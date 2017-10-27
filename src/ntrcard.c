/* libncgc
 * Copyright (C) 2017 angelsl
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdint.h>

#include "../include/ncgc/ntrcard.h"
#include "../include/ncgc/blowfish.h"

#define FLAGS_WR               (1u << 30)
#define FLAGS_SEC_LARGE        (1u << 28)              // Use "other" secure area mode, which tranfers blocks of 0x1000 bytes at a time
#define FLAGS_CLK_SLOW         (1u << 27)              // Transfer clock rate (0 = 6.7MHz, 1 = 4.2MHz)
#define FLAGS_SEC_CMD          (1u << 22)              // The command transfer will be hardware encrypted (KEY2)
#define FLAGS_DELAY2(n)        (((n) & 0x3Fu) << 16)   // Transfer delay length part 2
#define FLAGS_DELAY2_MASK      (FLAGS_DELAY2(0x3F))
#define FLAGS_SEC_EN           (1u << 14)              // Security enable
#define FLAGS_SEC_DAT          (1u << 13)              // The data transfer will be hardware encrypted (KEY2)
#define FLAGS_DELAY1(n)        ((n) & 0x1FFFu)         // Transfer delay length part 1
#define FLAGS_DELAY1_MASK      (FLAGS_DELAY1(0x1FFF))

#define BSWAP64(val) ((((val >> 56) & 0xFF)) | (((val >> 48) & 0xFF) << 8) | (((val >> 40) & 0xFF) << 16) | (((val >> 32) & 0xFF) << 24) | \
    (((val >> 24) & 0xFF) << 32) | (((val >> 16) & 0xFF) << 40) | (((val >> 8) & 0xFF) << 48) | (((val) & 0xFF) << 56))

#define CMD_RAW_DUMMY           0x9Fu
#define CMD_RAW_CHIPID          0x90u
#define CMD_RAW_HEADER_READ     0x00u
#define CMD_RAW_ACTIVATE_KEY1   0x3Cu

#define CMD_KEY1_INIT_KEY2      0x4u
#define CMD_KEY1_CHIPID         0x1u
#define CMD_KEY1_SECURE_READ    0x2u
#define CMD_KEY1_ACTIVATE_KEY2  0xAu

#define CMD_KEY2_DATA_READ      0xB7u
#define CMD_KEY2_CHIPID         0xB8u

#define MCNT_CR1_ENABLE         0x8000u
#define MCNT_CR1_IRQ            0x4000u

#define P(card)                 ((card)->platform)
#define PDATA(card)             ((card)->platform.data)
#define F(flags)                ((ncgc_nflags_t) { (flags) })

static uint64_t key1_construct(ncgc_ncard_t* card, const uint8_t cmdarg, const uint16_t arg, const uint32_t ij) {
    // C = cmd, A = arg
    // KK KK JK JJ II AI AA CA
    const uint32_t k = card->key1.k++;
    uint64_t cmd = ((cmdarg & 0xF) << 4) |
        ((arg & 0xF000ull) >> 12 /* << 0 - 12 */) | ((arg & 0xFF0ull) << 4 /* 8 - 4 */) | ((arg & 0xFull) << 20 /* 20 - 0 */) |
        ((ij & 0xF00000ull) >> 4 /* << 16 - 20 */) | ((ij & 0xFF000ull) << 12 /* 24 - 12 */) | ((ij & 0xFF0ull) << 28 /* 32 - 4 */) |
        ((ij & 0xFull) << 44 /* 44 - 0 */) | ((k & 0xF0000ull) << 24 /* 40 - 16 */) | ((k & 0xFF00ull) << 40 /* 48 - 8 */) |
        ((k & 0xFFull) << 56 /* 56 - 0 */);
    cmd = BSWAP64(cmd);
    ncgc_nbf_encrypt(card->key1.ps, (void *) &cmd);
    return BSWAP64(cmd);
}

static int32_t key1_cmd(ncgc_ncard_t* card, const uint8_t cmdarg, const uint16_t arg, const uint32_t ij,
    const uint32_t read_size, void *const dest, const uint32_t flags) {
    uint64_t cmd = key1_construct(card, cmdarg, arg, ij);
    return P(card).send_command(PDATA(card), cmd, read_size, dest, read_size, F(flags));
}

static int32_t read_header(ncgc_ncard_t* card, void *const buf) {
    char ourbuf[0x68] = {0};
    char *usedbuf = buf ? buf : ourbuf;

    int32_t r = P(card).send_command(PDATA(card),
        CMD_RAW_HEADER_READ, 0x1000, usedbuf, buf ? 0x1000 : sizeof(ourbuf),
        F(FLAGS_CLK_SLOW | FLAGS_DELAY1(0x1FFF) | FLAGS_DELAY2(0x3F)));
    if (r < 0) {
        return r;
    }

    card->hdr.game_code = *(uint32_t *)(usedbuf + 0xC);
    card->hdr.key1_romcnt = card->key1.romcnt = *(uint32_t *)(usedbuf + 0x64);
    card->hdr.key2_romcnt = card->key2.romcnt = *(uint32_t *)(usedbuf + 0x60);
    card->key2.seed_byte = *(uint8_t *)(usedbuf + 0x13);
    return 0;
}

static void seed_key2(ncgc_ncard_t *const card) {
    const uint8_t seed_bytes[8] = {0xE8, 0x4D, 0x5A, 0xB1, 0x17, 0x8F, 0x99, 0xD5};
    card->key2.x = seed_bytes[card->key2.seed_byte & 7] + (((uint64_t)(card->key2.mn)) << 15) + 0x6000;
    card->key2.y = 0x5C879B9B05ull;

    if (P(card).hw_key2) {
        P(card).seed_key2(PDATA(card), card->key2.x, card->key2.y);
    }
}

int32_t ncgc_ninit(ncgc_ncard_t *const card, void *const buf) {
    int32_t r;
    if ((r = P(card).reset(PDATA(card)))) {
        return r;
    }

    if (card->encryption_state != NCGC_NRAW) {
        return -1;
    }

    if ((r = P(card).send_command(PDATA(card), CMD_RAW_DUMMY, 0x2000, NULL, 0, F(FLAGS_CLK_SLOW | FLAGS_DELAY2(0x18)))) < 0) {
        return -r+100;
    }

    P(card).io_delay(0x40000);
    
    if ((r = P(card).send_command(PDATA(card), CMD_RAW_CHIPID, 4, &card->raw_chipid, 4, F(FLAGS_CLK_SLOW))) < 0) {
        return -r+200;
    }

    if ((r = read_header(card, buf)) < 0) {
        return -r+300;
    }
    return 0;
}

void ncgc_nsetup_blowfish(ncgc_ncard_t* card, uint32_t ps[NCGC_NBF_PS_N32]) {
    card->key1.key[0] = card->hdr.game_code;
    card->key1.key[1] = card->hdr.game_code >> 1;
    card->key1.key[2] = card->hdr.game_code << 1;
    memcpy(card->key1.ps, ps, sizeof(card->key1.ps));
    _Static_assert(sizeof(card->key1.ps) == 0x1048, "Wrong Blowfish PS size");

    ncgc_nbf_apply_key(card->key1.ps, card->key1.key);
    ncgc_nbf_apply_key(card->key1.ps, card->key1.key);
}

int32_t ncgc_nbegin_key1(ncgc_ncard_t* card) {
    int32_t r;
    card->key2.mn = 0xC99ACE;
    card->key1.ij = 0x11A473;
    card->key1.k = 0x39D46;
    card->key1.l = 0;

    // 00 KK KK 0K JJ IJ II 3C
    if ((r = P(card).send_command(PDATA(card),
        CMD_RAW_ACTIVATE_KEY1 |
            ((card->key1.ij & 0xFF0000ull) >> 8) | ((card->key1.ij & 0xFF00ull) << 8) | ((card->key1.ij & 0xFFull) << 24) |
            ((card->key1.k & 0xF0000ull) << 16) | ((card->key1.k & 0xFF00ull) << 32) | ((card->key1.k & 0xFFull) << 48),
        0, NULL, 0, F(card->key2.romcnt & (FLAGS_CLK_SLOW | FLAGS_DELAY2_MASK | FLAGS_DELAY1_MASK)))) < 0) {
        return -r+100;
    }

    card->key1.romcnt = (card->key2.romcnt & (FLAGS_WR | FLAGS_CLK_SLOW)) |
        ((card->hdr.key1_romcnt & (FLAGS_CLK_SLOW | FLAGS_DELAY1_MASK)) +
        ((card->hdr.key1_romcnt & FLAGS_DELAY2_MASK) >> 16)) | FLAGS_SEC_LARGE;
    if ((r = key1_cmd(card, CMD_KEY1_INIT_KEY2, card->key1.l, card->key2.mn, 0, NULL, card->key1.romcnt)) < 0) {
        return -r+200;
    }

    seed_key2(card);
    card->key1.romcnt |= FLAGS_SEC_EN | FLAGS_SEC_DAT;

    if ((r = key1_cmd(card, CMD_KEY1_CHIPID, card->key1.l, card->key1.ij, 4, &card->key1.chipid, card->key1.romcnt)) < 0) {
        return -r+300;
    }
    if (card->raw_chipid != card->key1.chipid) {
        card->encryption_state = NCGC_NUNKNOWN;
        return -1;
    }
    card->encryption_state = NCGC_NKEY1;
    return 0;
}

void ncgc_nread_secure_area(ncgc_ncard_t* card, void *const dest) {
    uint32_t secure_area_romcnt = (card->hdr.key1_romcnt & (FLAGS_CLK_SLOW | FLAGS_DELAY1_MASK | FLAGS_DELAY2_MASK)) |
        FLAGS_SEC_EN | FLAGS_SEC_DAT | FLAGS_SEC_LARGE;
    char *const dest8 = dest;
    for (uint16_t c = 4; c < 8; ++c) {
        // TODO handle chipid high-bit set
        key1_cmd(card,
            CMD_KEY1_SECURE_READ, c, card->key1.ij, 0x1000,
            dest8 + (c - 4) * 0x1000, secure_area_romcnt);
    }
}

int32_t ncgc_nbegin_key2(ncgc_ncard_t* card) {
    int32_t r;
    if ((r = key1_cmd(card, CMD_KEY1_ACTIVATE_KEY2, card->key1.l, card->key1.ij, 0, NULL, card->key1.romcnt)) < 0) {
        return -r+100;
    }
    card->key2.romcnt = card->hdr.key2_romcnt & (FLAGS_CLK_SLOW | FLAGS_SEC_CMD | FLAGS_DELAY2_MASK | FLAGS_SEC_EN | FLAGS_SEC_DAT | FLAGS_DELAY1_MASK);

    if ((r = P(card).send_command(PDATA(card),
        CMD_KEY2_CHIPID, 4, &card->key2.chipid, 4, F(card->key2.romcnt))) < 0) {
        return -r+200;
    }
    if (card->key2.chipid != card->raw_chipid) {
        card->encryption_state = NCGC_NUNKNOWN;
        return -1;
    }
    card->encryption_state = NCGC_NKEY2;
    return 0;
}