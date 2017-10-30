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

#ifndef NCGC_NTRCARD_H
#define NCGC_NTRCARD_H

#include "nocpp.h"

#include <stdbool.h>
#include <stdint.h>

#include "blowfish.h"

/// A struct wrapping over the raw flags bitfield.
///
/// Try your best not to modify this directly.
typedef struct ncgc_nflags {
    uint32_t flags;
} ncgc_nflags_t;

typedef union {
    uint64_t int_data;
    void *ptr_data;
} ncgc_nplatform_data_t;

struct ncgc_ncard;

typedef struct ncgc_nplatform {
    ncgc_nplatform_data_t data;
    int32_t (*reset)(struct ncgc_ncard *card);
    int32_t (*send_command)(struct ncgc_ncard *card, uint64_t cmd, uint32_t read_size, void *dest, uint32_t dest_size, ncgc_nflags_t flags);
    void (*io_delay)(uint32_t delay);
    void (*seed_key2)(struct ncgc_ncard *card, uint64_t x, uint64_t y);

    bool hw_key2;
} ncgc_nplatform_t;

typedef enum {
    NCGC_NRAW, NCGC_NKEY1, NCGC_NKEY2, NCGC_NUNKNOWN
} ncgc_nencryption_state_t;

typedef struct ncgc_ncard {
    /// The chip ID, stored in `ntrcard_init`
    uint32_t raw_chipid;

    struct {
        /// The game code, from the header
        uint32_t game_code;
        /// The KEY1 ROMCNT settings, as in the header
        uint32_t key1_romcnt;
        /// The KEY2 ROMCNT settings, as in the header
        uint32_t key2_romcnt;
    } hdr;

    struct {
        /// The chip ID gotten in KEY1 mode
        uint32_t chipid;
        /// The KEY1 ROMCNT settings, as used
        uint32_t romcnt;
        /// KEY1 Blowfish P array and S boxes
        uint32_t ps[NCGC_NBF_PS_N32];
        /// KEY1 Blowfish key
        uint32_t key[3];
        /// KEY1 nonce iiijjj
        uint32_t ij;
        /// KEY1 counter
        uint32_t k;
        /// KEY1 nonce llll
        uint16_t l;
    } key1;

    ncgc_nencryption_state_t encryption_state;

    struct {
        /// The KEY2 seed byte, as in the header
        uint8_t seed_byte;
        /// The KEY2 ROMCNT settings, as used
        uint32_t romcnt;
        /// The KEY2 seed, set in `ntrcard_begin_key1`
        uint32_t mn;
        /// The chip ID gotten in KEY2 mode
        uint32_t chipid;

        /// The KEY2 state X
        uint64_t x;
        /// The KEY2 state Y
        uint64_t y;
    } key2;

    ncgc_nplatform_t platform;
} ncgc_ncard_t;

/// Returns the delay before the response to a KEY1 command (KEY1 gap1)
inline uint16_t ncgc_nflags_predelay(const ncgc_nflags_t flags) { return (uint16_t) (flags.flags & 0x1FFF); }
/// Returns the delay after the response to a KEY1 command (KEY1 gap2)
inline uint16_t ncgc_nflags_postdelay(const ncgc_nflags_t flags) { return (uint16_t) ((flags.flags >> 16) & 0x3F); }
/// Returns true if clock pulses should be sent, and the KEY2 state advanced, during the pre- and post(?)-delays
inline bool ncgc_nflags_delay_pulse_clock(const ncgc_nflags_t flags) { return !!(flags.flags & (1 << 28)); }
/// Returns true if the command is KEY2-encrypted
inline bool ncgc_nflags_key2_command(const ncgc_nflags_t flags) { return (!!(flags.flags & (1 << 22))) && (!!(flags.flags & (1 << 14))); }
/// Returns true if the response is KEY2-encrypted
inline bool ncgc_nflags_key2_data(const ncgc_nflags_t flags) { return (!!(flags.flags & (1 << 13))) && (!!(flags.flags & (1 << 14))); }
/// Returns true if the slower CLK rate should be used (usually for raw commands)
inline bool ncgc_nflags_slow_clock(const ncgc_nflags_t flags) { return (!!(flags.flags & (1 << 27))); }

/// Sets the the delay before the response to a KEY1 command (KEY1 gap1)
inline void ncgc_nflags_set_predelay(ncgc_nflags_t *const flags, const uint16_t predelay) { flags->flags = (flags->flags & 0xFFFFE000) | (predelay & 0x1FFF); }
/// Sets the delay after the response to a KEY1 command (KEY1 gap2)
inline void ncgc_nflags_set_postdelay(ncgc_nflags_t *const flags, const uint16_t postdelay) { flags->flags = (flags->flags & 0xFFC0FFFF) | ((postdelay & 0x3F) << 16); }
/// Set if clock pulses should be sent, and the KEY2 state advanced, during the pre- and post(?)-delays
inline void ncgc_nflags_set_delay_pulse_clock(ncgc_nflags_t *const flags, const bool set) { flags->flags = (flags->flags & ~(1 << 28)) | (set ? (1 << 28) : 0); }
/// Set if the command is KEY2-encrypted
inline void ncgc_nflags_set_key2_command(ncgc_nflags_t *const flags, const bool set) {
    flags->flags = (flags->flags & ~((1 << 22) | (1 << 14))) |
        (set ? (1 << 22) : 0) | ((set || ncgc_nflags_key2_data(*flags)) ? (1 << 14) : 0);
}
/// Set if the response is KEY2-encrypted
inline void ncgc_nflags_set_key2_data(ncgc_nflags_t *const flags, const bool set) {
    flags->flags = (flags->flags & ~((1 << 13) | (1 << 14))) |
        (set ? (1 << 13) : 0) | ((set || ncgc_nflags_key2_command(*flags)) ? (1 << 14) : 0);
}
/// Set if the slower CLK rate should be used (usually for raw commands)
inline void ncgc_nflags_set_slow_clock(ncgc_nflags_t *const flags, const bool set) { flags->flags = (flags->flags & ~(1 << 27)) | (set ? (1 << 27) : 0); }

/// Constructs a `ncgc_nflags_t`.
inline ncgc_nflags_t ncgc_nflags_construct(const uint16_t predelay,
                                           const uint16_t postdelay,
                                           const bool delay_pulse_clock,
                                           const bool key2_command,
                                           const bool key2_data,
                                           const bool slow_clock) {
    ncgc_nflags_t flags;
    ncgc_nflags_set_predelay(&flags, predelay);
    ncgc_nflags_set_postdelay(&flags, postdelay);
    ncgc_nflags_set_delay_pulse_clock(&flags, delay_pulse_clock);
    ncgc_nflags_set_key2_command(&flags, key2_command);
    ncgc_nflags_set_key2_data(&flags, key2_data);
    ncgc_nflags_set_slow_clock(&flags, slow_clock);
    return flags;
}

/// Initialises the card slot and card, optionally reading the header into `buf`, if `buf` is not null.
/// Returns 0 on success, -1 if no card is inserted, or -2 if initialisation otherwise fails.
/// If specified, `buf` should be at least 0x1000 bytes.
int32_t ncgc_ninit(ncgc_ncard_t *const card, void *const buf);

/// Sets up the blowfish state based on the game code in the header, and the provided initial P array/S boxes.
void ncgc_nsetup_blowfish(ncgc_ncard_t* card, uint32_t ps[NCGC_NBF_PS_N32]);

/// Brings the card into KEY1 mode. Returns 0 on success, or -1 if the KEY1 CHIPID command result does not match
/// the chip ID stored in `card`.
int32_t ncgc_nbegin_key1(ncgc_ncard_t* card);

/// Reads the secure area. `dest` must be at least 0x4000 bytes.
void ncgc_nread_secure_area(ncgc_ncard_t* card, void *const dest);

/// Brings the card into KEY2 mode. Returns 0 on success, or -1 if the KEY2 CHIPID command result does not match
/// the chip ID stored in `card`.
int32_t ncgc_nbegin_key2(ncgc_ncard_t* card);
#endif /* NCGC_NTRCARD_H */
