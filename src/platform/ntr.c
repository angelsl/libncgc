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

#include "../../include/ncgc/platform/ntr.h"

#include <stdbool.h>
#include <stdint.h>

#include "../../include/ncgc/ntrcard.h"

#define REG_MCNT                (*(volatile uint16_t *)0x40001A0)
#define REG_MDATA               (*(volatile uint16_t *)0x40001A2)
#define REG_ROMCNT              (*(volatile uint32_t *)0x40001A4)
#define REG_CMDP                ((volatile uint8_t *)0x40001A8)
#define REG_CMD                 (*(volatile uint64_t *)0x40001A8)
#define REG_SEEDX_L             (*(volatile uint32_t *)0x40001B0)
#define REG_SEEDY_L             (*(volatile uint32_t *)0x40001B4)
#define REG_SEEDX_H             (*(volatile uint16_t *)0x40001B8)
#define REG_SEEDY_H             (*(volatile uint16_t *)0x40001BA)
#define REG_FIFO                (*(volatile uint32_t *)0x4100010)

#include "ntrcommon.c"

static int32_t reset(ncgc_ncard_t *const card) {
    bool (*resetfn)(void) = (bool (*)(void)) card->platform.data.fn_data;
    if (!resetfn) {
        return -1;
    } else if (!resetfn()) {
        return -2;
    }

    card->encryption_state = NCGC_NRAW;
    return 0;
}

void ncgc_nplatform_ntr_init(ncgc_ncard_t *card, bool (*resetfn)(void)) {
    card->platform = (ncgc_nplatform_t) {
        .data = { .fn_data = (void (*)(void)) resetfn },
        .reset = reset,
        .send_command = send_command,
        .io_delay = io_delay,
        .seed_key2 = seed_key2,
        .hw_key2 = true
    };
}
