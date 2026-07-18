/*
 * This file is part of the WiCAN project.
 *
 * Copyright (C) 2022  Meatpi Electronics.
 * Written by Ali Slim <ali@meatpi.com>
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


#ifndef SLEEP_MODE_h
#define SLEEP_MODE_h

#include <stdint.h>

typedef struct {
    float voltage;
    float sleep_voltage;
    float wakeup_voltage;
    uint32_t sleep_time_seconds;
    uint32_t sleep_remaining_seconds;
    int avg_raw;
    int min_raw;
    int max_raw;
    int avg_mv;
    uint8_t sleep_enabled;
    uint8_t state;
    const char *state_name;
} sleep_mode_status_t;

int8_t sleep_mode_init(uint8_t enable, float sleep_volt, float wakeup_volt);
int8_t sleep_mode_get_voltage(float *val);
int8_t sleep_mode_get_status(sleep_mode_status_t *status);

#endif
