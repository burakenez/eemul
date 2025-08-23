/**
 * @file eemul_port.h
 * @brief MCU-specific Flash port hooks for the EEPROM emulation library.
 * @version 1.0.0
 *
 * @copyright
 * MIT License
 *
 * Copyright (c) 2025 Burak Enez
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @details
 * The EEPROM emulation middleware does not directly manipulate Flash hardware.
 * Instead, it relies on this **port layer** to provide MCU-specific operations:
 *
 * - Erase Flash pages (`erase_page`)
 * - Program aligned chunks (`program`)
 * - Read arbitrary data (`read`)
 * - Optionally compute CRC32 (`crc32`)
 *
 * ### Notes
 * - `program()` must program **exactly EEMUL_ALIGN_BYTES** bytes per call.
 * - All addresses passed to these functions are absolute Flash addresses.
 * - If `.crc32` is NULL, the library automatically falls back to a software CRC.
 *
 * Provide an implementation of this interface in a target-specific file,
 * such as `eemul_port_gd32e23x.c` or `eemul_port_template.c`.
 */

#ifndef EEMUL_PORT_H
#define EEMUL_PORT_H

#include "eemul.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Global instance of MCU-specific Flash port operations.
 *
 * This object must be defined by the user to map EEPROM emulation
 * functions to the actual MCU Flash driver.
 *
 * ### Example
 * @code
 * const eemul_port_ops_t eemul_port_ops = {
 *     .erase_page = my_flash_erase,
 *     .program    = my_flash_program,
 *     .read       = my_flash_read,
 *     .crc32      = NULL // use SW fallback
 * };
 * @endcode
 */
extern const eemul_port_ops_t eemul_port_ops;

#ifdef __cplusplus
}
#endif

#endif /* EEMUL_PORT_H */
