/**
 * @file eemul_port_template.c
 * @brief Portable template Flash port for the EEPROM emulation library.
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
 * This file provides a **portable template implementation** of the EEPROM
 * emulation Flash port interface.
 *
 * Replace the stub functions with your MCU vendor SDK equivalents.
 *
 * ### Requirements
 * - `erase_page(addr)` must erase one physical Flash page at the given address.
 * - `program(addr, src)` must program **exactly ::EEMUL_ALIGN_BYTES** bytes per call.
 * - `read(addr, dst, len)` must return arbitrary data (usually just `memcpy`
 *   from memory-mapped Flash).
 * - `crc32(data, len)` is optional. Set `.crc32 = NULL` to use the library’s
 *   software fallback.
 */

#include "eemul_port.h"

/* MCU SDK headers (adjust include paths as needed) */

#include <string.h>

/* -------------------------------------------------------------------------- */
/* Flash Erase                                                                */
/* -------------------------------------------------------------------------- */

/**
 * @brief Erase one Flash page at the given address.
 *
 * @param address Absolute Flash address (must be page-aligned).
 * @retval true  Page successfully erased.
 * @retval false Erase failed or verification mismatch.
 *
 * @note Replace this stub with your MCU SDK's page erase function.
 */
static bool my_erase_page(uint32_t address)
{
    (void) address;
    /* Example: vendor_fmc_page_erase(address); */
    return false; /* default stub */
}

/* -------------------------------------------------------------------------- */
/* Flash Program                                                              */
/* -------------------------------------------------------------------------- */

/**
 * @brief Program exactly ::EEMUL_ALIGN_BYTES at a given Flash address.
 *
 * @param address Absolute Flash address (must be aligned).
 * @param src Pointer to buffer of ::EEMUL_ALIGN_BYTES bytes.
 * @retval true  Programming succeeded.
 * @retval false Programming failed.
 *
 * @note Replace with your MCU SDK’s program function.
 *       On MCUs supporting word or double-word programming, ensure
 *       ::EEMUL_ALIGN_BYTES matches that hardware granularity.
 */
static bool my_program(uint32_t address, const void *src)
{
#if (EEMUL_ALIGN_BYTES == 8)

    // TODO: implement double-word programming, if supported
    (void) address;
    (void) src;
    /* Example: vendor_fmc_program_doubleword(address, *(uint32_t*)src); */
    return false; /* default stub */

#elif (EEMUL_ALIGN_BYTES == 4)

    // TODO: implement word programming, if supported
    (void) address;
    (void) src;
    /* Example: vendor_fmc_program_word(address, *(uint32_t*)src); */
    return false; /* default stub */

#else
#error "EEMUL_ALIGN_BYTES must be 4 or 8 for vendor MCU"
#endif
}

/* -------------------------------------------------------------------------- */
/* Flash Read                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * @brief Read a range of bytes from Flash.
 *
 * @param address Absolute Flash address to read from.
 * @param dst Destination buffer in RAM.
 * @param len Number of bytes to read.
 *
 * @note Most MCUs support direct memory-mapped Flash access, so this
 *       implementation is typically just `memcpy`.
 */
static void my_read(uint32_t address, void *dst, uint32_t len)
{
    memcpy(dst, (const void *) address, len);
}

#if EEMUL_USE_FULL_BLOCK_HEADER

/* -------------------------------------------------------------------------- */
/* Optional CRC32                                                             */
/* -------------------------------------------------------------------------- */

/**
 * @brief Compute CRC32 over a buffer.
 *
 * @param data Pointer to buffer.
 * @param len Buffer length in bytes.
 * @return CRC32 checksum.
 *
 * @note Replace this stub with hardware CRC if available.
 *       Leave `.crc32 = NULL` in ::eemul_port_ops to use software fallback.
 */
static uint32_t my_crc32_hw(const void *data, uint32_t len)
{
    (void) data;
    (void) len;
    return 0; /* default stub */
}

#endif

/* -------------------------------------------------------------------------- */
/* Exported Ops                                                               */
/* -------------------------------------------------------------------------- */

/**
 * @brief Global Flash port binding for the EEPROM emulation library.
 *
 * Assigns the above functions to the middleware.
 * Replace stubs as needed for your MCU.
 */
const eemul_port_ops_t eemul_port_ops = {
    .erase_page = my_erase_page,
    .program = my_program,
    .read = my_read,
#if EEMUL_USE_FULL_BLOCK_HEADER
    .crc32 = NULL /* set to my_crc32_hw if hardware CRC is available */
#endif
};
