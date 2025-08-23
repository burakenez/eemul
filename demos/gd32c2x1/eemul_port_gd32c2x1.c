/**
 * @file eemul_port_gd32c2x1.c
 * @brief GD32C2x1 Flash port for the EEPROM emulation library.
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

/* GD32C2x1 SDK headers (adjust include paths as needed) */
#include "gd32c2x1.h"
#if EEMUL_USE_FULL_BLOCK_HEADER
#include "gd32c2x1_crc.h"
#endif
#include "gd32c2x1_fmc.h"

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
static bool gd_erase_page(uint32_t address)
{
    uint32_t page_index = (address - MAIN_FLASH_BASE_ADDRESS) / MAIN_FLASH_PAGE_SIZE;

    fmc_unlock();
    fmc_flag_clear(FMC_FLAG_ENDF | FMC_FLAG_PGERR | FMC_FLAG_WPERR | FMC_FLAG_OPRERR | FMC_FLAG_PGSERR | FMC_FLAG_PGMERR
                   | FMC_FLAG_PGAERR);

    fmc_state_enum es = fmc_page_erase(page_index);

    fmc_flag_clear(FMC_FLAG_ENDF | FMC_FLAG_PGERR | FMC_FLAG_WPERR | FMC_FLAG_OPRERR | FMC_FLAG_PGSERR | FMC_FLAG_PGMERR
                   | FMC_FLAG_PGAERR);
    fmc_lock();

    if (es != FMC_READY)
        return false;

    /* Verify erased page contents */
    for (uint32_t p = 0; p < EEMUL_FLASH_PAGE_SIZE; p += 4U)
    {
        if (*(volatile uint32_t *) (address + p) != 0xFFFFFFFFU)
            return false;
    }
    return true;
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
static bool gd_program(uint32_t address, const void *src)
{
#if (EEMUL_ALIGN_BYTES == 8)
    /* Double-word (8B) programming */
    uint64_t dw;
    memcpy(&dw, src, 8);

    fmc_unlock();
    fmc_flag_clear(FMC_FLAG_ENDF | FMC_FLAG_PGERR | FMC_FLAG_WPERR | FMC_FLAG_OPRERR | FMC_FLAG_PGSERR | FMC_FLAG_PGMERR
                   | FMC_FLAG_PGAERR);

    fmc_state_enum es = fmc_doubleword_program(address, dw);

    fmc_flag_clear(FMC_FLAG_ENDF | FMC_FLAG_PGERR | FMC_FLAG_WPERR | FMC_FLAG_OPRERR | FMC_FLAG_PGSERR | FMC_FLAG_PGMERR
                   | FMC_FLAG_PGAERR);
    fmc_lock();

    return (es == FMC_READY);
#else
#error "EEMUL_ALIGN_BYTES must be 8 for GD32C2x1"
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
static void gd_read(uint32_t address, void *dst, uint32_t len)
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
static uint32_t gd_crc32_hw(const void *data, uint32_t len)
{
    rcu_periph_clock_enable(RCU_CRC);

    crc_deinit();
    crc_polynomial_size_set(CRC_CTL_PS_32);
    crc_polynomial_set(0x04C11DB7U);
    crc_input_data_reverse_config(CRC_INPUT_DATA_BYTE); /* reflect input */
    crc_reverse_output_data_enable();                   /* reflect output */
    crc_init_data_register_write(0xFFFFFFFFU);

    (void) crc_block_data_calculate((void *) data, len, INPUT_FORMAT_BYTE);
    return crc_data_register_read() ^ 0xFFFFFFFFU;
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
    .erase_page = gd_erase_page,
    .program = gd_program,
    .read = gd_read,
#if EEMUL_USE_FULL_BLOCK_HEADER
    .crc32 = gd_crc32_hw, /* Set to NULL to disable HW CRC. */
#endif
};
