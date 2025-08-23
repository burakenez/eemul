/**
 * @file eemul_test.c
 * @brief Self-test routines for the EEPROM emulation library using param-based API.
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
 * Provides two test scenarios:
 *  - **Fill-region test:** sequential writes until all available blocks are used.
 *  - **Overflow test:** continues writing beyond region capacity to observe behavior.
 *
 * Each test verifies integrity by:
 *  - Writing parameters according to the descriptor (`s_descriptor`)
 *  - Reading them back immediately
 *  - Comparing for correctness
 *
 * Additional debug prints show active block index, address, and sequence counter.
 */

#include "eemul_port.h"
#include "eemul_test.h"

#include <stdio.h>
#include <string.h>

/* ---------------- Descriptor Definition ---------------- */

/**
 * @brief Example descriptor used for testing.
 *
 * Parameters are defined as fixed-size slots. These IDs will be
 * referenced by the test code via `eemul_write_param()` / `eemul_read_param()`.
 */
typedef uint8_t eemul_version_t[4];         /**< FW version (4 bytes). */
typedef uint8_t eemul_error_log_item_t[20]; /**< Error log entry (20 byte). */
typedef uint8_t eemul_statistics_t[20];     /**< Statistics page (20 bytes). */
typedef uint8_t eemul_counter_t[1];         /**< Counter (1 byte). */

const uint8_t s_descriptor[] __attribute__((aligned(2))) = {
    /* ID 0: FW version */
    sizeof(eemul_version_t),
    /* IDs 1: error log entries */
    sizeof(eemul_error_log_item_t),
    /* ID 2: statistics page */
    sizeof(eemul_statistics_t),
    /* ID 3: counter */
    sizeof(eemul_counter_t)
};

int eemul_test_fill_region(void)
{
    printf("=== Starting fill-region test (param API) ===\n");

    /* ---------------- Configure and Initialize ---------------- */
    eemul_init_config_t cfg = {
        .badblock_policy = EEMUL_BADBLOCK_POLICY_RETRY,
        .block_mode = EEMUL_BLOCK_MODE_SUBBLOCKS,
        .bad_retry_threshold = 2,         /* mark as bad after 2 HW errors */
        .enable_monotonic_sequence = true /* continue sequence after recovery */
    };

    eemul_handle_t handle;
    eemul_status_t status = eemul_init(&handle, &eemul_port_ops, &cfg, s_descriptor, sizeof(s_descriptor));
    if (status != EEMUL_STATUS_OK)
    {
        printf("[LIBTEST] eemul_init failed: %d\n", (int) status);
        return -1;
    }

    /* ---------------- Write / Verify Loop ---------------- */
    uint8_t tx[32];
    uint8_t rx[32];
    uint32_t writes_done = 1; /* init may already create the first block */

    for (uint16_t id = 0; id < sizeof(s_descriptor); ++id)
    {
        uint16_t sz = eemul_get_param_size(&handle, id);
        if (sz == 0)
            break; /* reached end */

        for (uint16_t i = 0; i < sz; i++)
            tx[i] = (uint8_t) (id + writes_done + i);

        status = eemul_write_param(&handle, id, tx);
        if (status != EEMUL_STATUS_OK)
        {
            printf("Write failed param=%u iter=%lu status=%d\n", id, (unsigned long) writes_done, (int) status);
            return -2;
        }

        memset(rx, 0, sz);
        status = eemul_read_param(&handle, id, rx);
        if (status != EEMUL_STATUS_OK || memcmp(tx, rx, sz) != 0)
        {
            printf("Verify mismatch param=%u iter=%lu\n", id, (unsigned long) writes_done);
            return -3;
        }

        /* ---------------- Debug Output ---------------- */
        printf("--- Commit %lu ---\n", (unsigned long) writes_done);
        printf("Active block index: %u\n", handle.active_block_index);
        printf("Active block addr : 0x%08lX\n", (unsigned long) handle.active_block_address);
        printf("Active sequence   : %lu\n", (unsigned long) handle.active_sequence);

        writes_done++;
        if (writes_done >= handle.blocks_count)
        {
            printf("All %u blocks used.\n", handle.blocks_count);
            break;
        }
    }

    printf("=== Fill-region test finished ===\n");
    return 0;
}

int eemul_test_overflow(void)
{
    printf("=== Starting overflow test (param API) ===\n");

    /* ---------------- Configure and Initialize ---------------- */
    eemul_init_config_t cfg = { .badblock_policy = EEMUL_BADBLOCK_POLICY_RETRY,
                                .block_mode = EEMUL_BLOCK_MODE_SUBBLOCKS,
                                .bad_retry_threshold = 2,
                                .enable_monotonic_sequence = true };

    eemul_handle_t handle;
    eemul_status_t status = eemul_init(&handle, &eemul_port_ops, &cfg, s_descriptor, sizeof(s_descriptor));
    if (status != EEMUL_STATUS_OK)
    {
        printf("[LIBTEST] eemul_init failed: %d\n", (int) status);
        return -1;
    }

    /* ---------------- Overflow Loop ---------------- */
    uint8_t buf[32];
    for (uint32_t i = 0; i < handle.blocks_count + 5; ++i)
    {
        buf[0] = (uint8_t) i;

        status = eemul_write_param(&handle, 1, buf);
        printf("Write #%lu: status=%d\n", (unsigned long) i, (int) status);

        printf("Active block index: %u\n", handle.active_block_index);
        printf("Active block addr : 0x%08lX\n", (unsigned long) handle.active_block_address);
        printf("Active sequence   : %lu\n", (unsigned long) handle.active_sequence);

        if (status != EEMUL_STATUS_OK)
        {
            printf("Stopped after %lu writes.\n", (unsigned long) i);
            return -2;
        }
    }

    printf("=== Overflow test finished ===\n");
    return 0;
}
