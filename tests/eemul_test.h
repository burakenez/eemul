/**
 * @file eemul_test.h
 * @brief Self-test routines for the EEPROM emulation library.
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
 * Provides simple integration tests to validate the EEPROM emulation logic:
 * - **Fill-region test**: sequentially writes parameters until every
 *   available block in the Flash region has been used, verifying data
 *   integrity on each commit.
 * - **Overflow test**: continues committing beyond region capacity to
 *   observe error handling and block exhaustion behavior.
 */

#ifndef EEMUL_TEST_H
#define EEMUL_TEST_H

#include "eemul.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Sequentially fills the entire Flash emulation region with commits.
 *
 * - Iterates over all parameters defined in @ref s_descriptor.
 * - Writes deterministic patterns into each parameter.
 * - Reads back and verifies integrity.
 * - Stops after all blocks have been used once.
 *
 * @retval 0  Success (all commits verified)
 * @retval <0 Failure (error code printed to console)
 */
int eemul_test_fill_region(void);

/**
 * @brief Continue writing parameters beyond available blocks to test overflow handling.
 *
 * - Repeatedly writes parameter #1 with incrementing patterns.
 * - Prints active block information after each commit.
 * - Intentionally writes `blocks_count + 5` times to exceed capacity.
 *
 * @retval 0  Success (overflow behavior observed)
 * @retval <0 Failure (error code printed to console)
 */
int eemul_test_overflow(void);

#ifdef __cplusplus
}
#endif

#endif /* EEMUL_TEST_H */
