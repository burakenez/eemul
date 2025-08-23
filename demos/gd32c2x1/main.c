/**
 * @file main.c
 * @brief Example entry point for EEPROM emulation self-tests.
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
 * Demonstrates usage of the EEMUL library with built-in tests:
 *  - Fill-region test (writes until region full, verifies data)
 *  - Overflow test (writes beyond capacity to test error handling)
 */

#include "eemul_test.h"

#include <stdint.h>
#include <stdio.h>

int main(void)
{
    printf("=== EEPROM Emulation Test Application ===\n");

    /* 1. Run fill-region test */
    int result1 = eemul_test_fill_region();
    printf("Fill-region test: %s\n", (result1 == 0) ? "PASS" : "FAIL");

    /* 2. Run overflow test */
    int result2 = eemul_test_overflow();
    printf("Overflow test   : %s\n", (result2 == 0) ? "PASS" : "FAIL");

    printf("=== All tests completed ===\n");

    /* Keep running (simulate embedded main loop) */
    while (1)
    {
        (void) result1;
        (void) result2;
    }

    return 0;
}