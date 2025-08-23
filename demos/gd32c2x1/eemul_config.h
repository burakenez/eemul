/**
 * @file eemul_config.h
 * @brief Build-time configuration for the Flash-backed EEPROM emulation.
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
 * This header contains **all application-tunable knobs** for EEMUL. It is the
 * only header most projects need to edit when porting to a new MCU or memory map.
 *
 * #### What belongs here
 * - Flash geometry (page size, number of pages, end address)
 * - Program alignment constraints
 * - Feature toggles that affect memory/RAM use (dynamic alloc, precomputed offsets)
 * - Header format selection (compact vs full)
 *
 * #### What does NOT belong here
 * - Internal derived sizing used only by the implementation (kept in eemul.c)
 *
 * #### Porting checklist
 * 1) Reserve a **contiguous** Flash region for EEMUL in your linker script.
 * 2) Set `EEMUL_REGION_END_ADDR`, `EEMUL_FLASH_PAGE_SIZE`, `EEMUL_NUMBER_OF_FLASH_PAGES`.
 * 3) Set `EEMUL_ALIGN_BYTES` to your MCU’s program granularity (4 or 8 are typical).
 * 4) Decide if you want dynamic buffer allocation at runtime.
 * 5) Choose header format: compact (smaller) or full (extra integrity fields).
 *
 * @note
 * EEMUL requires **≥2 pages** to safely rotate/erase without touching the active page.
 * A compile-time error is issued if fewer than 2 pages are configured.
 */

#ifndef EEMUL_CONFIG_H
#define EEMUL_CONFIG_H

/* -------------------------------------------------------------------------- */
/* Flash geometry / memory region                                             */
/* -------------------------------------------------------------------------- */

/**
 * @brief End address (exclusive) of the emulation region.
 *
 * The region occupies `EEMUL_NUMBER_OF_FLASH_PAGES * EEMUL_FLASH_PAGE_SIZE`
 * bytes immediately preceding this address. The start address is derived as:
 * `EEMUL_REGION_END_ADDR - EEMUL_REGION_SIZE_BYTES`.
 *
 * Must be aligned to `EEMUL_FLASH_PAGE_SIZE`.
 *
 * Uncomment to override default.
 */
#define EEMUL_REGION_END_ADDR                 (0x08010000U)

/**
 * @brief Size (bytes) of one physical Flash page (erase granularity).
 *
 * Typical values are 1024, 2048, or 4096 depending on the MCU family.
 *
 * Uncomment to override default.
 */
#define EEMUL_FLASH_PAGE_SIZE                 (0x400U) /* 1024 bytes */

/**
 * @brief Number of **contiguous** Flash pages reserved for EEMUL.
 *
 * Must be at least 2 to allow “write new → switch active → erase old” rotation.
 *
 * Uncomment to override default.
 */
#define EEMUL_NUMBER_OF_FLASH_PAGES           (2U)

/* -------------------------------------------------------------------------- */
/* Program/align constraints                                                  */
/* -------------------------------------------------------------------------- */

/**
 * @brief Flash programming alignment (bytes).
 *
 * Every program operation must be exactly this many bytes and aligned to this
 * boundary. Many MCUs require 4 or 8. The port layer enforces this.
 *
 * Uncomment to override default.
 */
#define EEMUL_ALIGN_BYTES                     (8U)

/* -------------------------------------------------------------------------- */
/* Runtime memory usage / features                                            */
/* -------------------------------------------------------------------------- */

/**
 * @brief Enable dynamic allocation (malloc/calloc) for runtime buffers.
 *
 * - 0: use internal static buffers sized by worst-case macros (see below).
 * - 1: allocate buffers at init based on the descriptor at runtime.
 *
 * Uncomment to override default.
 */
#define EEMUL_ENABLE_DYNAMIC_ALLOC            (0U)

/**
 * @brief Enable precomputation of per-parameter payload offsets at init.
 *
 * - 1: faster lookups at the cost of a small RAM table.
 * - 0: offsets computed on demand (saves RAM, a few extra instructions per call).
 *
 * Uncomment to override default.
 */
#define EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS (1U)

#if (EEMUL_ENABLE_DYNAMIC_ALLOC == 0)
/**
 * @brief Maximum payload size (bytes) when using static buffers.
 *
 * Must be >= sum of descriptor sizes. Increase if your descriptor grows.
 *
 * Uncomment to override default.
 */
#define EEMUL_MAX_PAYLOAD_BYTES (128U)
#endif /* static buffers */

#if (EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS == 1)
/**
 * @brief Maximum parameter count when using precomputed offsets (static RAM).
 *
 * Set this to the maximum number of elements in your descriptor.
 *
 * Uncomment to override default.
 */
#define EEMUL_MAX_PARAM_COUNT (32U)
#endif

/* -------------------------------------------------------------------------- */
/* Header format                                                              */
/* -------------------------------------------------------------------------- */

/**
 * @brief Select block header format.
 * - 0: Compact header (smaller; increases sub-block density).
 * - 1: Full header (adds integrity fields; larger).
 *
 * Uncomment to override default.
 */
#define EEMUL_USE_FULL_BLOCK_HEADER (0U)

/**
 * @brief Magic number stamped into every block header for identification.
 *
 * Kept public for diagnostics and test tooling. The value depends on
 * `EEMUL_USE_FULL_BLOCK_HEADER` to keep header footprints explicit.
 *
 * Normally derived automatically; uncomment to override manually.
 */
#if EEMUL_USE_FULL_BLOCK_HEADER
#define EEMUL_BLOCK_HEADER_MAGIC (0x4554414C554D4545ULL) /* "EEMULATE" (64-bit) */
#else
#define EEMUL_BLOCK_HEADER_MAGIC (0x4C554D45UL) /* "EMUL" (32-bit) */
#endif

#endif /* EEMUL_CONFIG_H */
