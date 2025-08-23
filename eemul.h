/**
 * @file eemul.h
 * @brief Flash-backed EEPROM emulation — public API, types and configuration.
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
 * This header defines the **public API** for the Flash-backed EEPROM emulation
 * layer (EEMUL). The emulation provides EEPROM-like parameter storage on top of
 * a reserved Flash region, supporting safe updates, rotation, and bad-block
 * management without external dependencies.
 *
 * The implementation focuses on **robustness, simplicity, and portability**:
 * applications can use it as a lightweight, low-level persistent key/value
 * store with atomic commits and wear-leveling. It is particularly useful on
 * MCUs that lack true EEPROM hardware.
 *
 * ## Core design concepts
 *
 * - **Atomic commits**: updates are never partially visible. A block is only
 *   considered valid if its header magic matches, integrity fields pass
 *   (optional, in full header mode), and its commit flag has been atomically
 *   programmed. Interrupted or half-written blocks are ignored automatically.
 *
 * - **Wear leveling**: blocks are consumed in a **linear rotation order**.
 *   The library never reuses a block until the entire region has rotated. This
 *   approach simplifies state tracking and minimizes RAM needs, while still
 *   providing sufficient leveling for typical small-parameter use cases.
 *
 * - **Bad-block handling**: two policies exist:
 *   1. **Retry-only**: skip bad candidates in the current session, retry at
 *      next reboot.
 *   2. **Mark-on-flash**: write a persistent marker into the header to
 *      permanently exclude the block across all sessions.
 *
 * - **Block modes**:
 *   - **PAGE mode**: one logical block = one or more full Flash pages. Best
 *     for larger payloads.
 *   - **SUBBLOCKS mode**: each page is divided into fixed slots (header +
 *     payload). This is efficient when storing many small parameters.
 *
 * - **Header formats**:
 *   - **Compact header**: minimal size, only basic fields. Maximizes density.
 *   - **Full header**: includes additional integrity fields (CRC, etc.) for
 *     stronger validation at the cost of larger headers.
 *
 * - **Buffering strategies**:
 *   - **Static buffers**: all arrays allocated at compile time; no malloc used.
 *     Suitable for deeply embedded devices with tight constraints.
 *   - **Dynamic buffers**: allocate at init() depending on actual descriptor.
 *     Saves static RAM at the cost of requiring a heap.
 *
 * - **Runtime tunables**:
 *   - `bad_retry_threshold`: number of failed erase/program attempts before
 *     marking a block bad.
 *   - `enable_monotonic_sequence`: controls whether sequence numbers continue
 *     monotonically across region formats/recoveries, or reset from 1.
 *
 * ## Initialization and operation
 *
 * On `eemul_init()`:
 *  - The region geometry (page size, count, alignment) is checked.
 *  - Buffers are allocated or bound (static/dynamic depending on config).
 *  - The latest committed block is scanned and promoted active.
 *  - If none is found, the library performs a **safe format**: erase region
 *    and establish a first committed block.
 *
 * During writes:
 *  - The active payload is loaded into RAM (`shadow_buf`).
 *  - Requested deltas are applied in RAM.
 *  - A new block candidate is chosen in rotation (skipping bad or unsafe ones).
 *  - The candidate’s page(s) are erased only if safe to do so.
 *  - Header is written with commit_flag unset (pre-commit).
 *  - Payload is programmed, aligned.
 *  - Commit_flag is atomically cleared → block is now active.
 *
 * On recovery:
 *  - The highest valid sequence block is promoted.
 *  - Pre-commit stale blocks are recognized and skipped.
 *  - Any transient errors are counted and may retire a block based on policy.
 *
 * ## How to use
 *
 * 1. **Reserve a Flash region** in your linker script.
 *    Example: two 1-KB pages ending at `0x08010000`.
 *    @code
 *    #define EEMUL_REGION_END_ADDR       0x08010000U
 *    #define EEMUL_FLASH_PAGE_SIZE       0x400U
 *    #define EEMUL_NUMBER_OF_FLASH_PAGES 2
 *    @endcode
 *
 * 2. **Define parameter descriptor** — an array of per-parameter sizes.
 *    Example: three parameters: 4B, 2B, 16B.
 *    @code
 *    static const uint8_t desc[] = { 4, 2, 16 };
 *    const uint16_t param_count = sizeof(desc);
 *    @endcode
 *
 * 3. **Implement Flash HAL** — erase/program/read (+ CRC if enabled).
 *    @code
 *    static bool erase(uint32_t addr) { ... }
 *    static bool prog(uint32_t addr, const void *src) { ... }
 *    static void read(uint32_t addr, void *dst, uint32_t len) { ... }
 *
 *    static const eemul_port_ops_t ops = {
 *        .erase_page = erase,
 *        .program    = prog,
 *        .read       = read,
 *        .crc32      = NULL // optional
 *    };
 *    @endcode
 *
 * 4. **Initialize**:
 *    @code
 *    eemul_handle_t h;
 *    eemul_init_config_t cfg = {
 *        .badblock_policy = EEMUL_BADBLOCK_POLICY_MARK,
 *        .block_mode = EEMUL_BLOCK_MODE_SUBBLOCKS,
 *        .bad_retry_threshold = 2,
 *        .enable_monotonic_sequence = true
 *    };
 *    if (eemul_init(&h, &ops, &cfg, desc, param_count) != EEMUL_STATUS_OK) {
 *        // handle init error
 *    }
 *    @endcode
 *
 * 5. **Read/write**:
 *    @code
 *    uint32_t v = 0xDEADBEEF;
 *    eemul_write_param(&h, 0, &v, sizeof(v));
 *
 *    v = 0;
 *    eemul_read_param(&h, 0, &v, sizeof(v)); // v restored
 *    @endcode
 *
 * 6. **Batch updates** (multiple params in one commit):
 *    @code
 *    eemul_begin_batch(&h);
 *    eemul_update_param_in_shadow(&h, 0, &fw, sizeof(fw));
 *    eemul_update_param_in_shadow(&h, 2, &cnt, sizeof(cnt));
 *    eemul_commit_batch(&h);
 *    @endcode
 *
 * ## Safety guarantees
 * - Active block’s page is never erased.
 * - Partially-written blocks are automatically discarded.
 * - Blocks that fail multiple times are retired.
 * - Sequence numbers guarantee strict ordering.
 */

#ifndef EEMUL_H
#define EEMUL_H

/**
 * @brief Application-tunable build-time configuration.
 *
 * All macros controlling flash geometry, alignment, feature toggles,
 * and header format are defined in this header. Projects should only
 * modify @ref eemul_config.h when porting or changing limits.
 */
#include "eemul_config.h"

#include <stdbool.h>
#include <stdint.h>

/* ----------------------------- Config Defines ------------------------------ */

/**
 * @brief End address (exclusive) of the EEPROM emulation region in Flash.
 *
 * The emulation region occupies a fixed number of Flash pages ending at this
 * address. The start address is derived automatically as:
 * `EEMUL_REGION_END_ADDR - EEMUL_REGION_SIZE_BYTES`.
 *
 * @note Must be aligned to Flash page boundaries.
 */
#ifndef EEMUL_REGION_END_ADDR
#define EEMUL_REGION_END_ADDR (0x08010000U)
#endif

/**
 * @brief Number of physical Flash pages reserved for EEPROM emulation.
 *
 * This determines the total size of the emulation region in bytes together with
 * ::EEMUL_FLASH_PAGE_SIZE. The emulation region is always contiguous.
 */
#ifndef EEMUL_NUMBER_OF_FLASH_PAGES
#define EEMUL_NUMBER_OF_FLASH_PAGES (2U)
#endif

#if (EEMUL_NUMBER_OF_FLASH_PAGES < 2)
#error "EEMUL requires at least 2 Flash pages for safe rotation."
#endif

/**
 * @brief Size of a single Flash page in bytes.
 *
 * This is the erase granularity of the hardware Flash. Each page is the minimum
 * unit that can be erased. Programming operations must respect this size.
 */
#ifndef EEMUL_FLASH_PAGE_SIZE
#define EEMUL_FLASH_PAGE_SIZE (0x400U) /**< 1024 bytes typical */
#endif

/**
 * @brief Flash programming alignment in bytes.
 *
 * All write operations must be aligned to this value, and must occur in
 * multiples of this value. Typical values are 4 (word) or 8 (double word)
 * depending on MCU.
 */
#ifndef EEMUL_ALIGN_BYTES
#define EEMUL_ALIGN_BYTES (4U)
#endif

/**
 * @brief Enable dynamic allocation (malloc/calloc) for runtime buffers.
 *
 * - If set to 0: the library uses internal static buffers.
 * - If set to 1: buffers are allocated dynamically at init().
 *
 * @note When disabled, maximum counts and sizes must fit within the static
 *       arrays defined in ::handle.c.
 */
#ifndef EEMUL_ENABLE_DYNAMIC_ALLOC
#define EEMUL_ENABLE_DYNAMIC_ALLOC (0U)
#endif

#if (EEMUL_ENABLE_DYNAMIC_ALLOC == 0)

/**
 * @brief Maximum supported payload size (in bytes) per block.
 *
 * This is an upper bound for static buffer allocation. It must be large enough
 * to hold the largest possible payload described in the parameter table.
 */
#ifndef EEMUL_MAX_PAYLOAD_BYTES
#define EEMUL_MAX_PAYLOAD_BYTES (128U)
#endif

#endif

/**
 * @brief Enable precomputation of parameter offsets at init time.
 *
 * If enabled, parameter offsets within the payload are precomputed and stored
 * in a lookup table for faster access. If disabled, offsets are recalculated
 * on each access, saving RAM at the cost of a few cycles.
 */
#ifndef EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS
#define EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS (1U)
#endif

#if EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS

/**
 * @brief Maximum number of parameters supported when using precomputed offsets.
 *
 * Defines the size of the static offset table. Increase if the descriptor table
 * contains more parameters than this limit.
 */
#ifndef EEMUL_MAX_PARAM_COUNT
#define EEMUL_MAX_PARAM_COUNT (32U)
#endif

#endif

/**
 * @brief Select block header format.
 *
 * - 0 = compact header (16 bytes). Fewer checks, but allows more
 *       sub-blocks to fit per Flash page.
 * - 1 = full header (32 bytes). Includes additional fields for maximum
 *       integrity checking and debugging.
 */
#ifndef EEMUL_USE_FULL_BLOCK_HEADER
#define EEMUL_USE_FULL_BLOCK_HEADER (0U)
#endif

/**
 * @brief Block header magic constant used to validate headers.
 *
 * This constant is written into every block header to uniquely identify
 * emulation blocks. It prevents confusion with erased Flash or random data.
 *
 * - In full-header mode (32 bytes)
 * - In compact-header mode (16 bytes)
 */
#if EEMUL_USE_FULL_BLOCK_HEADER
#define EEMUL_BLOCK_HEADER_MAGIC (0x4554414C554D4545ULL) /* EEMULATE*/
#else
#define EEMUL_BLOCK_HEADER_MAGIC (0x4C554D45UL) /* EMUL */
#endif

/**
 * @brief Value written to ::eemul_block_header_t::bad_marker to mark
 * permanently bad blocks.
 *
 * Normal (good) blocks contain 0xFFFFFFFF. Bad blocks are tagged with this
 * constant to prevent further use across reboots.
 */
#define EEMUL_BLOCK_HEADER_BAD_MARK_VALUE (0xBAD0BAD0U)

/**
 * @brief Total emulation region size in bytes.
 *
 * Computed as ::EEMUL_NUMBER_OF_FLASH_PAGES × ::EEMUL_FLASH_PAGE_SIZE.
 */
#define EEMUL_REGION_SIZE_BYTES           (EEMUL_NUMBER_OF_FLASH_PAGES * EEMUL_FLASH_PAGE_SIZE)

/**
 * @brief Start address (inclusive) of the emulation region in Flash.
 *
 * Derived automatically from ::EEMUL_REGION_END_ADDR and
 * ::EEMUL_REGION_SIZE_BYTES.
 */
#define EEMUL_REGION_START_ADDR           (EEMUL_REGION_END_ADDR - EEMUL_REGION_SIZE_BYTES)

/**
 * @brief Return/status codes of the emulation API.
 */
typedef enum
{
    EEMUL_STATUS_OK = 0,     /**< Operation successful. */
    EEMUL_STATUS_ERR_PARAM,  /**< Invalid argument or configuration. */
    EEMUL_STATUS_ERR_HW,     /**< Hardware (port operation) failure. */
    EEMUL_STATUS_ERR_LAYOUT, /**< Invalid/unsupported layout derived from config. */
    EEMUL_STATUS_ERR_NOBLOCK /**< No usable block found/initialized. */
} eemul_status_t;

/**
 * @brief Strategy for handling blocks that fail erase/program.
 */
typedef enum
{
    EEMUL_BADBLOCK_POLICY_RETRY = 0, /**< Skip failed block this session only; retry next boot. */
    EEMUL_BADBLOCK_POLICY_MARK = 1   /**< Also mark the block on-flash, skipping it on future boots. */
} eemul_badblock_policy_t;

/** @brief Logical block layout mode. */
typedef enum
{
    EEMUL_BLOCK_MODE_PAGE = 0,     /**< One flash page == one logical block. */
    EEMUL_BLOCK_MODE_SUBBLOCKS = 1 /**< Each page is sliced into multiple sub-blocks. */
} eemul_block_mode_t;

/**
 * @brief Initialization/configuration parameters for EEPROM emulation.
 */
typedef struct
{
    /* Core layout/config */
    eemul_badblock_policy_t badblock_policy; /**< Policy for handling bad blocks. */
    eemul_block_mode_t block_mode;           /**< Logical block mode: full-page or sub-blocks. */

    /* Runtime tuning knobs */
    uint8_t bad_retry_threshold;    /**< Retire a block after this many HW errors (min=1, 0 = immediate retire). */
    bool enable_monotonic_sequence; /**< true = sequence numbers continue across format/recover; false = reset to 1. */
} eemul_init_config_t;

/**
 * @brief Low-level Flash operations supplied by the user/HAL.
 *
 * @note
 * - `program()` must write exactly `EEMUL_ALIGN_BYTES` at `addr`.
 * - The library guarantees aligned calls.
 */
typedef struct
{
    bool (*erase_page)(uint32_t addr);                    /**< Erase one physical Flash page at `addr`. */
    bool (*program)(uint32_t addr, const void *src);      /**< Program `EEMUL_ALIGN_BYTES` bytes at `addr`. */
    void (*read)(uint32_t addr, void *dst, uint32_t len); /**< Read `len` bytes from Flash. */
#if EEMUL_USE_FULL_BLOCK_HEADER
    uint32_t (*crc32)(const void *data, uint32_t len); /**< Optional CRC32 function; if NULL, SW fallback is used. */
#endif
} eemul_port_ops_t;

/**
 * @brief Runtime state/handle for EEPROM emulation.
 *
 * Allocated and maintained by the library. Applications should not modify
 * these fields directly, except via the public API.
 */
typedef struct
{
    /* Port operations */
    const eemul_port_ops_t *port_ops; /**< Flash/CRC HAL operations supplied by user. */

    /* Parameter descriptor */
    const uint8_t *param_descriptor; /**< Descriptor array: parameter sizes. */
    uint16_t param_count;            /**< Number of parameters in `param_descriptor`. */

#if EEMUL_USE_FULL_BLOCK_HEADER
    uint32_t param_descriptor_crc; /**< CRC32 of descriptor (for integrity checks). */
#endif

    /* Flash region */
    uint32_t region_start; /**< Region start address (inclusive). */
    uint32_t region_end;   /**< Region end address (exclusive). */

    /* Sizing & layout */
    uint16_t payload_size;         /**< Total aligned payload size from descriptor. */
    uint16_t header_size;          /**< Aligned size of block header. */
    uint16_t block_bytes;          /**< Logical block/slot size (header + payload, aligned). */
    uint16_t pages_per_block;      /**< Pages covered per block. */
    uint16_t subblocks_per_page;   /**< Slots per page in SUBBLOCKS mode. */
    uint16_t blocks_count;         /**< Total logical block count in region. */
    eemul_block_mode_t block_mode; /**< Layout mode: full-page or sub-blocks. */

    /* Active block tracking */
    uint16_t active_block_index;   /**< Index of latest committed block. */
    uint32_t active_block_address; /**< Base Flash address of the active block header. */
    uint32_t active_sequence;      /**< Sequence number of active block. */
    uint32_t next_sequence;        /**< Next sequence to use (managed by recover/format/commit). */

    /* Policies */
    eemul_badblock_policy_t badblock_policy; /**< Bad-block handling policy. */

    /* Runtime tunables */
    uint8_t bad_retry_threshold;    /**< Promote block to bad after this many HW errors (min 1). */
    bool enable_monotonic_sequence; /**< If true, use next_sequence instead of reset on format. */

    /* Buffers */
    uint8_t *shadow_buf; /**< Latest payload snapshot in RAM (length >= payload_size). */

    /* Runtime statistics */
    uint32_t *block_error_counts; /**< Transient error counters per block (reset on init). */
    bool *bad_block_flags;        /**< Per-block permanent bad flags (length = blocks_count). */

#if EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS
    uint16_t *param_offsets; /**< Precomputed parameter offsets (length = param_count). */
#endif

    bool owns_buffers; /**< True if buffers are dynamically allocated. */
} eemul_handle_t;

/* ---------------------------- Public API ---------------------------------- */

/**
 * @brief Initialize EEPROM emulation handle and discover latest active block.
 *
 * Steps:
 *  - Configure handle with port ops, descriptor, and init config.
 *  - Allocate or assign runtime buffers (static or dynamic).
 *  - Precompute layout, CRC, and parameter offsets.
 *  - Scan for bad-block markers.
 *  - Locate latest committed block; if none found, auto-format the region.
 *
 * @param handle Out: handle to initialize.
 * @param port_ops Flash port operations.
 * @param init_config Init-time configuration (mode, policies).
 * @param param_descriptor Descriptor array (per-param sizes).
 * @param param_count Number of parameters.
 * @retval EEMUL_STATUS_OK          Success.
 * @retval EEMUL_STATUS_ERR_PARAM   Invalid input or allocation failure.
 * @retval EEMUL_STATUS_ERR_LAYOUT  Invalid descriptor/layout.
 * @retval EEMUL_STATUS_ERR_HW      HW error during auto-format.
 * @retval EEMUL_STATUS_ERR_NOBLOCK No usable block available.
 */
eemul_status_t eemul_init(eemul_handle_t *handle, const eemul_port_ops_t *port_ops,
                          const eemul_init_config_t *init_config, const uint8_t *param_descriptor,
                          uint16_t param_count);

/**
 * @brief Deinitialize an EEMUL handle and release any owned resources.
 *
 * Call this when the emulation is no longer needed or before re-initializing
 * with different configuration. After this call, the handle must not be used
 * unless re-initialized with eemul_init().
 *
 * @param handle Handle to deinitialize.
 */
void eemul_deinit(eemul_handle_t *handle);

/**
 * @brief Recover the emulation state from Flash.
 *
 * Responsibilities:
 *  - Reloads bad-block markers (persistent retirements).
 *  - Scans the entire region to find the latest valid committed block.
 *  - Restores @ref eemul_handle_t::active_block_index,
 *    @ref eemul_handle_t::active_block_address, and sequence.
 *  - If monotonic sequence is enabled, also initializes
 *    @ref eemul_handle_t::next_sequence.
 *
 * If no valid block is found, falls back to @ref eemul_format()
 * to erase and reinitialize the region.
 *
 * @note Recovery does not attempt wear-leveling itself. From this point
 * onward, all new block selection is delegated to
 * @ref choose_next_good_block().
 *
 * @param handle Pointer to emulation handle.
 * @retval EEMUL_STATUS_OK        Recovery successful.
 * @retval EEMUL_STATUS_ERR_PARAM Null handle provided.
 * @retval EEMUL_STATUS_ERR_HW    Format failed after no valid blocks found.
 */
eemul_status_t eemul_recover(eemul_handle_t *handle);

/**
 * @brief Read a parameter by ID.
 *
 * @param handle Initialized handle.
 * @param param_id Parameter ID
 * @param dst Destination buffer.
 *
 * @retval EEMUL_STATUS_OK        Success.
 * @retval EEMUL_STATUS_ERR_PARAM Invalid ID/size or NULL pointer.
 */
eemul_status_t eemul_read_param(eemul_handle_t *handle, uint16_t param_id, void *dst);

/**
 * @brief Write a parameter by ID (atomic commit).
 *
 * @param handle Initialized handle.
 * @param param_id Parameter ID
 * @param src Source buffer.
 *
 * @retval EEMUL_STATUS_OK        Success.
 * @retval EEMUL_STATUS_ERR_PARAM Invalid ID/size or NULL pointer.
 * @retval EEMUL_STATUS_ERR_HW    Flash operation failure (commit aborted).
 *
 * @note If no data change is detected for the selected range, no write occurs.
 */
eemul_status_t eemul_write_param(eemul_handle_t *handle, uint16_t param_id, const void *src);

/**
 * @brief Read raw bytes from the active payload image.
 *
 * @param handle Initialized handle.
 * @param offset Byte offset within the payload image.
 * @param dst Destination buffer.
 * @param len Number of bytes to read.
 *
 * @retval EEMUL_STATUS_OK        Success.
 * @retval EEMUL_STATUS_ERR_PARAM Out-of-range or NULL pointer.
 */
eemul_status_t eemul_read_at(eemul_handle_t *handle, uint16_t offset, void *dst, uint16_t len);

/**
 * @brief Write raw bytes into the payload image (atomic commit).
 *
 * @param handle Initialized handle.
 * @param offset Byte offset within the payload image.
 * @param src Source buffer.
 * @param len Number of bytes to write.
 *
 * @retval EEMUL_STATUS_OK        Success.
 * @retval EEMUL_STATUS_ERR_PARAM Out-of-range or NULL pointer.
 * @retval EEMUL_STATUS_ERR_HW    Flash operation failure (commit aborted).
 *
 * @note If the range is unchanged, the write is skipped to save wear.
 */
eemul_status_t eemul_write_at(eemul_handle_t *handle, uint16_t offset, const void *src, uint16_t len);

/* Optional helper getters */
/**
 * @brief Get computed payload size (bytes).
 *
 * @param handle Handle.
 * @return Payload size or 0 if NULL.
 */
uint16_t eemul_get_payload_size(const eemul_handle_t *handle);

/**
 * @brief Get byte offset of a parameter within the payload.
 *
 * @param handle Handle.
 * @param param_id Parameter ID
 * @return Offset or 0 if invalid.
 */
uint16_t eemul_get_param_offset(const eemul_handle_t *handle, uint16_t param_id);

/**
 * @brief Get declared (max) size of a parameter.
 *
 * @param handle Handle.
 * @param param_id Parameter ID
 * @return Size or 0 if invalid.
 */
uint16_t eemul_get_param_size(const eemul_handle_t *handle, uint16_t param_id);

/**
 * @brief Begin a batch update (prepare shadow buffer for multiple changes).
 *
 * Loads the current active payload into the shadow buffer.
 *
 * @param handle Pointer to an initialized handle.
 * @retval EEMUL_STATUS_OK        Success.
 * @retval EEMUL_STATUS_ERR_PARAM Invalid handle.
 */
eemul_status_t eemul_begin_batch(eemul_handle_t *handle);

/**
 * @brief Apply a single parameter update into the shadow buffer.
 *
 * Does not commit to Flash; only modifies the RAM shadow buffer.
 *
 * @param handle Pointer to handle.
 * @param id Parameter index.
 * @param src Pointer to new data.
 * @param len Length in bytes (must match descriptor size).
 * @retval EEMUL_STATUS_OK        Success.
 * @retval EEMUL_STATUS_ERR_PARAM Invalid argument or size mismatch.
 */
eemul_status_t eemul_update_param_in_shadow(eemul_handle_t *handle, uint16_t param_id, const void *src, uint16_t len);

/**
 * @brief Commit all shadow buffer changes as a new block.
 *
 * Writes the shadow buffer back into Flash via the commit mechanism.
 *
 * @param handle Pointer to handle.
 * @retval EEMUL_STATUS_OK          Success.
 * @retval EEMUL_STATUS_ERR_HW      Flash operation failed.
 * @retval EEMUL_STATUS_ERR_NOBLOCK No safe candidate block found.
 */
eemul_status_t eemul_commit_batch(eemul_handle_t *handle);

#endif /* EEMUL_H */
