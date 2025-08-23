/**
 * @file eemul.c
 * @brief Flash-backed EEPROM emulation — implementation & internal notes.
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
 * This file contains the **core logic** of the EEPROM emulation library,
 * including block layout, commit paths, recovery, bad-block tracking, and
 * Flash port interactions.
 *
 * ### 1. Atomic commit mechanism
 * - Every block starts with a header containing metadata and a `commit_flag`.
 * - When creating a new block:
 *   1. Header is written with `commit_flag` erased (0xFFFFFFFF).
 *   2. Payload is programmed (aligned writes).
 *   3. The single aligned word containing `commit_flag` is programmed to 0x0.
 * - After a reset, only blocks with commit_flag cleared are considered valid.
 * - This ensures atomic visibility: a block is either fully active or ignored.
 *
 * ### 2. Page and sub-block layout
 * - **PAGE mode**: one block spans one or more physical pages.
 *   Each commit erases its full block range before writing.
 *
 *   ```
 *   [ Flash Page N ]
 *  +-----------------+  <- Block header
 *  |     Header      |
 *  +-----------------+  <- Payload (aligned to EEMUL_ALIGN_BYTES)
 *  |                 |
 *  |     Payload     |
 *  |                 |
 *  +-----------------+  <- Next block (next page)
 *   ```
 *
 * - **SUBBLOCKS mode**: each page is divided into multiple equal slots.
 *   The page is erased once before the first slot is used; subsequent slots
 *   can be programmed without erasing again.
 *
 *   ```
 *  [ Flash Page N ]
 *  +---------+---------+---------+---------+
 *  | Header  | Header  | Header  | Header  |
 *  | Payload | Payload | Payload | Payload |
 *  +---------+---------+---------+---------+
 *    Block0    Block1    Block2    Block3
 *   ```
 *
 * ### 3. Power-loss safety
 * - If reset occurs mid-commit:
 *   - Pre-commit blocks remain with commit_flag erased.
 *   - On recovery, only committed blocks are valid.
 *   - Sequence scanning skips stale headers but ensures sequence continuity.
 *
 * ### 4. Block selection and erasure
 * - The active block’s page is never erased while it is active.
 * - Candidate blocks are chosen in rotation.
 * - Blank blocks are used directly; non-blank safe pages are erased before use.
 * - Bad blocks are retried until `bad_retry_threshold`, then marked bad.
 *
 * ### 5. Recovery
 * - On `eemul_init()`, the library scans all blocks:
 *   - Finds the highest valid sequence → promotes it active.
 *   - If none found, invokes formatting: erase region, create new first block.
 * - If `enable_monotonic_sequence` is true, sequence continues across format.
 *   Otherwise, sequence restarts from 1.
 *
 * ### 6. Constraints
 * - Writes are always aligned to `EEMUL_ALIGN_BYTES`.
 * - Flash region must consist of ≥2 pages (compile-time enforced).
 * - Header type (compact/full) is fixed at build time.
 *
 * ### 7. Philosophy
 * - Correctness and safety over optimization.
 * - Avoids erasing live data under all conditions.
 * - Keeps state small: per-block transient error counters, persistent bad flags.
 *
 * ### 8. Error handling
 * - Hardware failures increment error counters per block.
 * - If a block exceeds the retry threshold, it is retired.
 * - With mark-on-flash policy, a marker is written to header so the block
 *   is skipped in future boots.
 */

#include "eemul.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if EEMUL_ENABLE_DYNAMIC_ALLOC /* Dynamic Alloc */
#include <stdlib.h>
#endif

/* ----------------------- Alignment / small math helpers -------------------- */

/**
 * @brief Align a 32-bit value up to the nearest multiple of @p a.
 *
 * @param v Value to align.
 * @param a Alignment (must be a power of two).
 * @return The smallest multiple of @p a greater than or equal to @p v.
 */
static inline uint32_t align_up_u32(uint32_t v, uint32_t a)
{
    return (v + (a - 1U)) & ~(a - 1U);
}

/**
 * @brief Align a 16-bit value up to the nearest multiple of @p a.
 *
 * @param v Value to align.
 * @param a Alignment (must be a power of two).
 * @return The smallest multiple of @p a greater than or equal to @p v.
 */
static inline uint16_t align_up_u16(uint16_t v, uint16_t a)
{
    return (uint16_t) ((v + (a - 1U)) & ~(a - 1U));
}

/* ------------------------------- Block header ------------------------------ */

/**
 * @brief On-flash block header (packed). `commit_flag` is last for atomicity.
 *
 * Fields:
 *  - magic:                must be `EEMUL_BLOCK_HEADER_MAGIC`
 *  - sequence:             monotonic sequence, larger wins
 *  - payload_len:          sanity for payload size
 *  - param_descriptor_crc: CRC32 of the descriptor array
 *  - hdr_crc:              CRC of `[magic..param_descriptor_crc]`
 *  - bad_marker:           0xFFFFFFFF if good; `EEMUL_BLOCK_HEADER_BAD_MARK_VALUE` if permanently bad
 *  - commit_flag:          0xFFFFFFFF until fully committed; 0x00000000 when valid
 */
#if EEMUL_USE_FULL_BLOCK_HEADER

typedef struct __attribute__((packed))
{
    uint64_t magic;                /* EEMUL_BLOCK_HEADER_MAGIC when valid */
    uint32_t sequence;             /* Monotonic sequence number */
    uint32_t payload_len;          /* Payload length (sanity) */
    uint32_t param_descriptor_crc; /* CRC32 of descriptor table */
    uint32_t hdr_crc;              /* CRC32 of fields [magic..param_descriptor_crc] */
    uint32_t bad_marker;           /* 0xFFFFFFFF normally; 0xBAD0BAD0 if block is permanently bad */
    uint32_t commit_flag;          /* 0xFFFFFFFF until fully committed; 0x00000000 when valid */
} eemul_block_header_t;

#else /* compact header */

typedef struct __attribute__((packed))
{
    uint32_t magic;       /* EEMUL_BLOCK_MAGIC when valid */
    uint32_t sequence;    /* Monotonic sequence number */
    uint32_t bad_marker;  /* 0xFFFFFFFF normally; 0xBAD0BAD0 if permanently bad */
    uint32_t commit_flag; /* 0xFFFFFFFF until fully committed; 0x00000000 when valid */
} eemul_block_header_t;

#endif

/**
 * @brief Compute the aligned header size.
 * @return Header size in bytes, rounded up to ::EEMUL_ALIGN_BYTES.
 */
static inline uint16_t header_full_size(void)
{
    return align_up_u16((uint16_t) sizeof(eemul_block_header_t), (uint16_t) EEMUL_ALIGN_BYTES);
}

/**
 * @brief Offset of the commit_flag field inside the header.
 * @return Byte offset of commit_flag.
 */
static inline uint32_t header_commit_offset(void)
{
    return (uint32_t) offsetof(eemul_block_header_t, commit_flag);
}

/**
 * @brief Offset of the bad_marker field inside the header.
 * @return Byte offset of bad_marker.
 */
static inline uint32_t header_bad_marker_offset(void)
{
    return (uint32_t) offsetof(eemul_block_header_t, bad_marker);
}

#if (EEMUL_ENABLE_DYNAMIC_ALLOC == 0) /* Static Alloc */

/* ------------------- Static Configuration / Worst-Case Sizes -------------- */

/**
 * @brief Compile-time aligned header size (rounded up to @ref EEMUL_ALIGN_BYTES).
 */
#define EEMUL_HDR_SIZE_COMPILETIME \
    (((sizeof(eemul_block_header_t) + (EEMUL_ALIGN_BYTES - 1)) / EEMUL_ALIGN_BYTES) * EEMUL_ALIGN_BYTES)

/**
 * @brief Minimum possible size of a logical sub-block:
 *        header + one alignment unit of payload.
 */
#define EEMUL_MIN_SUBBLOCK_BYTES (EEMUL_HDR_SIZE_COMPILETIME + EEMUL_ALIGN_BYTES)

/**
 * @brief Maximum number of logical blocks/slots in the region,
 *        assuming worst-case minimal sub-block size.
 *
 * - In full-page mode: one block per Flash page.
 * - In sub-block mode: multiple slots per page, worst-case based on @ref EEMUL_MIN_SUBBLOCK_BYTES.
 */
#define EEMUL_MAX_BLOCKS_STATIC  (EEMUL_NUMBER_OF_FLASH_PAGES * (EEMUL_FLASH_PAGE_SIZE / EEMUL_MIN_SUBBLOCK_BYTES))

/* --------------------------- Static RAM Buffers --------------------------- */

/**
 * @brief Static shadow buffer for payload snapshots.
 *
 * @note Size is controlled by @ref EEMUL_MAX_PAYLOAD_BYTES.
 */
static uint8_t s_shadow_buf_static[EEMUL_MAX_PAYLOAD_BYTES];

/**
 * @brief Static arrays sized for the worst-case number of blocks.
 *
 * - @ref s_bad_block_static          : persistent bad-block flags.
 * - @ref s_block_error_counts_static : transient per-block error counters.
 */
static bool s_bad_block_static[EEMUL_MAX_BLOCKS_STATIC];
static uint32_t s_block_error_counts_static[EEMUL_MAX_BLOCKS_STATIC];

#if EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS

/**
 * @brief Static array for parameter payload offsets.
 *
 * @note Size is controlled by @ref EEMUL_MAX_PARAM_COUNT.
 */
static uint16_t s_param_offsets_static[EEMUL_MAX_PARAM_COUNT];

#endif

#endif

#if EEMUL_USE_FULL_BLOCK_HEADER

/* -------------------------------- SW CRC32 -------------------------------- */

/**
 * @brief Compute CRC32 over a buffer (software fallback).
 *
 * Uses polynomial 0x04C11DB7, reflected input/CRC, initial 0xFFFFFFFF.
 *
 * @param data Pointer to buffer.
 * @param len Buffer length in bytes.
 * @return CRC32 value.
 */
static uint32_t sw_crc32(const void *data, uint32_t len)
{
    const uint8_t *p = (const uint8_t *) data;
    uint32_t crc = 0xFFFFFFFFU;
    for (uint32_t i = 0; i < len; ++i)
    {
        crc ^= p[i];
        for (uint8_t b = 0; b < 8; ++b)
        {
            uint32_t m = -(crc & 1u);
            crc = (crc >> 1) ^ (0x04C11DB7U & m);
        }
    }
    return ~crc;
}

/**
 * @brief Compute CRC32 using port implementation if available.
 *
 * Falls back to software CRC if @p handle->port_ops->crc32 is NULL.
 *
 * @param handle EEPROM emulation handle (may hold hw CRC function).
 * @param data Pointer to buffer.
 * @param len Buffer length in bytes.
 * @return CRC32 value.
 */
static inline uint32_t ee_crc32(const eemul_handle_t *handle, const void *data, uint32_t len)
{
    return (handle->port_ops && handle->port_ops->crc32) ? handle->port_ops->crc32(data, len) : sw_crc32(data, len);
}

#endif

/* ---------------------------- Address helpers ------------------------------ */

/**
 * @brief Compute the Flash page index containing a given block.
 *
 * - Page mode: page index = block_index × pages_per_block.
 * - Sub-block mode: page index = block_index / subblocks_per_page.
 *
 * @param handle Handle with geometry configuration.
 * @param block_index Logical block index.
 * @return Page index relative to emulation region start.
 */
static inline uint16_t slot_page_index(const eemul_handle_t *handle, uint16_t block_index)
{
    if (handle->block_mode != EEMUL_BLOCK_MODE_SUBBLOCKS)
        return block_index * handle->pages_per_block; /* page-aligned first page index */

    return (uint16_t) (block_index / handle->subblocks_per_page);
}

/**
 * @brief Compute the sub-block index within a page.
 *
 * - Page mode: always 0.
 * - Sub-block mode: block_index % subblocks_per_page.
 *
 * @param handle Handle with geometry configuration.
 * @param block_index Logical block index.
 * @return Sub-block index inside the page.
 */
static inline uint16_t slot_subindex_in_page(const eemul_handle_t *handle, uint16_t block_index)
{
    if (handle->block_mode != EEMUL_BLOCK_MODE_SUBBLOCKS)
        return 0;

    return (uint16_t) (block_index % handle->subblocks_per_page);
}

/**
 * @brief Compute the base address of a block.
 *
 * Includes header (points to first byte of header).
 *
 * @param handle Handle with geometry configuration.
 * @param block_index Logical block index.
 * @return Absolute Flash address of the block header.
 */
static inline uint32_t block_base_addr(const eemul_handle_t *handle, uint16_t block_index)
{
    if (handle->block_mode != EEMUL_BLOCK_MODE_SUBBLOCKS)
    {
        return handle->region_start + (uint32_t) block_index * handle->pages_per_block * EEMUL_FLASH_PAGE_SIZE;
    }
    /* SUBBLOCKS: base of slot within its page */
    uint32_t page_base = handle->region_start + (uint32_t) slot_page_index(handle, block_index) * EEMUL_FLASH_PAGE_SIZE;
    uint32_t offset_in_page = (uint32_t) slot_subindex_in_page(handle, block_index) * (uint32_t) handle->block_bytes;
    return page_base + offset_in_page;
}

/**
 * @brief Compute start address of the payload region for a block.
 *
 * @param handle Handle with geometry configuration.
 * @param block_index Logical block index.
 * @return Absolute Flash address of the payload area.
 */
static inline uint32_t block_payload_addr(const eemul_handle_t *handle, uint16_t block_index)
{
    return block_base_addr(handle, block_index) + handle->header_size;
}

/**
 * @brief Return the physical page base address that contains @p addr.
 *
 * @param addr Absolute flash address.
 * @return Base address of the flash page containing @p addr.
 */
static inline uint32_t page_base(uint32_t addr)
{
    return addr & ~(EEMUL_FLASH_PAGE_SIZE - 1U);
}

/* --------------------------- Descriptor helpers ---------------------------- */

/**
 * @brief Compute total payload size from descriptor.
 *
 * Each parameter is aligned to ::EEMUL_ALIGN_BYTES.
 *
 * @param descriptor Array of parameter sizes.
 * @param param_count Number of parameters in descriptor.
 * @return Total payload size in bytes, or 0 on error.
 */
static uint16_t compute_payload_size(const uint8_t *descriptor, uint16_t param_count)
{
    if (!descriptor || param_count == 0)
        return 0;
    uint32_t total = 0;
    for (uint16_t i = 0; i < param_count; ++i)
    {
        uint8_t s = descriptor[i];
        if (s > 0)
            total += align_up_u16(s, (uint16_t) EEMUL_ALIGN_BYTES);
        if (total > 0xFFFF)
            return 0;
    }
    return (uint16_t) total;
}

#if EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS

/**
 * @brief Precompute parameter offsets into payload.
 *
 * Offsets are stored in @p handle->param_offsets.
 *
 * @param handle EEPROM emulation handle.
 */
static void precompute_param_offsets(eemul_handle_t *handle)
{
    uint16_t off = 0;
    for (uint16_t i = 0; i < handle->param_count; ++i)
    {
        handle->param_offsets[i] = off;
        uint16_t sz = handle->param_descriptor[i];
        off += align_up_u16(sz, (uint16_t) EEMUL_ALIGN_BYTES);
    }
}

#else

/**
 * @brief Compute payload offset of a parameter.
 *
 * @param handle EEPROM emulation handle.
 * @param param_id 1-based parameter ID.
 * @return Offset in bytes, or 0xFFFF if invalid.
 */
static uint16_t compute_param_offset(const eemul_handle_t *handle, uint16_t param_id)
{
    if (param_id >= handle->param_count)
        return 0xFFFF; // invalid

    uint16_t offset = 0;
    for (uint16_t i = 0; i < param_id - 1; ++i)
    {
        uint16_t sz = handle->param_descriptor[i];
        offset = (offset + sz + (EEMUL_ALIGN_BYTES - 1)) & ~(EEMUL_ALIGN_BYTES - 1);
    }
    return offset;
}

#endif

/* ------------------------------ Low-level ops ------------------------------ */

/**
 * @brief Check that a flash [addr, addr+len) range is fully erased (0xFF).
 *
 * Reads flash in small chunks and verifies that every byte equals 0xFF.
 *
 * @param handle Handle providing the port operations (for flash read).
 * @param addr Start address of the flash range to check.
 * @param len  Number of bytes to check.
 * @retval true  Entire range is erased (all 0xFF).
 * @retval false At least one non-0xFF byte found.
 */
static bool flash_is_erased(const eemul_handle_t *handle, uint32_t addr, uint32_t len)
{
    uint8_t buf[32];
    while (len)
    {
        uint32_t n = (len < sizeof(buf)) ? len : (uint32_t) sizeof(buf);
        handle->port_ops->read(addr, buf, n);
        for (uint32_t i = 0; i < n; ++i)
        {
            if (buf[i] != 0xFFU)
                return false;
        }
        addr += n;
        len -= n;
    }
    return true;
}

/**
 * @brief Erase a whole block (page(s) or one page in sub-block mode).
 *
 * In SUBBLOCKS mode:
 *  - Erase only when targeting the first sub-block of a page.
 *  - This safely reclaims pages containing stale pre-commit blocks.
 *
 * @param handle Handle with port operations.
 * @param block_index Logical block index.
 * @retval true  Success.
 * @retval false Erase failed.
 */
static bool erase_block(const eemul_handle_t *handle, uint16_t block_index)
{
    if (handle->block_mode != EEMUL_BLOCK_MODE_SUBBLOCKS)
    {
        uint32_t base = block_base_addr(handle, block_index);
        uint32_t limit = base + handle->pages_per_block * EEMUL_FLASH_PAGE_SIZE;
        for (uint32_t a = base; a < limit; a += EEMUL_FLASH_PAGE_SIZE)
        {
            if (!handle->port_ops->erase_page(a))
                return false;
        }
        return true;
    }

    /* SUBBLOCKS mode */
    if (slot_subindex_in_page(handle, block_index) != 0)
        return true; /* nothing to erase */

    const uint32_t page_base_addr =
        handle->region_start + (uint32_t) slot_page_index(handle, block_index) * EEMUL_FLASH_PAGE_SIZE;

    return handle->port_ops->erase_page(page_base_addr);
}

/**
 * @brief Program an aligned range into Flash.
 *
 * Writes in ::EEMUL_ALIGN_BYTES sized chunks.
 *
 * @param handle Handle with port operations.
 * @param addr Destination Flash address (aligned).
 * @param src Source buffer.
 * @param len Length in bytes (multiple of ::EEMUL_ALIGN_BYTES).
 * @retval true  Success.
 * @retval false Programming failed.
 */
static bool program_aligned_range(const eemul_handle_t *handle, uint32_t addr, const void *src, uint32_t len)
{
    const uint8_t *p = (const uint8_t *) src;
    for (uint32_t off = 0; off < len; off += EEMUL_ALIGN_BYTES)
        if (!handle->port_ops->program(addr + off, p + off))
            return false;
    return true;
}

/**
 * @brief Program exactly one aligned chunk (EEMUL_ALIGN_BYTES).
 *
 * @param handle Handle with port operations.
 * @param addr Destination Flash address (aligned).
 * @param tmpbuf Source buffer of size EEMUL_ALIGN_BYTES.
 * @retval true  Success.
 * @retval false Programming failed.
 */
static bool program_one_chunk(const eemul_handle_t *handle, uint32_t addr, const uint8_t *tmpbuf)
{
    return handle->port_ops->program(addr, tmpbuf);
}

/* ------------------------------- Scanning -------------------------------- */

/**
 * @brief Check if a block slot is blank (erased) and safe to use.
 *
 * - In page mode: checks the entire block (page-aligned).
 * - In sub-block mode: checks only the slot size (header + payload),
 *   so later slots in the same page are not rejected prematurely.
 *
 * @param handle Emulation handle.
 * @param block_index Logical block index to check.
 * @return true if the region belonging to the block is fully erased, false otherwise.
 */
static bool block_is_blank_and_safe(const eemul_handle_t *handle, uint16_t block_index)
{
    const uint32_t base = block_base_addr(handle, block_index);
    const uint32_t hdr_sz = header_full_size();
    const uint32_t pay_sz = align_up_u32(handle->payload_size, EEMUL_ALIGN_BYTES);

    uint32_t blk_sz;
    if (handle->block_mode == EEMUL_BLOCK_MODE_SUBBLOCKS)
    {
        /* Just one slot (header + payload) */
        blk_sz = hdr_sz + pay_sz;
    }
    else
    {
        /* Full block aligned to page size */
        blk_sz = align_up_u32(hdr_sz + pay_sz, EEMUL_FLASH_PAGE_SIZE);
    }

    return flash_is_erased(handle, base, blk_sz);
}

/**
 * @brief Read header of a block into RAM.
 *
 * @param handle Handle with port operations.
 * @param block_index Logical block index.
 * @param out Output header struct.
 */
static void read_header(const eemul_handle_t *handle, uint16_t block_index, eemul_block_header_t *out)
{
    handle->port_ops->read(block_base_addr(handle, block_index), out, sizeof(*out));
}

/**
 * @brief Check validity of a block header.
 *
 * Verifies magic, size, CRC, markers and commit flag.
 *
 * @param handle Handle with configuration.
 * @param header Header to validate.
 * @retval true  Header is valid and committed.
 * @retval false Invalid or uncommitted.
 */
static bool header_is_valid(const eemul_handle_t *handle, const eemul_block_header_t *header)
{
    if (header->magic != EEMUL_BLOCK_HEADER_MAGIC)
        return false;
#if EEMUL_USE_FULL_BLOCK_HEADER
    if (header->payload_len != handle->payload_size)
        return false;
    if (header->param_descriptor_crc != handle->param_descriptor_crc)
        return false;
    uint32_t crc_calc = ee_crc32(handle, header, offsetof(eemul_block_header_t, hdr_crc));
    if (crc_calc != header->hdr_crc)
        return false;
#endif
    if (header->bad_marker == EEMUL_BLOCK_HEADER_BAD_MARK_VALUE) /* permanently bad */
        return false;
    if (header->commit_flag != 0x00000000U) /* require committed */
        return false;
    return true;
}

/**
 * @brief Detect if a block has a stale "pre-commit" header (power-loss remnant).
 *
 * Identifies blocks where the magic value is present but the commit_flag
 * is still erased (0xFFFFFFFF), indicating that the commit was interrupted
 * before finalization.
 *
 * @param handle Emulation handle (provides header size and ops).
 * @param block_index Logical block index to check.
 * @retval true  Block has a valid magic but uncommitted (erased) commit_flag.
 * @retval false Block is either not a header, fully valid/committed, or empty.
 */
static bool block_has_uncommitted_header(const eemul_handle_t *handle, uint16_t block_index)
{
    eemul_block_header_t header;
    read_header(handle, block_index, &header);

    /* A committed header would pass header_is_valid(). We want the opposite:
       magic OK + NOT committed. */
#if EEMUL_USE_FULL_BLOCK_HEADER
    const bool magic_ok = (header.magic == (uint64_t) EEMUL_BLOCK_HEADER_MAGIC);
#else
    const bool magic_ok = (header.magic == (uint32_t) EEMUL_BLOCK_HEADER_MAGIC);
#endif
    if (!magic_ok)
        return false;

    /* If commit flag is still erased, it’s a pre-commit (stale) header */
    /* In both header modes commit_flag is a 32-bit word aligned for atomic set-to-zero */
    return (header.commit_flag == 0xFFFFFFFFU) && !header_is_valid(handle, &header);
}

/**
 * @brief Check whether a block header exists in "pre-commit" state.
 *
 * A block is considered "pre-commit" if:
 *  - The header magic field matches ::EEMUL_BLOCK_HEADER_MAGIC, and
 *  - The commit_flag field is still erased (0xFFFFFFFF), and
 *  - The header CRC is not valid yet.
 *
 * This typically indicates a block that was in the process of being
 * written when a power loss occurred. Such blocks must be ignored for
 * active selection and skipped for reuse until erased.
 *
 * @param handle Emulation handle (provides flash ops and geometry).
 * @param block_index Logical block index to inspect.
 * @param seq_out_opt Optional pointer to receive the sequence number
 *                    stored in the header. May be NULL if not needed.
 *
 * @retval true  Block has a pre-commit header (stale/incomplete).
 * @retval false Block is either blank, fully valid/committed, or corrupt.
 */
static bool header_is_precommit(const eemul_handle_t *handle, uint16_t block_index, uint32_t *seq_out_opt)
{
    eemul_block_header_t header;
    read_header(handle, block_index, &header);

#if EEMUL_USE_FULL_BLOCK_HEADER
    bool magic_ok = (header.magic == (uint64_t) EEMUL_BLOCK_HEADER_MAGIC);
#else
    bool magic_ok = (header.magic == (uint32_t) EEMUL_BLOCK_HEADER_MAGIC);
#endif
    if (!magic_ok)
        return false;

    if (header.commit_flag == 0xFFFFFFFFU)
    {
        if (seq_out_opt)
            *seq_out_opt = header.sequence;
        return true;
    }
    return false;
}

/**
 * @brief Scan all blocks for persistent bad markers.
 *
 * Updates @p handle->bad_block_flags accordingly.
 *
 * @param handle Handle to update.
 */
static void scan_bad_markers(eemul_handle_t *handle)
{
    eemul_block_header_t header;
    for (uint16_t i = 0; i < handle->blocks_count; ++i)
    {
        read_header(handle, i, &header);
        if (header.bad_marker == EEMUL_BLOCK_HEADER_BAD_MARK_VALUE)
            handle->bad_block_flags[i] = true;
    }
}

/* ------------------------------- Init/Layout ------------------------------- */

/**
 * @brief Compute derived geometry of the emulation.
 *
 * Fills payload_size, header_size, block_bytes, pages_per_block,
 * subblocks_per_page, and blocks_count.
 *
 * @param handle Handle to populate.
 * @retval true  Success.
 * @retval false Invalid layout.
 */
static bool compute_layout(eemul_handle_t *handle)
{
    /* Compute total payload size from descriptor */
    handle->payload_size = compute_payload_size(handle->param_descriptor, handle->param_count);
    if (handle->payload_size == 0)
        return false;

    /* Compute aligned header size */
    handle->header_size = header_full_size();

    if (handle->block_mode == EEMUL_BLOCK_MODE_SUBBLOCKS)
    {
        /* One sub-block = header + aligned payload */
        uint32_t slot_bytes = handle->header_size + align_up_u32(handle->payload_size, EEMUL_ALIGN_BYTES);
        slot_bytes = align_up_u32(slot_bytes, EEMUL_ALIGN_BYTES);

        /* Must fit inside a single page */
        if (slot_bytes == 0 || slot_bytes > EEMUL_FLASH_PAGE_SIZE)
            return false;

        handle->block_bytes = (uint16_t) slot_bytes;
        handle->pages_per_block = 1;
        handle->subblocks_per_page = (uint16_t) (EEMUL_FLASH_PAGE_SIZE / slot_bytes);
        if (handle->subblocks_per_page == 0)
            return false;
    }
    else
    {
        /* One logical block = header + aligned payload, rounded up to page size */
        uint32_t block_bytes_u32 = handle->header_size + align_up_u32(handle->payload_size, EEMUL_ALIGN_BYTES);
        handle->block_bytes = (uint16_t) align_up_u32(block_bytes_u32, EEMUL_FLASH_PAGE_SIZE);

        handle->pages_per_block = (uint16_t) (handle->block_bytes / EEMUL_FLASH_PAGE_SIZE);
        if (handle->pages_per_block == 0)
            return false;

        handle->subblocks_per_page = 1;
    }

    /* Derive number of usable logical blocks */
    handle->blocks_count = (handle->block_mode == EEMUL_BLOCK_MODE_SUBBLOCKS)
                               ? (uint16_t) (EEMUL_NUMBER_OF_FLASH_PAGES * handle->subblocks_per_page)
                               : (uint16_t) (EEMUL_REGION_SIZE_BYTES / handle->block_bytes);

    if (handle->blocks_count == 0)
        return false;

#if (EEMUL_ENABLE_DYNAMIC_ALLOC == 0) /* Static Alloc */
    /* In static mode: enforce worst-case upper bound */
    if (handle->blocks_count > EEMUL_MAX_BLOCKS_STATIC)
        return false;
#endif

    return true;
}

/**
 * @brief Find the latest valid committed block by sequence.
 *
 * - Picks the block with the highest committed sequence as active.
 * - Tracks stale pre-commit headers (power-loss remnants) but never
 *   promotes them as active.
 * - Ensures that the next sequence number continues monotonically
 *   above both the active committed sequence and any stale ones.
 *
 * @param handle Handle to update.
 * @retval true  Found at least one valid committed block.
 * @retval false No committed blocks found (fresh region).
 */
static bool find_latest_block(eemul_handle_t *handle)
{
    uint32_t best_seq = 0;
    int best_idx = -1;

    uint32_t highest_stale_seq = 0;

    for (uint16_t i = 0; i < handle->blocks_count; ++i)
    {
        if (handle->bad_block_flags[i])
            continue;

        eemul_block_header_t header;
        read_header(handle, i, &header);

        /* Fully committed header → candidate */
        if (header_is_valid(handle, &header))
        {
            if (best_idx < 0 || header.sequence > best_seq)
            {
                best_idx = i;
                best_seq = header.sequence;
            }
        }
        /* Detect pre-commit (header written but not committed) */
        else
        {
            uint32_t seq_tmp = 0;
            if (header_is_precommit(handle, i, &seq_tmp))
            {
                if (seq_tmp > highest_stale_seq)
                    highest_stale_seq = seq_tmp;
            }
        }
    }

    if (best_idx < 0)
    {
        /* No valid committed block exists → treat as fresh state. */
        handle->active_block_index = 0;
        handle->active_sequence = 0;
        handle->active_block_address = block_base_addr(handle, 0);

        /* Next sequence must continue beyond any stale pre-commit remnants. */
        handle->next_sequence = highest_stale_seq + 1U;
        return false;
    }

    /* Found at least one committed block */
    handle->active_block_index = (uint16_t) best_idx;
    handle->active_sequence = best_seq;
    handle->active_block_address = block_base_addr(handle, (uint16_t) best_idx);

    /* Ensure next_sequence is strictly beyond both committed and stale */
    uint32_t min_next = best_seq + 1U;
    if (highest_stale_seq + 1U > min_next)
        min_next = highest_stale_seq + 1U;
    handle->next_sequence = min_next;

    return true;
}

/* ----------------------------- Next Block Index --------------------------- */

/**
 * @brief Choose the next good block (rotation policy).
 *
 * Rules:
 *  - In PAGE mode: never pick a block on the same physical page as the active block.
 *  - In SUBBLOCKS mode: allow other sub-blocks in the same page (they share erased space).
 *  - Prefer blank blocks; allow reclaim of uncommitted headers.
 *  - Return first usable candidate, or -1 if none.
 *
 * @param handle Pointer to initialized handle.
 * @return Block index to use, or -1 if none available.
 */
static int16_t choose_next_good_block(eemul_handle_t *handle)
{
    if (!handle || handle->blocks_count == 0)
        return -1;

    const uint32_t active_page = page_base(handle->active_block_address);

    for (uint16_t step = 1; step <= handle->blocks_count; ++step)
    {
        uint16_t idx = (uint16_t) ((handle->active_block_index + step) % handle->blocks_count);

        if (handle->bad_block_flags[idx])
            continue;

        const uint32_t cand_base = block_base_addr(handle, idx);
        const uint32_t cand_page = page_base(cand_base);

        /* Restriction: skip same page only in PAGE mode */
        if (handle->block_mode == EEMUL_BLOCK_MODE_PAGE && cand_page == active_page)
            continue;

        /* Allow reclaiming stale pre-commit blocks */
        if (block_has_uncommitted_header(handle, idx))
            return (int16_t) idx;

        /* Prefer blank */
        if (block_is_blank_and_safe(handle, idx))
            return (int16_t) idx;

        /* Otherwise: usable but needs erase */
        return (int16_t) idx;
    }

    return -1;
}

/* ------------------------- Atomic Commit Helpers --------------------------- */

/**
 * @brief Write a block header in pre-commit state.
 *
 * commit_flag remains 0xFFFFFFFF until finalized.
 *
 * @param handle Handle with port operations.
 * @param block_index Target block index.
 * @param sequence Sequence number to assign.
 * @retval true  Success.
 * @retval false Programming failed.
 */
static bool write_block_header_precommit(const eemul_handle_t *handle, uint16_t block_index, uint32_t sequence)
{
    /* Prepare header with commit_flag = 0xFFFFFFFF and bad_marker = 0xFFFFFFFF */
    eemul_block_header_t header;
    memset(&header, 0xFF, sizeof(header));
    header.magic = EEMUL_BLOCK_HEADER_MAGIC;
    header.sequence = sequence;
#if EEMUL_USE_FULL_BLOCK_HEADER
    header.payload_len = handle->payload_size;
    header.param_descriptor_crc = handle->param_descriptor_crc;
    header.hdr_crc = ee_crc32(handle, &header, offsetof(eemul_block_header_t, hdr_crc));
#endif
    header.bad_marker = 0xFFFFFFFFU;  /* not bad */
    header.commit_flag = 0xFFFFFFFFU; /* will be set to 0 at final commit */

    /* Write entire header as-is */
    uint32_t addr = block_base_addr(handle, block_index);
    uint16_t hsize = header_full_size();

    uint8_t tmp[(sizeof(eemul_block_header_t) > EEMUL_ALIGN_BYTES) ? sizeof(eemul_block_header_t) : EEMUL_ALIGN_BYTES];
    memset(tmp, 0xFF, sizeof(tmp));
    memcpy(tmp, &header, sizeof(header));

    return program_aligned_range(handle, addr, tmp, hsize);
}

/**
 * @brief Finalize a block by programming commit_flag to 0x00000000.
 *
 * @param handle Handle with port operations.
 * @param block_index Target block index.
 * @retval true  Success.
 * @retval false Programming failed.
 */
static bool write_block_commit_flag(const eemul_handle_t *handle, uint16_t block_index)
{
    /* Program only the aligned chunk containing commit_flag, turning those 4 bytes to 0x00. */
    uint32_t base = block_base_addr(handle, block_index);
    uint32_t off = header_commit_offset();
    uint32_t chunkbase = base + (off / EEMUL_ALIGN_BYTES) * EEMUL_ALIGN_BYTES;
    uint32_t in_chunk = off % EEMUL_ALIGN_BYTES;

    uint8_t chunk[EEMUL_ALIGN_BYTES];
    memset(chunk, 0xFF, sizeof(chunk));
    for (uint32_t i = 0; i < 4; ++i)
        chunk[in_chunk + i] = 0x00;

    return program_one_chunk(handle, chunkbase, chunk);
}

/**
 * @brief Mark a block as permanently bad.
 *
 * Programs bad_marker to EEMUL_BLOCK_HEADER_BAD_MARK_VALUE.
 *
 * @param handle Handle with port operations.
 * @param block_index Target block index.
 * @retval true  Success.
 * @retval false Programming failed.
 */
static bool write_block_bad_marker(const eemul_handle_t *handle, uint16_t block_index)
{
    /* Program the bad_marker word to EEMUL_BLOCK_HEADER_BAD_MARK_VALUE. */
    uint32_t base = block_base_addr(handle, block_index);
    uint32_t off = header_bad_marker_offset();
    uint32_t chunkbase = base + (off / EEMUL_ALIGN_BYTES) * EEMUL_ALIGN_BYTES;
    uint32_t in_chunk = off % EEMUL_ALIGN_BYTES;

    uint8_t chunk[EEMUL_ALIGN_BYTES];
    memset(chunk, 0xFF, sizeof(chunk));
    /* Write 0xBAD0BAD0 (has zeros) */
    chunk[in_chunk + 0] = (uint8_t) (EEMUL_BLOCK_HEADER_BAD_MARK_VALUE >> 0);
    chunk[in_chunk + 1] = (uint8_t) (EEMUL_BLOCK_HEADER_BAD_MARK_VALUE >> 8);
    chunk[in_chunk + 2] = (uint8_t) (EEMUL_BLOCK_HEADER_BAD_MARK_VALUE >> 16);
    chunk[in_chunk + 3] = (uint8_t) (EEMUL_BLOCK_HEADER_BAD_MARK_VALUE >> 24);

    return program_one_chunk(handle, chunkbase, chunk);
}

/* ------------------------- Commit Change (Atomic) -------------------------- */

/**
 * @brief Commit a change by creating a new block with modified payload.
 *
 * Guarantees:
 *  - Uses @ref choose_next_good_block() to select the next candidate
 *    (rotation is handled there; this function only commits to one block).
 *  - Skips unchanged writes by comparing the modified slice in the shadow buffer.
 *  - Never erases a page that contains the active block in PAGE mode
 *    (sub-blocks are allowed to share erased pages).
 *  - Skips stale pre-commit blocks; caller reclaims/erases when safe.
 *  - Erases non-blank blocks only when safe.
 *  - Uses monotonic or reset-style sequence numbering per configuration.
 *  - Tracks per-block HW errors and retires blocks after
 *    @ref eemul_handle_t::bad_retry_threshold failures.
 *
 * @param handle Handle with buffers and port operations.
 * @param offset Byte offset into payload.
 * @param src Source buffer with new data.
 * @param len Number of bytes to write.
 * @retval true  Success (block committed and promoted active).
 * @retval false Failure (no usable candidate or all steps failed).
 */
static bool commit_new_block_with_change(eemul_handle_t *handle, uint16_t offset, const void *src, uint16_t len)
{
    /* Snapshot active payload */
    const uint32_t curr_paddr = block_payload_addr(handle, handle->active_block_index);
    handle->port_ops->read(curr_paddr, handle->shadow_buf, handle->payload_size);

    /* No-op write avoidance: always slice-compare */
    if (memcmp(&handle->shadow_buf[offset], src, len) == 0)
        return true;

    /* Apply change */
    memcpy(&handle->shadow_buf[offset], src, len);

    /* Sequence policy */
    const uint32_t desired_seq =
        handle->enable_monotonic_sequence ? handle->next_sequence : (handle->active_sequence + 1U);

    /* Ask for one candidate */
    int16_t cand = choose_next_good_block(handle);
    if (cand < 0)
        return false; /* nothing usable */

    const uint16_t new_index = (uint16_t) cand;

    /* If not blank, erase (choose_next_good_block ensures it’s safe page-wise) */
    if (!block_is_blank_and_safe(handle, new_index))
    {
        if (!erase_block(handle, new_index))
        {
            if (++handle->block_error_counts[new_index] >= handle->bad_retry_threshold)
            {
                handle->bad_block_flags[new_index] = true;
                if (handle->badblock_policy == EEMUL_BADBLOCK_POLICY_MARK)
                    (void) write_block_bad_marker(handle, new_index);
            }
            return false;
        }
    }

    /* Pre-commit header */
    if (!write_block_header_precommit(handle, new_index, desired_seq))
    {
        if (++handle->block_error_counts[new_index] >= handle->bad_retry_threshold)
        {
            handle->bad_block_flags[new_index] = true;
            if (handle->badblock_policy == EEMUL_BADBLOCK_POLICY_MARK)
                (void) write_block_bad_marker(handle, new_index);
        }
        return false;
    }

    /* Program payload */
    const uint32_t paddr = block_payload_addr(handle, new_index);
    const uint32_t plen = align_up_u32(handle->payload_size, EEMUL_ALIGN_BYTES);
    if (!program_aligned_range(handle, paddr, handle->shadow_buf, plen))
    {
        if (++handle->block_error_counts[new_index] >= handle->bad_retry_threshold)
        {
            handle->bad_block_flags[new_index] = true;
            if (handle->badblock_policy == EEMUL_BADBLOCK_POLICY_MARK)
                (void) write_block_bad_marker(handle, new_index);
        }
        return false;
    }

    /* Final atomic commit */
    if (!write_block_commit_flag(handle, new_index))
    {
        if (++handle->block_error_counts[new_index] >= handle->bad_retry_threshold)
        {
            handle->bad_block_flags[new_index] = true;
            if (handle->badblock_policy == EEMUL_BADBLOCK_POLICY_MARK)
                (void) write_block_bad_marker(handle, new_index);
        }
        return false;
    }

    /* Success → Promote */
    handle->active_block_index = new_index;
    handle->active_sequence = desired_seq;
    handle->active_block_address = block_base_addr(handle, new_index);

    if (handle->enable_monotonic_sequence)
        handle->next_sequence = desired_seq + 1U;

    handle->block_error_counts[new_index] = 0; /* reset error count */
    return true;
}

/* --------------------------------- Format ---------------------------------- */

/**
 * @brief Format the entire emulation region.
 *
 * Responsibilities:
 *  - Erases all pages within the configured region.
 *  - Clears stale/uncommitted headers left by power loss.
 *  - Marks pages/blocks as permanently bad if erase fails
 *    (depending on badblock policy).
 *  - Initializes the first usable block with sequence = 1 (or next sequence
 *    if monotonic mode is enabled).
 *
 * After this call, the emulation handle is ready with a known
 * active block. Subsequent block allocation for commits is always
 * handled by @ref choose_next_good_block().
 *
 * @param handle Pointer to emulation handle.
 * @retval EEMUL_STATUS_OK          Region formatted and initialized.
 * @retval EEMUL_STATUS_ERR_PARAM   Null handle.
 * @retval EEMUL_STATUS_ERR_HW      Flash erase/program failed.
 * @retval EEMUL_STATUS_ERR_NOBLOCK No usable block found.
 */
static eemul_status_t eemul_format(eemul_handle_t *handle)
{
    if (!handle)
        return EEMUL_STATUS_ERR_PARAM;

    /* Reset all block flags */
    for (uint16_t i = 0; i < handle->blocks_count; ++i)
        handle->bad_block_flags[i] = false;

    /* Erase all pages in region */
    for (uint32_t addr = handle->region_start; addr < handle->region_end; addr += EEMUL_FLASH_PAGE_SIZE)
    {
        if (!handle->port_ops->erase_page(addr))
        {
            /* Mark the block owning this page as bad */
            uint16_t bad_idx = (uint16_t) ((addr - handle->region_start) / handle->block_bytes);
            if (bad_idx < handle->blocks_count)
            {
                handle->bad_block_flags[bad_idx] = true;
                if (handle->badblock_policy == EEMUL_BADBLOCK_POLICY_MARK)
                    (void) write_block_bad_marker(handle, bad_idx);
            }
        }
    }

    /* Defensive: clear stale pre-commit headers (should be gone after erase) */
    for (uint16_t i = 0; i < handle->blocks_count; ++i)
    {
        if (block_has_uncommitted_header(handle, i))
        {
            handle->bad_block_flags[i] = true;
            if (handle->badblock_policy == EEMUL_BADBLOCK_POLICY_MARK)
                (void) write_block_bad_marker(handle, i);
        }
    }

    /* Choose the initial sequence number */
    uint32_t init_seq = 1U;
    if (handle->enable_monotonic_sequence && handle->next_sequence > 0U)
        init_seq = handle->next_sequence;

    /* Initialize the very first usable block */
    for (uint16_t i = 0; i < handle->blocks_count; ++i)
    {
        if (!handle->bad_block_flags[i])
        {
            if (!erase_block(handle, i))
            {
                handle->bad_block_flags[i] = true;
                continue;
            }
            if (!write_block_header_precommit(handle, i, init_seq))
                return EEMUL_STATUS_ERR_HW;

            /* Optional: initialize payload to zeros (consistent cold-start state) */
            memset(handle->shadow_buf, 0x00, handle->payload_size);
            const uint32_t paddr = block_payload_addr(handle, i);
            const uint32_t plen = align_up_u32(handle->payload_size, EEMUL_ALIGN_BYTES);
            if (!program_aligned_range(handle, paddr, handle->shadow_buf, plen))
                return EEMUL_STATUS_ERR_HW;

            if (!write_block_commit_flag(handle, i))
                return EEMUL_STATUS_ERR_HW;

            /* Update active state */
            handle->active_block_index = i;
            handle->active_block_address = block_base_addr(handle, i);
            handle->active_sequence = init_seq;
            handle->next_sequence = init_seq + 1U; /* keep monotonic progress if enabled */

            return EEMUL_STATUS_OK;
        }
    }

    return EEMUL_STATUS_ERR_NOBLOCK;
}

/* ---------------------------- Public API ---------------------------------- */

eemul_status_t eemul_init(eemul_handle_t *handle, const eemul_port_ops_t *port_ops,
                          const eemul_init_config_t *init_config, const uint8_t *param_descriptor, uint16_t param_count)
{
    if (!handle || !port_ops || !param_descriptor || !init_config)
        return EEMUL_STATUS_ERR_PARAM;

    memset(handle, 0, sizeof(*handle));
    handle->port_ops = port_ops;
    handle->param_descriptor = param_descriptor;
    handle->param_count = param_count;
    handle->badblock_policy = init_config->badblock_policy;
    handle->block_mode = init_config->block_mode;

    /* New runtime tunables */
    handle->bad_retry_threshold = init_config->bad_retry_threshold ? init_config->bad_retry_threshold : 1U;
    handle->enable_monotonic_sequence = init_config->enable_monotonic_sequence;

    handle->region_start = EEMUL_REGION_START_ADDR;
    handle->region_end = handle->region_start + EEMUL_REGION_SIZE_BYTES;

#if EEMUL_USE_FULL_BLOCK_HEADER
    /* Precompute descriptor CRC */
    handle->param_descriptor_crc = ee_crc32(handle, param_descriptor, param_count);
#endif

    /* Precompute layout */
    if (!compute_layout(handle))
        return EEMUL_STATUS_ERR_LAYOUT;

    /* Allocate or assign buffers */
    handle->owns_buffers = false;

#if (EEMUL_ENABLE_DYNAMIC_ALLOC == 0) /* Static Alloc */

    handle->shadow_buf = s_shadow_buf_static;
    if (handle->blocks_count > EEMUL_MAX_BLOCKS_STATIC)
        return EEMUL_STATUS_ERR_LAYOUT;

    handle->bad_block_flags = s_bad_block_static;
    handle->block_error_counts = s_block_error_counts_static; /* <-- ensure this static is defined */

    if (handle->param_count > (sizeof(s_param_offsets_static) / sizeof(s_param_offsets_static[0])))
        return EEMUL_STATUS_ERR_LAYOUT;
#if EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS
    handle->param_offsets = s_param_offsets_static;
#endif

#elif (EEMUL_ENABLE_DYNAMIC_ALLOC == 1) /* Dynamic Alloc */

    handle->shadow_buf = (uint8_t *) malloc(align_up_u32(handle->payload_size, EEMUL_ALIGN_BYTES));
    handle->bad_block_flags = (bool *) calloc(handle->blocks_count, sizeof(bool));
    handle->block_error_counts = (uint32_t *) calloc(handle->blocks_count, sizeof(uint32_t));
#if EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS
    handle->param_offsets = (uint16_t *) malloc(sizeof(uint16_t) * handle->param_count);
#endif
    if (!handle->shadow_buf || !handle->bad_block_flags || !handle->block_error_counts
#if EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS
        || !handle->param_offsets
#endif
    )
    {
        if (handle->shadow_buf)
            free(handle->shadow_buf);
        if (handle->bad_block_flags)
            free(handle->bad_block_flags);
        if (handle->block_error_counts)
            free(handle->block_error_counts);
#if EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS
        if (handle->param_offsets)
            free(handle->param_offsets);
#endif
        memset(handle, 0, sizeof(*handle));
        return EEMUL_STATUS_ERR_PARAM;
    }
    handle->owns_buffers = true;
#else
    return EEMUL_STATUS_ERR_PARAM;
#endif

    /* Init RAM structures */
    memset(handle->bad_block_flags, 0, sizeof(bool) * handle->blocks_count);
    memset(handle->block_error_counts, 0, sizeof(uint32_t) * handle->blocks_count);

#if EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS
    precompute_param_offsets(handle);
#endif

    /* Finally → recovery (will set active/next sequence, honoring monotonic sequencing) */
    return eemul_recover(handle);
}

void eemul_deinit(eemul_handle_t *handle)
{
    if (!handle)
        return;

#if EEMUL_ENABLE_DYNAMIC_ALLOC /* Dynamic Alloc */
    /* Only free if this handle allocated its own buffers */
    if (handle->owns_buffers)
    {
        if (handle->shadow_buf)
            free(handle->shadow_buf);
        if (handle->bad_block_flags)
            free(handle->bad_block_flags);
        if (handle->block_error_counts)
            free(handle->block_error_counts);
#if EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS
        if (handle->param_offsets)
            free(handle->param_offsets);
#endif
    }
#endif

    /* Zero out the handle to avoid dangling pointers */
    memset(handle, 0, sizeof(*handle));
}

eemul_status_t eemul_recover(eemul_handle_t *handle)
{
    if (!handle)
        return EEMUL_STATUS_ERR_PARAM;

    /* Defensive: reload bad markers */
    scan_bad_markers(handle);

    /* Try to find the latest valid committed block.
       find_latest_block() also inspects stale pre-commit headers and sets:
       - handle->active_block_index/address/active_sequence when found
       - handle->next_sequence = max(latest_committed+1, highest_stale+1)
       This naturally honors monotonic sequencing if enabled. */
    if (find_latest_block(handle))
        return EEMUL_STATUS_OK;

    /* None found → fall back to formatting (will use handle->next_sequence if monotonic) */
    return eemul_format(handle);
}

eemul_status_t eemul_read_at(eemul_handle_t *handle, uint16_t offset, void *data, uint16_t len)
{
    if (!handle || !data)
        return EEMUL_STATUS_ERR_PARAM;
    if ((uint32_t) offset + len > handle->payload_size)
        return EEMUL_STATUS_ERR_PARAM;

    uint32_t addr = block_payload_addr(handle, handle->active_block_index) + offset;
    handle->port_ops->read(addr, data, len);
    return EEMUL_STATUS_OK;
}

eemul_status_t eemul_write_at(eemul_handle_t *handle, uint16_t offset, const void *src, uint16_t len)
{
    if (!handle || !src)
        return EEMUL_STATUS_ERR_PARAM;
    if ((uint32_t) offset + len > handle->payload_size)
        return EEMUL_STATUS_ERR_PARAM;

    if (!commit_new_block_with_change(handle, offset, src, len))
        return EEMUL_STATUS_ERR_HW;

    return EEMUL_STATUS_OK;
}

/* ------------------------------ Param helpers ------------------------------ */

eemul_status_t eemul_read_param(eemul_handle_t *handle, uint16_t param_id, void *dst)
{
    if (!handle || !dst || param_id >= handle->param_count)
        return EEMUL_STATUS_ERR_PARAM;

    uint16_t size = eemul_get_param_size(handle, param_id);
    uint16_t offset = eemul_get_param_offset(handle, param_id);

    if (size == 0 || offset == 0xFFFFU)
        return EEMUL_STATUS_ERR_PARAM;

    return eemul_read_at(handle, offset, dst, size);
}

eemul_status_t eemul_write_param(eemul_handle_t *handle, uint16_t param_id, const void *src)
{
    if (!handle || !src || param_id >= handle->param_count)
        return EEMUL_STATUS_ERR_PARAM;

    uint16_t size = eemul_get_param_size(handle, param_id);
    uint16_t offset = eemul_get_param_offset(handle, param_id);

    if (size == 0 || offset == 0xFFFFU)
        return EEMUL_STATUS_ERR_PARAM;

    if (!commit_new_block_with_change(handle, offset, src, size))
        return EEMUL_STATUS_ERR_HW;

    return EEMUL_STATUS_OK;
}

uint16_t eemul_get_payload_size(const eemul_handle_t *handle)
{
    return handle ? handle->payload_size : 0;
}

uint16_t eemul_get_param_offset(const eemul_handle_t *handle, uint16_t param_id)
{
    if (!handle || param_id >= handle->param_count)
        return 0;

#if EEMUL_ENABLE_PRECOMPUTE_PARAM_OFFSETS
    return handle->param_offsets[param_id];
#else
    return compute_param_offset(handle, param_id);
#endif
}

uint16_t eemul_get_param_size(const eemul_handle_t *handle, uint16_t param_id)
{
    if (!handle || param_id >= handle->param_count)
        return 0;

    return handle->param_descriptor[param_id];
}

/* ------------------------------- Batch API -------------------------------- */

eemul_status_t eemul_begin_batch(eemul_handle_t *handle)
{
    if (!handle)
        return EEMUL_STATUS_ERR_PARAM;

    const uint32_t curr_paddr = block_payload_addr(handle, handle->active_block_index);
    handle->port_ops->read(curr_paddr, handle->shadow_buf, handle->payload_size);

    return EEMUL_STATUS_OK;
}

eemul_status_t eemul_update_param_in_shadow(eemul_handle_t *handle, uint16_t param_id, const void *src, uint16_t len)
{
    if (!handle || !src || param_id >= handle->param_count)
        return EEMUL_STATUS_ERR_PARAM;

    const uint16_t expected = eemul_get_param_size(handle, param_id);
    if (expected != len)
        return EEMUL_STATUS_ERR_PARAM;

    const uint16_t off = eemul_get_param_offset(handle, param_id);
    memcpy(&handle->shadow_buf[off], src, len);
    return EEMUL_STATUS_OK;
}

eemul_status_t eemul_commit_batch(eemul_handle_t *handle)
{
    if (!handle)
        return EEMUL_STATUS_ERR_PARAM;

    if (!commit_new_block_with_change(handle, 0, handle->shadow_buf, handle->payload_size))
        return EEMUL_STATUS_ERR_HW;

    return EEMUL_STATUS_OK;
}
