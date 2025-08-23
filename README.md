# ⚡ EEMUL — Flash-Backed EEPROM Emulation Middleware  

[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/burakenez/eemul)](https://github.com/burakenez/eemul/tags/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) ![Language: C](https://img.shields.io/badge/language-C-blue.svg) ![Platform: Embedded](https://img.shields.io/badge/platform-embedded-lightgrey.svg) ![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)  

✨ **EEMUL** is a **portable, robust, and configurable EEPROM emulation library** for microcontrollers that lack built-in EEPROM.  
It leverages **on-chip Flash** to provide **persistent parameter storage** with:  
- 🛡️ Atomic commits  
- 🔄 Wear leveling  
- ❌ Bad-block handling  
- 📦 Flexible block modes  
- 🧾 Descriptor-based layout  

---

## ✨ Features  

- 🛡️ **Atomic commit protocol** → prevents corrupted states after power loss.  
- 🔄 **Wear leveling (rotate)** → spreads writes evenly across blocks.  
- ❌ **Bad-block resilience** → skip or permanently mark failing pages.  
- 📦 **Multiple block modes**:  
  - **Page mode** → one Flash page = one block (simple).  
  - **Sub-block mode** → multiple blocks per page (space efficient).  
- 📐 **Header flexibility** → compact (16B) or full (32B) headers.  
- 🧾 **Descriptor-driven storage** → define parameter sizes once, library handles offsets.  
- 🛠️ **Shadow buffer in RAM** → enables differential writes & no-op suppression.  
- ⚙️ **Configurable buffer strategy** → static arrays (ROM friendly) or dynamic alloc (flexible).  
- 🔌 **Portable HAL port layer** → implement erase/program/read (CRC optional).  

---

## 🏗️ Architecture Overview  

- 🔹 Reserved Flash region is divided into **logical blocks**.  
- 🔹 Each block = **Header + Payload snapshot**.  
- 🔹 At runtime:  
  1. 📍 Locate latest valid committed block.  
  2. 📥 Load payload into RAM shadow buffer.  
  3. ✍️ On updates, create a new block (erase → precommit header → program payload → finalize commit).  
- 🔢 Sequence counters ensure monotonic versioning.  

⚡ **Power-loss safe**: only blocks with `commit_flag=0x00000000` are treated as valid.  

---

## 📐 Memory Layout  

### Page Mode  
```
[ Page 0 ] => Block0 (Header + Payload)
[ Page 1 ] => Block1 (Header + Payload)
...
```

### Sub-block Mode  
```
[ Page N ]
+---------+---------+---------+
| Block0  | Block1  | Block2  |
| H + P   | H + P   | H + P   |
+---------+---------+---------+
```

- **Page mode** → simple alignment, fewer blocks.  
- **Sub-block mode** → better density, useful when payload is small vs page size.  

---

## 📑 Header Options  

| Mode     | Size | Fields                                                      | Use case        |
|----------|------|-------------------------------------------------------------|-----------------|
| Compact  | 16B  | magic, sequence, CRC, commit                                | Space efficient |
| Full     | 32B  | magic, sequence, CRCs, payload len, bad-marker, commit flag | Max integrity   |

🔮 **Magic constants**:  
- Full header → `"EEMULATE"` (64-bit ASCII).  
- Compact header → `"EMUL"` (32-bit ASCII).  

---

## ⚙️ Configuration Macros  

```c
#define EEMUL_REGION_END_ADDR       0x08010000U   // Region end address (exclusive)
#define EEMUL_NUMBER_OF_FLASH_PAGES 2U            // Reserved pages
#define EEMUL_FLASH_PAGE_SIZE       0x400U        // 1KB per page
#define EEMUL_ALIGN_BYTES           4U            // Program alignment
#define EEMUL_ENABLE_DYNAMIC_ALLOC  1U            // Use malloc/calloc for buffers
#define EEMUL_USE_FULL_BLOCK_HEADER 1U            // 1=full (32B), 0=compact (16B)
```

Derived:  
- 🧮 `EEMUL_REGION_SIZE_BYTES = PAGES × PAGE_SIZE`  
- 🧮 `block_bytes = align_up(header + payload, PAGE_SIZE)`  
- 🧮 `blocks_count = REGION_SIZE / block_bytes`  

---

## 🧾 Descriptor Example  

```c
typedef uint8_t eemul_version_t[4];
typedef uint8_t eemul_statistics_t[20];
typedef uint8_t eemul_counter_t[1];
typedef uint8_t eemul_error_log_item_t[1];

const uint8_t s_descriptor[] = {
  /* ID 1: FW version */
  sizeof(eemul_version_t),
  /* IDs 2..12: error log entries */
  sizeof(eemul_error_log_item_t), sizeof(eemul_error_log_item_t), /* ... */
  /* ID 13: statistics page */
  sizeof(eemul_statistics_t),
  /* ID 14: counter */
  sizeof(eemul_counter_t)
};
```

---

## 🚀 Quick Start  

```c
// 1️⃣ Provide Flash ops
const eemul_port_ops_t ops = {
  .erase_page = my_erase,
  .program    = my_prog,
  .read       = my_read,
  .crc32      = NULL // SW CRC fallback
};

// 2️⃣ Configure
eemul_handle_t h;
const eemul_init_config_t cfg = {
  .badblock_policy  = EEMUL_BADBLOCK_POLICY_MARK,
  .block_mode       = EEMUL_BLOCK_MODE_SUBBLOCKS,
  .bad_retry_threshold = 2,
  .enable_monotonic_sequence  = true,
};

// 3️⃣ Init
eemul_init(&h, &ops, &cfg, s_descriptor, sizeof(s_descriptor));

// 4️⃣ Write parameter
uint32_t val = 0x12345678;
eemul_write_param(&h, 0, &val, sizeof(val));

// 5️⃣ Read parameter
val = 0;
eemul_read_param(&h, 0, &val, sizeof(val));
```

---

## 🧪 Testing Utilities  

Two built-in test modes:  

- 📝 **Region fill test** → sequential writes until the emulation region is full.  
- 🔄 **Overflow test** → observe behavior after storage exceeds capacity.  

Logs include:  
- 🔢 Active block index + sequence  
- 📍 Active block address  
- ✅ Read-back verification  

---

## 🔌 Porting Layer (eemul_port)  

Minimal hooks to implement per MCU:  

```c
bool erase_page(uint32_t addr);
bool program(uint32_t addr, const void *src); // size = EEMUL_ALIGN_BYTES
void read(uint32_t addr, void *dst, uint32_t len);
uint32_t crc32(const void *data, uint32_t len); // optional
```

Template: **eemul_port_template.c** demonstrates GD32 implementation.  

---

## 📂 Repository Structure  

```
├── eemul.h               # Public API & configuration
├── eemul.c               # Implementation
├── eemul_port.h          # Port interface definition
├── eemul_port_template.c # Example port
├── tests/
│   ├── eemul_test.h      # Test declarations
│   ├── eemul_test.c      # Region fill & overflow tests
└── README.md             # Project documentation
```

---

## 🤝 Contributing  

💡 Contributions are welcome:  
- 🐛 Report issues & suggest improvements.  
- 🍴 Fork and submit pull requests.  
- 🧪 Extend tests, add new port templates, or propose features (e.g., encryption).  

---

## 📜 License  

Released under the **MIT License**.  
Use freely in personal, academic, and commercial projects.  

---  

🔥 **EEMUL — reliable EEPROM emulation on any MCU, with Flash-backed safety.**  
