# 🛠️ Adjust-Feature: The Ultimate Windows Feature Framework
An advanced PowerShell framework for toggling hidden Windows features by interfacing with the **RTL (Runtime Library)** and **WNF (Windows Notification Facility)** subsystems. 

This tool merges the logic of **ViVeTool** and **Mach2**, providing a unified interface to manipulate the `FeatureConfiguration` state blobs and registry overrides used by `ntdll.dll`.

---

## 🏗️ Architecture Overview

The script operates across the entire Windows Feature Management stack, ensuring changes are either permanent or instantaneous.

### 1. The Fcon Layer (Persistent Storage & Intent)
This is the static "Source of Truth" on the disk. It ensures that configurations survive a power cycle and are available for the very next boot sequence.

* **Location:** User-mode (fcon.dll) and Registry Hives.
* **Mechanism:** - StorageWriter::WriteFeatureStates: Encodes Feature IDs and states into the Registry.
  - StorageWriter::FlushFeatureOverrides: Commits the Registry Hive to the physical disk.
* **Transition Logic:** Once the Registry is updated, this layer initiates a call to the RTL Layer (RtlSetFeatureConfigurations) to synchronize the current session. Simultaneously, it leaves the data on disk for winload.exe to find during the next startup.

### 2. The RTL Layer (Boot Initialization & Live Kernel SYSCALL)
This is the active enforcement layer that bridges the gap between Registry data and CPU execution. It operates in two distinct phases:

* **Phase A (The Boot Load):** During the pre-boot sequence, winload.exe (or winload.efi) uses the Fsep (Feature Selection) functions to read the SYSTEM Registry hive. It decrypts the Feature IDs and prepares the "Boot Feature List" to be passed to ntoskrnl.exe. This ensures features are active before the first driver even loads.
* **Phase B (The Live Update):** At runtime, fcon.dll executes RtlSetFeatureConfigurations, which triggers a SYSCALL. This crosses the boundary from User Mode (Ring 3) to Kernel Mode (Ring 0). The Feature Manager (Fmp) inside ntoskrnl.exe receives the update and physically modifies the feature bitmask in the Kernel's Non-Paged Pool memory.
* **Impact:** High-priority enforcement. This part updates the kernel state both at startup and in real-time.

### 3. The WNF Layer (Subsystem Notification)
The "Modern" broadcast layer that tells User-Mode applications that the Kernel and Registry states have changed.

* **Mechanism:** RtlPublishWnfStateData(WNF_FCON_PENDING_FEATURE_CONFIGS_CHANGED).
* **Impact:** Triggers immediate notifications to running processes (e.g., explorer.exe) to update the UI without a restart.

---

## 📝 Capability Matrix

| Feature | RTL Engine | WNF Engine |
| :--- | :---: | :---: |
| **Persistence** | Permanent (Registry) | Volatile (Memory) |
| **Instant UI Update** | No | **Yes** |
| **A/B Test Override** | High | Medium |
| **Requires Reboot** | Sometimes | **Never** |

---

## 🧪  Demonstration Script

The following demo showcases the full lifecycle of feature manipulation across both RTL and WNF stacks.

```powershell
Clear-Host
Write-Host

# Feature List
$Variant    = 0,1,2
$Feature    = 57517687, 58755790, 59064570
$UserPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\8"
$PolicyPath = 'HKLM:SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides'

Set-FeatureConfiguration   -Feature $Feature -Action Reset -Mode User   | Out-Null
Set-FeatureConfiguration   -Feature $Feature -Action Reset -Mode Policy | Out-Null

Write-Host "  * FCON, Mode: Enabled, Variants`n" -ForegroundColor Green
Modify-StagingControls        -Feature $Feature -State Default                   | Out-Null
Modify-StagingControls        -Feature $Feature -State Enabled                   | Out-Null
Modify-StagingControlVariants -Feature $Feature -State Enabled -Variant $Variant | Out-Null

Get-ChildItem $UserPath -ea 0 | % { Get-ItemProperty $_.PSPath } | 
    Format-Table @{n='FeatureId';e='PSChildName';a='Center';w=15}, 
                 @{n='State';e='EnabledState';a='Center';w=10}, 
                 @{n='Variant';e='Variant';a='Center';w=10}, 
                 @{n='Kind';e='VariantPayloadKind';a='Center';w=10}, 
                 @{n='Payload';e='VariantPayload';a='Center';w=10}

Write-Host "  * RTL, User/Kernel Mode: Enable & Set Variant" -ForegroundColor Green
Set-FeatureConfiguration -Feature $Feature -Variant $Variant -Action Enable -Mode User   -Store Runtime | Out-Null
Set-FeatureConfiguration -Feature $Feature -Variant $Variant -Action Enable -Mode Policy -Store Runtime | Out-Null

$Overrides = Get-ChildItem $UserPath -ea 0
$UserQuery = Query-FeatureConfiguration -Feature $Feature
$KernelQuery = Query-KernelFeatureState -Feature $Feature -ApplyFlags

$Overrides | % { Get-ItemProperty $_.PSPath } | Format-Table `
    @{Expression="PSChildName";         Label="Feature ID";    Alignment="Center"; Width=15},
    @{Expression="EnabledState";        Label="State";         Alignment="Center"; Width=12},
    @{Expression="EnabledStateOptions"; Label="Options";       Alignment="Center"; Width=15},
    @{Expression="Variant";             Label="Variant";       Alignment="Center"; Width=10},
    @{Expression="VariantPayload";      Label="Payload";       Alignment="Center"; Width=15},
    @{Expression="VariantPayloadKind";  Label="Kind";          Alignment="Center"; Width=10}

Write-Host "  * Query, Mode:User" -ForegroundColor Green
$UserQuery | Format-Table @{Expression="FeatureId"; Alignment="Center"; Width=15},
             @{Expression="Priority"; Alignment="Center"; Width=10},
             @{Expression="EnabledState"; Alignment="Center"; Width=15},
             @{Expression="Variant"; Alignment="Center"; Width=10},
             @{Expression="VariantPayloadKind"; Alignment="Center"; Width=20},
             @{Expression="IsWexpConfiguration"; Alignment="Center"; Width=20},
             @{Expression="HasSubscriptions"; Alignment="Center"; Width=18}

Write-Host "  * Query, Mode:Kernel" -ForegroundColor Green
$KernelQuery | Format-Table @{Expression="FeatureId"; Alignment="Center"; Width=15},
             @{Expression="Priority"; Alignment="Center"; Width=10},
             @{Expression="EnabledState"; Alignment="Center"; Width=15},
             @{Expression="Variant"; Alignment="Center"; Width=10},
             @{Expression="VariantPayloadKind"; Alignment="Center"; Width=20},
             @{Expression="IsWexpConfiguration"; Alignment="Center"; Width=20},
             @{Expression="HasSubscriptions"; Alignment="Center"; Width=18}


Write-Host "  * WNF, Mode: Enable`n" -ForegroundColor Green
Set-WnfFeatureConfig   -Store User    -Mode Enable -Feature $Feature | Out-Null
Set-WnfFeatureConfig   -Store Machine -Mode Enable -Feature $Feature | Out-Null
$wnfUser =  Query-WnfFeatureConfig -Store User    -Feature $Feature
$wnfQuery = Query-WnfFeatureConfig -Store Machine -Feature $Feature

# Formatted User Store
$wnfUser | Format-Table `
    @{Expression="FeatureId";    Label="FeatureId";    Alignment="Center"; Width=15},
    @{Expression="ServiceState"; Label="Priority";     Alignment="Center"; Width=10}, 
    @{Expression="StateText";    Label="EnabledState"; Alignment="Center"; Width=15}, 
    @{Expression="Payload";      Label="Variant";      Alignment="Center"; Width=10},
    @{Expression="Kind";         Label="PayloadKind";  Alignment="Center"; Width=20},
    @{Expression="InVariantList";Label="WexpConfig";   Alignment="Center"; Width=20},
    @{Expression={ $false };     Label="Subscriptions";Alignment="Center"; Width=18}

# Formatted Machine Store
$wnfQuery | Format-Table `
    @{Expression="FeatureId";    Label="FeatureId";    Alignment="Center"; Width=15},
    @{Expression="ServiceState"; Label="Priority";     Alignment="Center"; Width=10}, 
    @{Expression="StateText";    Label="EnabledState"; Alignment="Center"; Width=15}, 
    @{Expression="Payload";      Label="Variant";      Alignment="Center"; Width=10},
    @{Expression="Kind";         Label="PayloadKind";  Alignment="Center"; Width=20},
    @{Expression="InVariantList";Label="WexpConfig";   Alignment="Center"; Width=20},
    @{Expression={ $false };     Label="Subscriptions";Alignment="Center"; Width=18}

return
```
---

## 🧪 Decode & Encode Feature ID

This section provides logic and source references for encoding and decoding **FeatureIDs** in the Windows Registry.

### 📂 Registry Location
Overrides are managed at:
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides`

---

### ⚙️ Transformation Logic

#### **Decode Algorithm (Winload.exe)**
Used to translate the registry value back to a readable Feature ID.

`_byteswap_ulong(__ROL4__(v18 ^ 0x833EA8FF, 255) ^ 0x8FB23D4F) ^ 0x74161A4E;`

**Search Reference (IDA):** `833EA8FFh` or `FeatureManagement`
* Found in: `FsepInitializeFeatureUsageSubscriptions`, `FsepPopulateFeatureConfigurationsForPolicyKey`

#### **Encode Algorithm (CmService.dll / MitigationClient.dll / fcon.dll)**
Used to generate the value stored in the registry.

`__ROR4__(_byteswap_ulong(v18 ^ 0x74161A4E) ^ 0x8FB23D4F, 255) ^ 0x833EA8FF;`

**Search Reference (IDA):** `833EA8FFh`
* Found in: `StorageWriter::CreateFeatureKey`, `StorageWriter::WritePolicyFeatureState`

---

### 🧠 Kernel-Mode Memory Layout (Feature Tables)
While the RTL layer manages the Registry and WNF manages notifications, 

the **Kernel Feature Table** is the actual memory-mapped structure used 

by the Windows Executive (`ntoskrnl.exe`) to evaluate feature states at runtime.

```text
typedef enum _SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE {
    Boot          = 0,
    Runtime       = 1,
    UsageTriggers = 2,
    Count         = 3
} SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE;

typedef struct _KERNEL_FEATURE_TABLE {

    /* 0x00 */ UINT64 ChangeStamp;      // Global sequence number for updates
    
    // --- Boot Section (Block 1) ---
    /* 0x08 */ UINT64 Boot_STAMP;       // Section-specific version/stamp (HeaderFlags)
    /* 0x10 */ HANDLE Boot_Handle;      // Section object handle
    /* 0x18 */ UINT64 Boot_Size;        // Total bytes in the section
    
    // --- Runtime Section (Block 2) ---
    /* 0x20 */ UINT64 Runtime_STAMP;    // Section-specific stamp
    /* 0x28 */ HANDLE Runtime_Handle;   // Section object handle
    /* 0x30 */ UINT64 Runtime_Size;     // Total bytes in the section
    
    // --- Default Section (Block 3) ---
    /* 0x38 */ UINT64 Default_STAMP;    // Section-specific stamp
    /* 0x40 */ HANDLE Default_Handle;   // Section object handle
    /* 0x48 */ UINT64 Default_Size;     // Total bytes in the section

} KERNEL_FEATURE_TABLE, *PKERNEL_FEATURE_TABLE;
```
---

# 🧠 FCON Feature Control – Internal API Notes

This documentation details the low-level structures and exported functions found in `fcon.dll` used for managing Windows Feature Configuration (Staging).

---

#### 📋 Data Structures (C++)

Both structures require 1-byte alignment to match the internal memory layout of the Feature Manager.

```cpp
// Size: 8 bytes (0x08)
// Used for simple feature toggles
typedef struct _RTL_STAGING_FEATURE_ENTRY {
    uint32_t FeatureId;    // 0x00: The unique ID of the feature
    uint8_t  State;        // 0x04: 0 = Default, 1 = Disabled, 2 = Enabled
    uint8_t  Reserved[3];  // 0x05: Alignment padding to 8 bytes
} RTL_STAGING_FEATURE_ENTRY;

// Size: 12 bytes (0x0C)
// Used for features with specific variants/sub-configurations
typedef struct _RTL_STAGING_VARIANT_ENTRY {
    uint32_t FeatureId;    // 0x00: The unique ID of the feature
    uint8_t  State;        // 0x04: 0 = Default, 1 = Disabled, 2 = Enabled
    uint8_t  Reserved1[3]; // 0x05: Alignment padding
    uint8_t  Variant;      // 0x08: The variant index to apply
    uint8_t  Reserved2[3]; // 0x09: Alignment padding to 12 bytes
} RTL_STAGING_VARIANT_ENTRY;

🛠 API Information (C++)
These functions are exported by fcon.dll and are responsible for committing the structure arrays into the system state.

C++
/**
 * @brief Modifies basic feature staging controls.
 * @param Priority     1 = Service, 2 = User, 3 = Test
 * @param Count        Number of elements in the Buffer
 * @param Buffer       Pointer to an array of RTL_STAGING_FEATURE_ENTRY
 * @param WipeExisting 1 to clear previous overrides in this priority, 0 to append
 */
extern "C" HRESULT ModifyStagingControls(
    uint8_t  Priority,
    uint64_t Count,
    void* Buffer,
    uint8_t  WipeExisting
);

/**
 * @brief Modifies feature staging controls with variant support.
 * @param Priority     1 = Service, 2 = User, 3 = Test
 * @param Count        Number of elements in the Buffer
 * @param Buffer       Pointer to an array of RTL_STAGING_VARIANT_ENTRY
 * @param WipeExisting 1 to clear previous overrides in this priority, 0 to append
 */
extern "C" HRESULT ModifyStagingControlVariants(
    uint8_t  Priority,
    uint64_t Count,
    void* Buffer,
    uint8_t  WipeExisting
);

🔗 Quick Summary
Feature Type	Struct Used	Total Size	API Function
Standard Override	RTL_STAGING_FEATURE_ENTRY	8 Bytes	  ModifyStagingControls
Variant Override	RTL_STAGING_VARIANT_ENTRY	12 Bytes	ModifyStagingControlVariants
````
---
# 🧠 WNF Feature Control – Internal API Notes

This documentation describes the low-level structures and native APIs used for managing Windows Feature Configuration through the **WNF (Windows Notification Facility)** backend.

---

#### 📋 Data Structures (C++)

These structures represent the internal layout of feature configuration entries stored inside WNF state blobs.

```cpp
// Size: 12 bytes (0x0C)
// Core runtime feature entry (matches kernel format)
typedef struct _WNF_FEATURE_ENTRY {
    uint32_t FeatureId;   // 0x00: Unique feature identifier
    uint32_t PackedBits;  // 0x04: Bitfield (states, variant, flags)
    uint32_t Payload;     // 0x08: Optional payload (threshold, config)
} WNF_FEATURE_ENTRY;

// Size: 16 bytes (0x10)
// Header describing a WNF feature update buffer
typedef struct _WNF_FEATURE_UPDATE {
    uint8_t  Version;                   // 0x00: Structure version (usually 2)
    uint8_t  VersionMinor;              // 0x01: Minor version
    uint16_t HeaderSizeBytes;           // 0x02: Size of header (typically 0x10)
    uint16_t FeatureCount;              // 0x04: Number of feature entries
    uint16_t FeatureUsageTriggerCount;  // 0x06: Variant/trigger count
    uint32_t SessionProperties;         // 0x08: Session flags
    uint32_t Properties;                // 0x0C: Global flags
} WNF_FEATURE_UPDATE;
```

---

#### 🛠 API Information (C++)

These native APIs are exposed by `ntdll.dll` and are used to interact with WNF state data.

```cpp
/**
 * @brief Queries WNF state data (feature configuration blob).
 */
NTSTATUS NtQueryWnfStateData(
    PCWNF_STATE_NAME  StateName,
    PCWNF_TYPE_ID     TypeId,
    const VOID*       ExplicitScope,
    PWNF_CHANGE_STAMP ChangeStamp,
    PVOID             Buffer,
    PULONG            BufferSize
);

/**
 * @brief Updates WNF state data (writes feature configuration).
 */
NTSTATUS NtUpdateWnfStateData(
    PCWNF_STATE_NAME  StateName,
    PVOID             Buffer,
    ULONG             Length,
    PWNF_CHANGE_STAMP ChangeStamp,
    PVOID             TypeId,
    ULONG             ExplicitScope,
    ULONG             MatchingChangeStamp
);
```

---

#### 🔍 Internal Consumers

These functions parse and resolve feature state from WNF blobs.

**EditionUpgradeManagerObj.dll**

* `wil_details_StagingConfig_Load` → Loads WNF feature data
* `wil_details_StagingConfig_QueryFeatureState` → Resolves final state
* `wil_StagingConfig_QueryFeatureState` → Public wrapper
* `wil_details_NtQueryWnfStateData` → Internal query helper

**ntoskrnl.exe**

* `NtQueryWnfStateData` → Kernel handler
* `ExpCaptureWnfStateName` → Validates WNF identifiers
* `wil_details_StagingConfig_Load` → Kernel-side parsing

---

#### 🧠 Bitfield Layout (PackedBits)

```
bits 8-9   → Service State
bits 10-11 → User State
bits 12-13 → Test State
bits 30-31 → Kind (payload type)
```

---

#### 🔗 Quick Summary

| Feature System Component | Role                          |
| ------------------------ | ----------------------------- |
| WNF                      | Feature storage backend       |
| ntdll.dll                | Read/write interface          |
| EditionUpgradeManager    | Usermode resolver             |
| ntoskrnl.exe             | Final authority (enforcement) |

---

#### ⚡ Notes

* Feature entries are stored as **12-byte records**
* Multiple states coexist → resolved by priority
* WNF acts as the **central feature data channel**
* Kernel may override or mask values at runtime

```
``` 
---

# 🧠 RTL Feature Control – Internal API Notes

---

## 📦 1. Core Structures (12-byte runtime + 32-byte update)

### _RTL_FEATURE_CONFIGURATION (12 bytes)

Source:

* ntoskrnl.exe (runtime table)
* winload.exe (registry loader)

What it does:

* Compact runtime representation (bit-packed flags + payload)

Key layout:

```
FeatureId
[bitfield @ +4]:
  - Priority (4)
  - EnabledState (2)
  - Variant (6)
  - VariantPayloadKind (2)
VariantPayload
```

---

### _RTL_FEATURE_CONFIGURATION_UPDATE (32 bytes)

Source:

* fcon.dll → StagingControls_SetFeatureEnabledState
* fcon.dll → StorageWriter::SetFeatureStates

What it does:

* Expanded "user-mode" update structure
* Later packed → 12-byte kernel struct

Key layout:

```
FeatureId
ChangeMask

EnabledState
EnabledStateOptions
Variant
VariantPayloadKind
VariantPayload

ConfigurationKind
```

---

## 🔁 2. 32 → 12 BYTE PACKER (Kernel)

### ntoskrnl.exe → RtlpFcUpdateFeature

What it does:

* Converts 32-byte update → 12-byte runtime struct
* Applies ChangeMask logic

Key logic:

```
if (ChangeMask & 1)
    EnabledState -> bits 4-5

if (ChangeMask & 2)
    Variant -> bits 8-13
    PayloadKind -> bits 14-15
    Payload -> +8
```

---

## 🔁 3. USERMODE PACKER

### fcon.dll → StagingControls_EnumerateFeatures__lambda

What it does:

* Builds compact bitfield manually (bad/“stupid” packer)

Key logic:

```
flags =
  priority
  | (enabled << 4)
  | (options << 6)
  | (variant << 8)
  | (payloadKind << 14)
```

---

## 🔓 4. USERMODE UNPACKER

### EditionUpgradeManagerObj.dll → wil_QueryFeatureState

What it does:

* Reads compact 12-byte entry → expands to readable fields

Key extraction:

```
EnabledState  = (flags >> 4) & 3
Variant       = (flags >> 8) & 0x3F
PayloadKind   = (flags >> 14)
Payload       = *(+12)
```

---

## 🔓 5. KERNEL UNPACKER

### ntoskrnl.exe → wil_details_StagingConfig_QueryFeatureState

What it does:

* Full kernel-side feature resolution
* Applies masking rules + overrides

Key behavior:

```
- Iterates feature table (12-byte entries)
- Applies policy masks
- Extracts:
  state, variant, payload, flags
```

Helper:

### wil_details_StagingConfigFeature_HasUniqueState

```
checks if feature has non-default state
```

---

## 🧾 6. REGISTRY → STRUCT LOADER

### winload.exe → FsepPopulateFeatureConfiguration

What it does:

* Converts registry values → 12-byte struct directly

Handles:

```
"EnabledState"
"EnabledStateOptions"
"Variant"
"VariantPayloadKind"
"VariantPayload"
```

Bit writes:

```
state   -> bits 4-5
options -> bit 6
variant -> bits 8-13
kind    -> bits 14-15
payload -> +8
```

---

## 💾 7. REGISTRY WRITER (USERMODE)

### fcon.dll → StorageWriter::SetFeatureStates

What it does:

* Writes feature config into registry

Writes:

```
EnabledState
EnabledStateOptions
Variant
VariantPayloadKind
VariantPayload
```

Flow:

```
CreateFeatureKey(...)
RegSetValueExW(...)
```

---

## 🧠 8. VALIDATION

### ntoskrnl.exe → RtlpFcValidateFeatureConfigurationBuffer

What it does:

* Validates array of 12-byte entries

Checks:

```
- alignment
- size = count * 0xC
- sorted order
- no invalid flags
```

---

## 📊 9. FEATURE TABLE

### KERNEL_FEATURE_TABLE

What it does:

* Holds 3 sections:

```
Boot
Runtime
Default
```

Each:

```
STAMP
HANDLE
SIZE
```

---

## 🎯 10. PRIORITY + SECTIONS

### RTL_FEATURE_CONFIGURATION_PRIORITY

What it does:

* Defines override priority

Examples:

```
User = 8
Security = 9
Dynamic = 6
ImageOverride = 0xF
```

---

### SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE

```
Boot
Runtime
UsageTriggers
```

---

## ⚠️ KEY TAKEAWAYS

* 32-byte struct = user-mode editing format
* 12-byte struct = kernel runtime format
* Packing = bitfield compression
* Registry = persistence layer
* Kernel = final authority

---

## 🔁 FULL FLOW

```
Registry <-> StorageWriter (fcon.dll)
        -> 32-byte UPDATE
        -> RtlpFcUpdateFeature (ntoskrnl.exe)
        -> 12-byte STRUCT
        -> Kernel Feature Table
        -> wil_details_StagingConfig_QueryFeatureState
```

```
```
