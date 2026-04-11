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

## 🚀 All Possibilities: Usage Guide

### 📂 Discovery & Deep Scanning
```powershell
# DUMP ALL: List every feature currently active in the WNF User store
Query-WnfFeatureConfig -Store User -OutList

# TARGETED QUERY: Check the specific state of a feature ID in the WNF Machine store
Query-WnfFeatureConfig -Store Machine -Feature 58755790
```

### ⚡ Live Hot-Swapping (WNF)
```powershell
# Enable a feature for the current session ONLY via WNF
Set-WnfFeatureConfig -Store User -Mode Enable -Feature 58755790

# Reset WNF state to system defaults (clearing memory blobs)
Set-WnfFeatureConfig -Store Machine -Mode Default -Feature 58755790
```

### 🔒 Permanent Overrides (RTL)
```powershell
# Set a system-wide policy override (Disables the feature for all users)
Set-FeatureConfiguration -Feature 58755790 -Action Disable -Mode Policy
```

---

## 🧬 Technical Implementation Details

### State Priority Logic
The script resolves the "Effective State" within the WNF blob following the OS priority ladder:
1. **TestState:** (Highest) Used by Microsoft for internal testing.
2. **UserState:** User-specific overrides.
3. **ServiceState:** (Lowest) The default state shipped with the OS build.

### WNF Bitfield Alignment
The script performs manual bit-shifting for the `WNF_FEATURE_ENTRY` structure:
* **ServiceState:** Bits 8–9
* **UserState:** Bits 10–11
* **TestState:** Bits 12–13
* **Kind:** Bits 30–31
  
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

### 💻 C++ Implementation Example
This demo uses standard intrinsic-style rotations (`_rotl`, `_rotr`).

```cpp
#include <iostream>
#include <intrin.h>
#include <windows.h>
#include <vector>

struct TestCase {
    uint32_t decoded;
    uint32_t encoded;
};

int main()
{
    std::vector<TestCase> tests = {
        { 57517687U, 4011992206U },
        { 58992578U, 2216818319U },
        { 58755790U, 2642149007U },
        { 59064570U, 4109366415U }
    };
    std::cout << "Starting validation for " << tests.size() << " cases...\n";
    std::cout << "--------------------------------------------------\n";
    for (const auto& test : tests) {
        uint32_t resultDecoded = _byteswap_ulong(_rotl(test.encoded ^ 0x833EA8FF, (255 % 32)) ^ 0x8FB23D4F) ^ 0x74161A4E;
        uint32_t resultEncoded = _rotr(_byteswap_ulong(test.decoded ^ 0x74161A4E) ^ 0x8FB23D4F, (255 % 32)) ^ 0x833EA8FF;

        std::cout << "Test Decoded " << test.decoded << ": "
            << (resultDecoded == test.decoded ? "  [PASS]" : "  [FAIL]") << "\n";
        std::cout << "Test Encoded " << test.encoded << ": "
            << (resultEncoded == test.encoded ? "[PASS]" : "[FAIL]") << "\n";
        std::cout << "--------------------------------------------------\n";
    }

    return 0;
}
```
---

## 🧪  Demonstration Script

The following demo showcases the full lifecycle of feature manipulation across both RTL and WNF stacks.

```powershell
Clear-Host
Write-Host

# Feature List
$Variant    = 1,1,2
$Feature    = 57517687, 58755790, 59064570
$UserPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\8"
$PolicyPath = 'HKLM:SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides'

Set-FeatureConfiguration   -Feature $Feature -Action Reset -Mode User   | Out-Null
Set-FeatureConfiguration   -Feature $Feature -Action Reset -Mode Policy | Out-Null

#Write-Host "FCON, Mode: Enabled, Variants`n" -ForegroundColor Green
#Modify-StagingControls        -Feature $Feature -State Default                   | Out-Null
#Modify-StagingControls        -Feature $Feature -State Enabled                   | Out-Null
#Modify-StagingControlVariants -Feature $Feature -State Enabled -Variant $Variant | Out-Null
#Get-ChildItem $UserPath -ea 0 | % { Get-ItemProperty $_.PSPath } | Select-Object PSChildName, EnabledState, EnabledStateOptions, Variant, VariantPayload, VariantPayloadKind | Format-Table

Write-Host "RTL, User/Kernel Mode: Enable & Set Variant" -ForegroundColor Green
Set-FeatureConfiguration -Feature $Feature -Variant $Variant -Action Disable -Mode User   -Store Runtime | Out-Null
Set-FeatureConfiguration -Feature $Feature -Variant $Variant -Action Disable -Mode Policy -Store Runtime | Out-Null
Get-ChildItem $UserPath -ea 0 | % { Get-ItemProperty $_.PSPath } | Select-Object PSChildName, EnabledState, EnabledStateOptions, Variant, VariantPayload, VariantPayloadKind | Format-Table

Write-Host "Query, Mode: User" -ForegroundColor Magenta
Query-FeatureConfiguration -Feature $Feature             | Select FeatureId, Priority, EnabledState, Variant, VariantPayloadKind, IsWexpConfiguration, HasSubscriptions | Format-Table
Write-Host "Query, Mode: Kernel" -ForegroundColor Magenta
Query-KernelFeatureState   -Feature $Feature -ApplyFlags | Select FeatureId, Priority, EnabledState, Variant, VariantPayloadKind, IsWexpConfiguration, HasSubscriptions | Format-Table

# Write-Host "WNF, Mode: Enable`n" -ForegroundColor Green
# Set-WnfFeatureConfig   -Store User    -Mode Enable -Feature $Feature | Out-Null
# Set-WnfFeatureConfig   -Store Machine -Mode Enable -Feature $Feature | Out-Null
# Query-WnfFeatureConfig -Store User    -Feature $Feature
# Query-WnfFeatureConfig -Store Machine -Feature $Feature
```

---

## 📝 Capability Matrix

| Feature | RTL Engine | WNF Engine |
| :--- | :---: | :---: |
| **Persistence** | Permanent (Registry) | Volatile (Memory) |
| **Instant UI Update** | No | **Yes** |
| **A/B Test Override** | High | Medium |
| **Requires Reboot** | Sometimes | **Never** |

---

## ⚠️ Safety & Compatibility
* **Requirements:** Windows 10 Build 18963+ or Windows 11.
* **Privileges:** **Administrator Privileges Required** for both Registry (HKLM) and WNF Machine store access.
```
