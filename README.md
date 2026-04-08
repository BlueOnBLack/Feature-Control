# 🛠️ Adjust-Feature: The Ultimate Windows Feature Framework
An advanced PowerShell framework for toggling hidden Windows features by interfacing with the **RTL (Runtime Library)** and **WNF (Windows Notification Facility)** subsystems. 

This tool merges the logic of **ViVeTool** and **Mach2**, providing a unified interface to manipulate the `FeatureConfiguration` state blobs and registry overrides used by `ntdll.dll`.

---

## 🏗️ Architecture Overview

The script operates across the entire Windows Feature Management stack, ensuring changes are either permanent or instantaneous.

### 1. The Fcon Layer (Registry Store)
This is the persistent configuration store. It defines the "Desired State" for features. While user-mode tools often surface this in the Software hive, the true system-level overrides reside in the System hive to be accessible during early boot.

* **Store Types:** User (HKCU) and System (HKLM).
* **Mechanism:** Writes structured feature override data. For system-wide impact, it targets:
  HKLM\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides
* **Impact:** Persistent. These entries act as the static database that the boot loader queries to determine which features should be initialized as "On" or "Off" before the OS is fully functional.

### 2. The RTL Layer (Boot Loader & Kernel Initialization)
This is the execution bridge. It translates the static Fcon Registry entries into the active Kernel memory state.

* **Store Types:** Boot Configuration and Kernel Non-Paged Pool.
* **Mechanism:** 1. Winload (winload.exe/efi) reads the Overrides from the SYSTEM registry hive during the Pre-Boot phase.
  2. It evaluates these against the hardware/policy and passes the "Enabled" list to ntoskrnl.exe.
  3. At runtime, RtlSetFeatureConfigurations can be used by system services to modify the live Kernel state or update the Registry for the next boot.
* **Impact:** This layer ensures that even BOOT_START drivers operate with the correct feature set. It is the high-priority enforcement point that bridges disk-based settings to silicon-based execution.

### 3. The WNF Layer (Live Notifications)
The "Modern" store used for A/B testing (Velocity).

* **Store Names:** User (0x418A073AA3BC88F5) and Machine (0x418A073AA3BC7C75).
* **Mechanism:** Memory-state updates via NtUpdateWnfStateData. 
* **Impact:** Triggers immediate notifications to running processes (e.g., explorer.exe) to update UI without a restart.

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

Write-Host 'RTL Runtime Store' -ForegroundColor Green -NoNewline

$Feature = 58755790
$Feature = @(57517687, 58755790, 59064570)

Set-FeatureConfiguration -Feature $feature -Action Disable -Mode Policy | Out-Null
Set-FeatureConfiguration -Feature $feature -Action Disable -Mode User   | Out-Null
Query-KernelFeatureState -Feature $feature -Store Runtime

Write-Host "RTL, Mode: Enable`n" -ForegroundColor Green

Set-FeatureConfiguration   -Feature $Feature -Action Enable -Mode User   | Out-Null
Set-FeatureConfiguration   -Feature $Feature -Action Enable -Mode Policy | Out-Null
Query-FeatureConfiguration -Feature $Feature

Write-Host "RTL, Mode: Disable`n" -ForegroundColor Green

Set-FeatureConfiguration   -Feature $Feature -Action Disable -Mode User   | Out-Null
Set-FeatureConfiguration   -Feature $Feature -Action Disable -Mode Policy | Out-Null
Query-FeatureConfiguration -Feature $Feature

Write-Host "RTL, Mode: Reset`n" -ForegroundColor Green

Set-FeatureConfiguration   -Feature $Feature -Action Reset -Mode User   | Out-Null
Set-FeatureConfiguration   -Feature $Feature -Action Reset -Mode Policy | Out-Null
Query-FeatureConfiguration -Feature $Feature

Write-Host 'WNF, Mode: Enable' -ForegroundColor Green
Write-Host

Set-WnfFeatureConfig   -Store User    -Mode Enable -Feature $Feature | Out-Null
Set-WnfFeatureConfig   -Store Machine -Mode Enable -Feature $Feature | Out-Null
Query-WnfFeatureConfig -Store User    -Feature $Feature
Query-WnfFeatureConfig -Store Machine -Feature $Feature

Write-Host "WNF, Mode: Disable`n" -ForegroundColor Green

Set-WnfFeatureConfig   -Store User    -Mode Disable -Feature $Feature | Out-Null
Set-WnfFeatureConfig   -Store Machine -Mode Disable -Feature $Feature | Out-Null
Query-WnfFeatureConfig -Store User    -Feature $Feature
Query-WnfFeatureConfig -Store Machine -Feature $Feature

Write-Host "WNF, Mode: Default`n" -ForegroundColor Green

Set-WnfFeatureConfig   -Store User    -Mode Default -Feature $Feature | Out-Null
Set-WnfFeatureConfig   -Store Machine -Mode Default -Feature $Feature | Out-Null
Query-WnfFeatureConfig -Store User    -Feature $Feature
Query-WnfFeatureConfig -Store Machine -Feature $Feature

return
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
