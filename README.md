# 🛠️ Adjust-Feature: The Ultimate Windows Feature Framework
An advanced PowerShell framework for toggling hidden Windows features by interfacing with the **RTL (Runtime Library)** and **WNF (Windows Notification Facility)** subsystems. 

This tool merges the logic of **ViVeTool** and **Mach2**, providing a unified interface to manipulate the `FeatureConfiguration` state blobs and registry overrides used by `ntdll.dll`.

---

## 🏗️ Architecture Overview

The script operates across the entire Windows Feature Management stack, ensuring changes are either permanent or instantaneous.

### 1. The RTL Layer (Registry & Policy)
This is the "Traditional" store. It uses `RtlSetFeatureConfigurations` to write to the Registry.
* **Store Types:** `User` (HKCU) and `Policy` (HKLM).
* **Mechanism:** Updates the `FeatureManagement\Overrides` keys. 
* **Impact:** Persistent across reboots. High priority.

### 2. The WNF Layer (Live Notifications)
The "Modern" store used for A/B testing (Velocity).
* **Store Names:** `User` (**0x418A073AA3BC88F5**) and `Machine` (**0x418A073AA3BC7C75**).
* **Mechanism:** Memory-state updates via `NtUpdateWnfStateData`. 
* **Impact:** Triggers **immediate** notifications to running processes (e.g., `explorer.exe`) to update UI without a restart.

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

## 🧪  Decode & Encode Feature ID

Here provides Source for Encode & Decode FeatureID in registry

Address: Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides

```
* Decode Script
* _byteswap_ulong(__ROL4__(v18 ^ 0x833EA8FF, 255) ^ 0x8FB23D4F) ^ 0x74161A4E;

// Winload.exe, IDA, Search, 833EA8FFh, OR FeatureManagement <Part Of Registry Path>
// __int64 __fastcall FsepInitializeFeatureUsageSubscriptions(__int64 a1, unsigned int a2, unsigned int **a3, __int64 *a4)
// __int64 __fastcall FsepPopulateFeatureConfigurationsForPolicyKey( int a1, unsigned int a2, __int64 *a3, __int64 a4, _DWORD *a5)
// __int64 __fastcall FsepPopulateFeatureConfigurationsForPriorityKey( __int64 a1, ULONG a2, unsigned int a3, __int64 *a4, __int64 a5, _QWORD *a6, __int64 a7, _DWORD *a8)

* Encode Script
* __ROR4__(_byteswap_ulong(v18 ^ 0x74161A4E) ^ 0x8FB23D4F, 255) ^ 0x833EA8FF);

// CmService.dll, IDA, Search, 833EA8FFh, OR FeatureManagement <Part Of Registry Path>
// __int64 __fastcall StorageWriter::CreateFeatureKey(unsigned int a1, int a2, HKEY *a3, const unsigned __int16 *a4)

// MitigationClient.dll, IDA, Search, 833EA8FFh, OR FeatureManagement <Part Of Registry Path>
// __int64 __fastcall StorageWriter::OpenFeatureKeyForRead(unsigned int a1, int a2, HKEY *a3)

// fcon.dll, IDA, Search, 833EA8FFh, OR FeatureManagement <Part Of Registry Path>
// __int64 __fastcall StorageWriter::DeletePolicyFeatureState(int a1)
// __int64 __fastcall StorageWriter::WritePolicyFeatureState(int a1, int a2)
// __int64 __fastcall StorageWriter::DeleteFeatureState(unsigned int a1, int a2)
// __int64 __fastcall StorageWriter::OpenFeatureSubscriptionsKey(int a1, HKEY *a2)
// __int64 __fastcall StorageWriter::CreateFeatureSubscriptionsKey(int a1, HKEY *a2, const unsigned __int16 *a3)
// __int64 __fastcall StorageWriter::DeleteFeatureSubscriptions(struct _RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS *a1, unsigned __int64 a2)

// C+ Demo using <_rotr, _rotl> instead of <__ROL4__, __ROR4__>
// Decode Script, _byteswap_ulong(__ROL4__(v18 ^ 0x833EA8FF, 255) ^ 0x8FB23D4F) ^ 0x74161A4E; // Winload.exe
// Encode Script, __ROR4__(_byteswap_ulong(a2 ^ 0x74161A4E) ^ 0x8FB23D4F, 255) ^ 0x833EA8FF); // CmService.dll, MitigationClient.dll, fcon.dll
uint32_t DecodedID, EncodedID; DecodedID = 58755790U; EncodedID = 2642149007U;
std::cout << ((_byteswap_ulong(_rotl(EncodedID ^ 0x833EA8FF, (255 % 32)) ^ 0x8FB23D4F) ^ 0x74161A4E)) << "   Is Match to " << DecodedID << "\n"; // Decode Value
std::cout << (_rotr(_byteswap_ulong(DecodedID ^ 0x74161A4E) ^ 0x8FB23D4F, (255 % 32)) ^ 0x833EA8FF) << " Is Match to " << EncodedID << "\n";     // Encode Value
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
