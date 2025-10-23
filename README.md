# Adjust-Feature PowerShell Script
This script provides a single PowerShell function, `Adjust-Feature`, to enable, disable, or reset hidden Windows features using undocumented Native API calls (similar to tools like ViVeTool and Mach2).
Based on ViveTool Source code. Also Borrow some libraries from system informer Project
## ⚠️ Warning and Disclaimer

This script uses **undocumented Windows Native APIs** (`NtSetSystemInformation`, `RtlSetFeatureConfigurations`, etc.) and directly manipulates the operating system's internal feature management configuration, including registry overrides.

* **Use at your own risk.** Altering features may lead to system instability, crashes, or unexpected behavior.

* **Always back up your system** before making significant changes.

* The logic and offsets are based on reverse-engineered information and **may break in future Windows updates.**

## 🌟 Features

* **Feature Control:** Enable, Disable, or Reset (return to default) specific feature IDs.

* **Persistent Configuration:** Applies necessary registry overrides to ensure changes persist across reboots.

* **Boot Status Management:** Updates the system boot status to ensure pending feature changes are applied.

* **Dynamic PInvoke:** Uses reflection and dynamic PInvoke to call necessary functions from `ntdll.dll` without requiring external DLLs.

## 🛠️ Prerequisites

* **Operating System:** Windows 10 or Windows 11.

* **PowerShell:** Windows PowerShell or PowerShell Core.

* **Permissions:** The script **must be run with Administrator privileges.**

## 🚀 Usage

### 1. Load the Function

First, save the script content as a `.ps1` file (e.g., `FeatureManager.ps1`) and load it into your PowerShell session:

```powershell
# Run PowerShell as Administrator
. .\FeatureManager.ps1
```

### 2. Function Syntax

The function requires at least two mandatory parameters: the Feature ID(s) and the desired state.

```powershell
Adjust-Feature
    -FeatureIds <UInt32[]>   # One or more Windows Feature IDs (e.g., 48796508)
    -State <String>          # Must be "Enable", "Disable", or "Reset"
    [-Global]                # Optional: Apply feature configuration globally (Higher priority, typically system-wide)
```

### 3. Examples

**Example 1: Enable a Feature**

```powershell
Adjust-Feature -FeatureIds @(48796508) -State Enable
```

**Example 2: Disable Multiple Features**

```powershell
Adjust-Feature -FeatureIds @(12345678, 87654321) -State Disable
```

**Example 3: Reset a Feature to Default**

```powershell
Adjust-Feature -FeatureIds @(48796508) -State Reset
```

**Example 4: Enable Globally (Higher Priority)**

```powershell
Adjust-Feature -FeatureIds @(48796508) -State Enable -Global
```

## 📝 Technical Notes

The script implements two main actions:

1. **API Call:** It calls the native function (via PInvoke) that internally points to `RtlSetFeatureConfigurations` using the `NtSetSystemInformation` syscall (SystemInformationClass 210). This immediately updates the runtime feature state and schedules a boot-time update if necessary.

2. **Registry Overrides:** It sets feature overrides in the registry paths:

   * **User/Default:** `HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\08\<ObfuscatedId>`

   * **Global/Priority 10:** `HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides`

These registry keys ensure that the feature state remains constant even after future system updates or policy checks.
