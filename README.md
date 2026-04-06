# Adjust-Feature PowerShell Script  
This script provides a PowerShell function, `Adjust-Feature`, to enable, disable, or reset hidden Windows features using undocumented Native API calls — similar to tools like ViVeTool and Mach2.  


Based on the ViVeTool source code and borrowing some libraries from the System Informer project (see Git page).



**Support Both WNF & RTL Libaries, Also Supprt RTL Kernel Libary TableLookUP**

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
Clear-Host
Write-Host

Write-Host 'RTL Runtime Store' -ForegroundColor Green -NoNewline

$Feature = 58755790
$Feature = @(57517687, 58755790, 59064570)

Set-FeatureConfiguration -Feature $feature -Action Disable -Mode Policy | Out-Null
Set-FeatureConfiguration -Feature $feature -Action Disable -Mode User   | Out-Null
Query-KernelFeatureState -Feature $feature -Store Runtime

Write-Host "RTL, Mode: Enable`n" -ForegroundColor Green

Set-FeatureConfiguration -Feature $Feature -Action Enable -Mode User   | Out-Null
Set-FeatureConfiguration -Feature $Feature -Action Enable -Mode Policy | Out-Null
Query-FeatureConfiguration -Feature  $Feature

Write-Host "RTL, Mode: Disable`n" -ForegroundColor Green

Set-FeatureConfiguration -Feature $Feature -Action Disable -Mode User   | Out-Null
Set-FeatureConfiguration -Feature $Feature -Action Disable -Mode Policy | Out-Null
Query-FeatureConfiguration -Feature  $Feature

Write-Host "RTL, Mode: Reset`n" -ForegroundColor Green

Set-FeatureConfiguration -Feature $Feature -Action Reset -Mode User   | Out-Null
Set-FeatureConfiguration -Feature $Feature -Action Reset -Mode Policy | Out-Null
Query-FeatureConfiguration -Feature  $Feature

Write-Host 'WNF, Mode: Enable' -ForegroundColor Green
Write-Host

Set-WnfFeatureConfig -Store User    -Mode Enable -Feature $Feature | Out-Null
Set-WnfFeatureConfig -Store Machine -Mode Enable -Feature $Feature | Out-Null
Query-WnfFeatureConfig -Store User    -Feature $Feature
Query-WnfFeatureConfig -Store Machine -Feature $Feature

Write-Host "WNF, Mode: Disable`n" -ForegroundColor Green

Set-WnfFeatureConfig -Store User    -Mode Disable -Feature $Feature | Out-Null
Set-WnfFeatureConfig -Store Machine -Mode Disable -Feature $Feature | Out-Null
Query-WnfFeatureConfig -Store User    -Feature $Feature
Query-WnfFeatureConfig -Store Machine -Feature $Feature

Write-Host "WNF, Mode: Default`n" -ForegroundColor Green

Set-WnfFeatureConfig -Store User    -Mode Default -Feature $Feature | Out-Null
Set-WnfFeatureConfig -Store Machine -Mode Default -Feature $Feature | Out-Null
Query-WnfFeatureConfig -Store User    -Feature $Feature
Query-WnfFeatureConfig -Store Machine -Feature $Feature

return
```

## 📝 Technical Notes

The script implements two main actions:

1. **API Call:** It calls the native function (via PInvoke) that internally points to `RtlSetFeatureConfigurations` using the `NtSetSystemInformation` syscall (SystemInformationClass 210). This immediately updates the runtime feature state and schedules a boot-time update if necessary.

2. **Registry Overrides:** It sets feature overrides in the registry paths:

   * **User/Default:** `HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\08\<ObfuscatedId>`

   * **Global/Priority 10:** `HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides`

These registry keys ensure that the feature state remains constant even after future system updates or policy checks.
