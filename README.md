# Windows Notification Facility (WNF) & Feature Configuration (Velocity)

This documentation and script set provides a low-level interface for interacting with the Windows Notification Facility (WNF). It is specifically designed to manage Feature Configurations (the "Velocity" A/B testing and feature flagging system) used in Windows 10 and Windows 11.

---

## **Technical Context**

### **Background**
Starting with Build 18963, Windows introduced centralized exports in ntdll.dll for feature work. Previously, developers had to manually interact with WNF state data blobs to configure features.

* **Fcon**: Feature Configuration library (System32).
* **WNF**: Windows Notification Facility (Kernel-mode pub/sub).
* **RTL**: Run-Time Library functions inside ntdll.

### **WNF State Stores**
The system uses specific 64-bit State Names to store feature overrides:

* **Machine Store**: 0x418A073AA3BC7C75L
* **User Store**: 0x418A073AA3BC88F5L

---

## **PowerShell Implementation**

#region "Feature, WNF"
function Init-WNF {
    if (-not ([PSTypeName]'WNF_FEATURE_ENTRY').Type) {
        New-Struct -Module (New-InMemoryModule -ModuleName WNF_FEATURE_ENTRY) -FullName WNF_FEATURE_ENTRY -StructFields @{
            FeatureId = New-field 0 UInt32
            PackedBits = New-field 1 UInt32
            Payload = New-field 2 UInt32
        } | Out-Null
    }
    $functions = @(
        @{ Name="NtQueryWnfStateData"; Dll="ntdll.dll"; ReturnType=[Int32]; Parameters=[Type[]]@([UInt64].MakeByRefType(), [Int64], [Int64], [UInt32].MakeByRefType(), [IntPtr], [UInt32].MakeByRefType()) },
        @{ Name="NtUpdateWnfStateData"; Dll="ntdll.dll"; ReturnType=[Int32]; Parameters=[Type[]]@([UInt64].MakeByRefType(), [IntPtr], [UInt32], [UInt32].MakeByRefType(), [UInt64], [UInt32], [UInt32]) }
    )
    $Global:wnf = Register-NativeMethods $functions
}
#endregion

---

## **Usage**

### **1. Check Feature Status**
**To see if a specific feature has an override in the Machine store:**
Query-WnfFeatureConfig -Store "Machine" -Feature 12345678

**To list all current overrides in the User store:**
Query-WnfFeatureConfig -Store "User" -OutList

### **2. Set Feature Overrides**
**To force-enable or force-disable a feature:**

**Enable a feature**
Set-WnfFeatureConfig -Store "Machine" -Mode "Enable" -Feature 12345678

**Disable a feature**
Set-WnfFeatureConfig -Store "User" -Mode "Disable" -Feature 12345678

**Reset to default**
Set-WnfFeatureConfig -Store "Machine" -Mode "Default" -Feature 12345678

---

## **References**
* **Mach2 GitHub (Rafael Rivera)**
* **Visiting Vibranium Velocity (Medium)**
