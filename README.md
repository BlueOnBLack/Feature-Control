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

### 🧠 FCON feature Api Set | Internal Feature Control API

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

### 🧠 RTL feature Api Set | Internal Feature Control API
**Struct Information**
```cpp
* RTL_FEATURE_CONFIGURATION_UPDATE - NtDoc
* https://ntdoc.m417z.com/rtl_feature_configuration_update

* _RTL_FEATURE_CONFIGURATION
* https://ntdoc.m417z.com/rtl_feature_configuration
* https://www.vergiliusproject.com/kernels/x64/windows-10/21h1/_RTL_FEATURE_CONFIGURATION

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

typedef enum _RTL_FEATURE_CONFIGURATION_PRIORITY {
    ImageDefault        = 0,
    EKB                 = 1,
    Safeguard           = 2,
    Persistent          = 2,  // same as Safeguard
    Reserved3           = 3,
    Service             = 4,
    Reserved5           = 5,
    Dynamic             = 6,
    Reserved7           = 7,
    User                = 8,
    Security            = 9,
    UserPolicy          = 0xA,
    ConfigurationSystem = 0xB,
    Test                = 0xC,
    Reserved13          = 0xD,
    Reserved14          = 0xE,
    ImageOverride       = 0xF,
    Max                 = 0xF
} RTL_FEATURE_CONFIGURATION_PRIORITY;

typedef enum _SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE {
    Boot          = 0,
    Runtime       = 1,
    UsageTriggers = 2,
    Count         = 3
} SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE;


typedef enum _RTL_FEATURE_CONFIGURATION_PRIORITY
{
} RTL_FEATURE_CONFIGURATION_PRIORITY, * PRTL_FEATURE_CONFIGURATION_PRIORITY;
typedef enum _RTL_FEATURE_ENABLED_STATE
{
} RTL_FEATURE_ENABLED_STATE;
typedef enum _RTL_FEATURE_VARIANT_PAYLOAD_KIND
{
} RTL_FEATURE_VARIANT_PAYLOAD_KIND, * PRTL_FEATURE_VARIANT_PAYLOAD_KIND;
typedef enum _RTL_FEATURE_CONFIGURATION_OPERATION
{
} RTL_FEATURE_CONFIGURATION_OPERATION, * PRTL_FEATURE_CONFIGURATION_OPERATION;

typedef struct __RTL_FEATURE_CONFIGURATION_UPDATE 
{
    /* 0x00 */ ULONG FeatureId;         // Unique ID
    /* 0x04 */ ULONG SourcePriority;    // User(1), Service(2), Image(3)
    /* 0x08 */ ULONG TargetState;       // 0:Default, 1:Off, 2:On

    /* 0x0C */ ULONG ConfigurationKind; // Known as VariantPayloadKind

    /* 0x10 */ UCHAR BaseVariant;       // The "DefaultState" / Primary 6-bit Slot
    /* 0x11 */ UCHAR Reserved[3];       // Alignment

    /* 0x14 */ union {
        ULONG RawFlags;
        struct {
            ULONG Unused          : 1;
            ULONG IsGroupBypass   : 1;  // Forces state regardless of A/B group
            ULONG Reserved        : 12;
            ULONG ExtendedVariant : 2;  // The "High Slot" (Bits 14-15)
            ULONG PendingUpgrade  : 1;  // ChangeTimeUpgrade
            ULONG Unused2         : 15;
        } Bits;
    } ControlFlags;

    /* 0x18 */ ULONG PayloadValue;      // The actual data (Threshold/Timeout)
    /* 0x1C */ ULONG UpdateAction;      // 0:Update, 1:Delete, 2:Commit
} _RTL_FEATURE_CONFIGURATION_UPDATE;

//0xc bytes (sizeof)
struct _RTL_FEATURE_CONFIGURATION
{
    ULONG FeatureId;                   //0x0
    ULONG Priority:4;                  //0x4
    ULONG EnabledState:2;              //0x4
    ULONG IsWexpConfiguration:1;       //0x4
    ULONG HasSubscriptions:1;          //0x4
    ULONG Variant:6;                   //0x4
    ULONG VariantPayloadKind:2;        //0x4
    ULONG VariantPayload;              //0x8
};

00000000 _RTL_FEATURE_CONFIGURATION struc ; (sizeof=0xC, align=0x4)
00000000 FeatureId       dd ?        ; 0x0, 4 bytes Feature identifier
00000004 Option          dw ?        ; 0x4, 2 bytes packed bitfield of options
00000006 padding         dw ?        ; 0x6, 2 bytes alignment padding
00000008 VariantPayload  dd ?        ; 0x8, 4 bytes payload value
0000000C _RTL_FEATURE_CONFIGURATION ends
```
**Struct Rules**
````cpp
// ntoskrnl.exe
// __int64 __fastcall RtlpFcValidateFeatureConfigurationBuffer(unsigned int *a1, ULONGLONG a2)

unsigned int v3; // r10d
unsigned int *v4; // r11
unsigned int v5; // r9d
unsigned int v6; // r8d
_DWORD *i; // rdx
ULONGLONG pullResult; // [rsp+30h] [rbp+8h] BYREF

pullResult = 0i64;
if ( a1 )
{
if ( a2 >= 4
    && ((unsigned __int8)a1 & 3) == 0
    && RtlULongLongMult(*a1, 0xCui64, &pullResult) >= 0
    && pullResult + 4 >= pullResult
    && pullResult + 4 <= a2 )
{
    v5 = *v4;
    v6 = v3;
    if ( !*v4 )
    return v3;
    for ( i = v4 + 1;
        (!v6 || (int)RtlFcpCompareFeatureToFeature(&v4[2 * v6 - 2 + v6], i) < 0) && (i[1] & 0x30) != 48;
        i += 3 )
    {
    if ( ++v6 >= v5 )
        return v3;
    }
}
return (unsigned int)-1073741811;
}
return a2 != 0 ? 0xC000000D : 0;
````
**32 byte Struct Info & Convertor**
````cpp
// Ntoskrnl.exe
// IDA, Local Types

00000000 _RTL_FEATURE_CONFIGURATION struc ; (sizeof=0xC, align=0x4)
00000000 FeatureId       dd ?        ; 0x0, 4 bytes Feature identifier
00000004 Option          dw ?        ; 0x4, 2 bytes packed bitfield of options
00000006 padding         dw ?        ; 0x6, 2 bytes alignment padding
00000008 VariantPayload  dd ?        ; 0x8, 4 bytes payload value
0000000C _RTL_FEATURE_CONFIGURATION ends

// construct Using fcon.dll
// __int64 __fastcall StagingControls_SetFeatureEnabledState
// // __int64 __fastcall StorageWriter::SetFeatureStates(struct _RTL_FEATURE_CONFIGURATION_UPDATE *a1, unsigned __int64 a2, const unsigned __int16 *a3)

#pragma pack(push, 1)
struct _RTL_FEATURE_CONFIGURATION_UPDATE {
    // --- Header / Metadata (Offsets 0x00 - 0x07) ---
    // StorageWriter accesses these via *((uint32_t*)i - 2) and -1
    /* 0x00 */ uint32_t FeatureId;           // The ID of the feature
    /* 0x04 */ uint32_t ChangeMask;          // Logic Bitmask (1=State, 2=Variant)

    // --- Active Data Area (Offsets 0x08 - 0x1B) ---
    // StorageWriter starts its loop pointer 'i' exactly here (+8)
    /* 0x08 */ uint32_t EnabledState;        // *i -> "EnabledState"
    /* 0x0C */ uint32_t EnabledStateOptions; // *(i + 1) -> "EnabledStateOptions"
    
    /* 0x10 */ uint8_t  Variant;             // i[8] -> "Variant"
    /* 0x11 */ uint8_t  Reserved[3];         // Padding to align next DWORD
    
    /* 0x14 */ uint32_t VariantPayloadKind;  // *(i + 3) -> "VariantPayloadKind"
    /* 0x18 */ uint32_t VariantPayload;      // *(i + 4) -> "VariantPayload"

    // --- Trailing Metadata (Offsets 0x1C - 0x1F) ---
    /* 0x1C */ uint32_t ConfigurationKind;   // The Hive (e.g., 8 for User)
}; 
// Static assert to ensure the ">> 5" (32-byte) stride logic holds true
static_assert(sizeof(_RTL_FEATURE_CONFIGURATION_UPDATE) == 32, "Struct must be exactly 32 bytes");
#pragma pack(pop)

// fcon.dll, BAse info ^ Offsets
// __int64 __fastcall StagingControls_SetFeatureEnabledState

if ( (*((_BYTE *)v7 + 32) & 1) != 0 )
{
if ( v12 == v25 )
{
    std::vector<_RTL_FEATURE_CONFIGURATION_UPDATE>::_Emplace_reallocate<_RTL_FEATURE_CONFIGURATION_UPDATE>(
    (const void **)v31,
    v25,
    v7);
    v12 = (struct _RTL_FEATURE_CONFIGURATION_UPDATE *)v32;
    v25 = v31[1];
}
else
{
    *(_OWORD *)v25 = *(_OWORD *)v7;
    *((_OWORD *)v25 + 1) = *((_OWORD *)v7 + 1);
    v25 = (struct _RTL_FEATURE_CONFIGURATION_UPDATE *)((char *)v25 + 32);
    v31[1] = v25;
}
}
v7 = (struct RtlFeatureUpdate *)((char *)v7 + 40);
--v6;
}
while ( v6 );
v18 = v31[0];
}
v26 = RtlSetFeatureConfigurations(a5, 1i64, v18, (v25 - v18) >> 5);

// fcon.dll, BAse info ^ Offsets
// __int64 __fastcall StorageWriter::SetFeatureStates(struct _RTL_FEATURE_CONFIGURATION_UPDATE *a1, unsigned __int64 a2, const unsigned __int16 *a3)

__int64 __fastcall StorageWriter::SetFeatureStates(
        struct _RTL_FEATURE_CONFIGURATION_UPDATE *a1,
        unsigned __int64 a2,
        const unsigned __int16 *a3)
{
  __int64 v3; // rsi
  char *i; // rdi
  __int64 v7; // rdx
  __int64 v8; // rcx
  int v9; // eax
  signed int v10; // ebx
  LSTATUS v11; // eax
  LSTATUS v12; // eax
  LSTATUS v13; // eax
  LSTATUS v14; // eax
  LSTATUS v15; // eax
  unsigned __int64 v17; // r9
  __int64 v18; // rdx
  int lpData; // [rsp+20h] [rbp-10h]
  wil::details::in1diag3 *retaddr; // [rsp+68h] [rbp+38h]
  int Data; // [rsp+78h] [rbp+48h] BYREF
  HKEY hKey; // [rsp+88h] [rbp+58h] BYREF

  v3 = 0i64;
  if ( !a2 )
    return 0i64;
  for ( i = (char *)a1 + 8; ; i += 32 )
  {
    v7 = *((unsigned int *)i - 2);
    v8 = *((unsigned int *)i - 1);
    hKey = 0i64;
    v9 = StorageWriter::CreateFeatureKey(v8, v7, &hKey, a3);
    v10 = v9;
    if ( v9 < 0 )
      break;
    Data = *(_DWORD *)i;
    v11 = RegSetValueExW(hKey, L"EnabledState", 0, 4u, (const BYTE *)&Data, 4u);
    v10 = (unsigned __int16)v11 | 0x80070000;
    if ( v11 <= 0 )
      v10 = v11;
    if ( v10 < 0 )
    {
      v17 = (unsigned int)v10;
      v18 = 473i64;
      goto LABEL_29;
    }
    Data = *((_DWORD *)i + 1);
    v12 = RegSetValueExW(hKey, L"EnabledStateOptions", 0, 4u, (const BYTE *)&Data, 4u);
    v10 = (unsigned __int16)v12 | 0x80070000;
    if ( v12 <= 0 )
      v10 = v12;
    if ( v10 < 0 )
    {
      v17 = (unsigned int)v10;
      v18 = 474i64;
      goto LABEL_29;
    }
    Data = (unsigned __int8)i[8];
    v13 = RegSetValueExW(hKey, L"Variant", 0, 4u, (const BYTE *)&Data, 4u);
    v10 = (unsigned __int16)v13 | 0x80070000;
    if ( v13 <= 0 )
      v10 = v13;
    if ( v10 < 0 )
    {
      v17 = (unsigned int)v10;
      v18 = 475i64;
      goto LABEL_29;
    }
    Data = *((_DWORD *)i + 3);
    v14 = RegSetValueExW(hKey, L"VariantPayloadKind", 0, 4u, (const BYTE *)&Data, 4u);
    v10 = (unsigned __int16)v14 | 0x80070000;
    if ( v14 <= 0 )
      v10 = v14;
    if ( v10 < 0 )
    {
      v17 = (unsigned int)v10;
      v18 = 476i64;
      goto LABEL_29;
    }
    Data = *((_DWORD *)i + 4);
    v15 = RegSetValueExW(hKey, L"VariantPayload", 0, 4u, (const BYTE *)&Data, 4u);
    v10 = (unsigned __int16)v15 | 0x80070000;
    if ( v15 <= 0 )
      v10 = v15;
    if ( v10 < 0 )
    {
      v17 = (unsigned int)v10;
      v18 = 477i64;
      goto LABEL_29;
    }
    if ( hKey )
      RegCloseKey(hKey);
    if ( ++v3 >= a2 )
      return 0i64;
  }
  v17 = (unsigned int)v9;
  v18 = 471i64;
LABEL_29:
  wil::details::in1diag3::Return_Hr(
    retaddr,
    (void *)v18,
    (unsigned int)"onecore\\base\\flighting\\featuremanagement\\libs\\featurestatewriter\\storagewriter.cpp",
    (const char *)v17,
    lpData);
  if ( hKey )
    RegCloseKey(hKey);
  return (unsigned int)v10;
}

// ntoskrnl.exe, Packer<>Unpacker 32<>12
// __int64 __fastcall RtlpFcUpdateFeature(__int64 a1, __int64 a2)

{
    int v2; // eax
    int v5; // ecx
    int v6; // edx
    __int64 result; // rax

    v2 = *(_DWORD *)(a2 + 28);
    if ( (v2 & 1) != 0 )
    {
    *(_DWORD *)(a1 + 4) ^= (*(_DWORD *)(a1 + 4) ^ (16 * *(_DWORD *)(a2 + 8))) & 0x30;
    v2 = *(_DWORD *)(a2 + 28);
    }
    if ( (v2 & 2) != 0 )
    {
    *(_DWORD *)(a1 + 4) ^= (*(_DWORD *)(a1 + 4) ^ (*(unsigned __int8 *)(a2 + 16) << 8)) & 0x3F00;
    v5 = *(_DWORD *)(a1 + 4);
    *(_DWORD *)(a1 + 8) = *(_DWORD *)(a2 + 24);
    v6 = v5 ^ ((unsigned __int16)v5 ^ (unsigned __int16)((unsigned __int16)*(_DWORD *)(a2 + 20) << 14)) & 0xC000;
    *(_DWORD *)(a1 + 4) = v6;
    }
    else
    {
    v6 = *(_DWORD *)(a1 + 4);
    }
    result = v6 ^ ((unsigned __int8)v6 ^ (unsigned __int8)((unsigned __int8)*(_DWORD *)(a2 + 12) << 6)) & 0x40u;
    *(_DWORD *)(a1 + 4) = result;
    return result;
}

// Winload.exe, Registry to 12 Bytes Struct [Skip 32 translate]
// __int64 __fastcall FsepPopulateFeatureConfiguration(__int64 a1, __int64 *a2, __int64 a3, __int64 a4)

{
  int v7; // ebp
  int v8; // r14d
  int i; // edx
  __int64 v10; // rcx
  bool v11; // zf
  unsigned int v12; // ebx
  int v13; // ebx
  __int64 result; // rax
  UNICODE_STRING String2; // [rsp+30h] [rbp-28h] BYREF

  v7 = a1;
  if ( a1 && a2 && *a2 && a4 )
  {
    v8 = 0;
    for ( i = 0; ; i = v8 )
    {
      result = FsepEnumerateValueKey(a1, i, a3, (_DWORD)a2, a3);
      if ( (_DWORD)result == -2147483622 )
        return 0i64;
      if ( (int)result < 0 )
        return result;
      v10 = *a2;
      *(_DWORD *)(&String2.MaximumLength + 1) = 0;
      v11 = *(_DWORD *)(v10 + 4) == 4;
      String2.Buffer = (wchar_t *)(v10 + 20);
      String2.Length = *(_WORD *)(v10 + 16);
      String2.MaximumLength = String2.Length;
      if ( v11 && *(_DWORD *)(v10 + 12) == 4 )
      {
        v12 = *(_DWORD *)(*(unsigned int *)(v10 + 8) + v10);
        if ( RtlEqualUnicodeString(&EnabledStateValueName, &String2, 1u) )
        {
          if ( v12 > 2 )
            goto LABEL_24;
          v13 = (*(_DWORD *)(a4 + 4) ^ (16 * v12)) & 0x30;
          goto LABEL_12;
        }
        if ( RtlEqualUnicodeString(&IsEnabledStateOptionsValueName, &String2, 1u) )
        {
          if ( v12 <= 1 )
          {
            v13 = (*(_DWORD *)(a4 + 4) ^ (v12 << 6)) & 0x40;
LABEL_12:
            *(_DWORD *)(a4 + 4) ^= v13;
          }
        }
        else if ( RtlEqualUnicodeString(&VariantValueName, &String2, 1u) )
        {
          if ( v12 < 0x40 )
          {
            v13 = (*(_DWORD *)(a4 + 4) ^ (v12 << 8)) & 0x3F00;
            goto LABEL_12;
          }
        }
        else if ( RtlEqualUnicodeString(&VariantPayloadKindValueName, &String2, 1u) )
        {
          if ( v12 < 4 )
          {
            v13 = (*(_DWORD *)(a4 + 4) ^ (v12 << 14)) & 0xC000;
            goto LABEL_12;
          }
        }
        else if ( RtlEqualUnicodeString(&VariantPayloadValueName, &String2, 1u) )
        {
          *(_DWORD *)(a4 + 8) = v12;
        }
      }
LABEL_24:
      ++v8;
      LODWORD(a1) = v7;
    }
  }
  return 3221225485i64;
}
````

**Base Packer <> Unpacker**
````cpp
// fcon.dll ==> [Stupid Packer]
// __int64 __fastcall StagingControls_EnumerateFeatures__lambda_025e1f4f593c8987aee57b4ee711a6c5____(_BYTE ***a1)

LODWORD(v28) = *(v8 - 1);
v15 = v8[5];
HIDWORD(v28) = v12 & 0xF | (16 * (v8[1] & 3 | (4 * (v8[2] & 1 | (4 * (((v8[4] & 3) << 6) | v8[3] & 0x3F))))));

// EditionUpgradeManagerObj.dll --> [Stupid Unpacker]
// __int64 __fastcall wil_QueryFeatureState(__int64 a1, unsigned int a2, int a3, int a4, _DWORD *a5, _DWORD *a6)

{
    ....
    v14 = HIDWORD(v18); // Compact 32-bit 'Flags' from the 12-byte runtime entry
    v10 = 1;
    v15 = HIDWORD(v18);

    // Writes to Offset 0x0C (12) of the local result buffer
    // Matches the 32-bit payload data
    *(_DWORD *)(a1 + 12) = v19;                         // Source: Offset 0x18 at RTL_FEATURE_CONFIGURATION_UPDATE

    // Writes to Offset 0x08 (8) of the local result buffer
    // Extracts Payload Kind (Resident/External) from top bits
    *(_DWORD *)(a1 + 8) = (unsigned __int16)v15 >> 14;  // Source: Offset 0x0C (Bits 14-15) at RTL_FEATURE_CONFIGURATION_UPDATE

    // Writes to Offset 0x00 (0) of the local result buffer
    // ENABLED STATE: Extracted via right-shift 4, mask 3
    *(_DWORD *)a1 = (v15 >> 4) & 3;                     // Source: Offset 0x08 at RTL_FEATURE_CONFIGURATION_UPDATE

    // Writes to Offset 0x04 (4) of the local result buffer
    // VARIANT: Extracted from second byte, mask 0x3F
    *(_BYTE *)(a1 + 4) = BYTE1(v14) & 0x3F;             // Source: Offset 0x10 at RTL_FEATURE_CONFIGURATION_UPDATE

    // Writes to Offset 0x10 (16) of the local result buffer
    // Subscription check bit
    *(_DWORD *)(a1 + 16) = (v14 >> 7) & 1;              // Source: Offset 0x0C (Bit 7) at RTL_FEATURE_CONFIGURATION_UPDATE

    // Writes to Offset 0x14 (20) of the local result buffer
    // WEXP (Windows Experience) check bit
    *(_DWORD *)(a1 + 20) = (v14 >> 6) & 1;              // Source: Offset 0x0C (Bit 6) at RTL_FEATURE_CONFIGURATION_UPDATE
````

**Kernel Unpacker**
````cpp
/// ntoskrnl.exe --> [Kernel Unpacker]
// __int64 __fastcall wil_details_StagingConfig_QueryFeatureState(__int64 a1, __int64 a2, int a3, int a4)

{
  __int64 v4; // r12
  int v5; // r10d
  __int64 v6; // r11
  int v7; // ebx
  __int64 v9; // rdi
  unsigned int v10; // r9d
  int v12; // r14d
  unsigned int i; // esi
  unsigned int v14; // r9d
  unsigned int v15; // ecx
  _DWORD *v16; // rax
  __int64 result; // rax
  __int64 v18; // rax
  int v19; // eax
  __int64 v20; // r8
  int v21; // eax
  __int64 v22; // xmm0_8
  unsigned int v23; // r8d
  int v24; // eax
  int v25; // r8d
  __int64 v26; // [rsp+20h] [rbp-10h] BYREF
  int v27; // [rsp+28h] [rbp-8h]
  int v28; // [rsp+70h] [rbp+40h]

  v28 = a3;
  v4 = *(_QWORD *)(a1 + 24);
  v5 = 0;
  v6 = *(_QWORD *)(a1 + 32);
  v7 = 0;
  v26 = 0i64;
  v9 = a2;
  v27 = 0;
  v10 = *(unsigned __int16 *)(v4 + 4);
  v12 = 0;
  for ( i = 0; i < v10; ++i )
  {
    a2 = i;
    if ( *(_DWORD *)(v6 + 12i64 * i) == a3 )
    {
      if ( a4 && *(_DWORD *)(a1 + 48) )
      {
        if ( (*(_DWORD *)(v6 + 12i64 * i + 4) & 1) == 0 )
        {
          v7 = *(_DWORD *)(v6 + 12i64 * i + 8);
          v26 = *(_QWORD *)(v6 + 12i64 * i);
          v27 = v7;
          goto LABEL_10;
        }
      }
      else
      {
        v21 = *(_DWORD *)(v6 + 12i64 * i + 4);
        v12 = 1;
        v22 = *(_QWORD *)(v6 + 12i64 * i);
        v7 = *(_DWORD *)(v6 + 12i64 * i + 8);
        v27 = v7;
        v26 = v22;
        if ( (v21 & 1) != 0 )
          break;
      }
    }
  }
  v14 = 0;
  if ( v12 )
  {
LABEL_10:
    if ( !a4 || (v18 = 12i64, !*(_DWORD *)(a1 + 48)) )
      v18 = 8i64;
    v19 = *(_DWORD *)(v18 + v4);
    if ( (v19 & 4) != 0 )
    {
      v20 = HIDWORD(v26) & 0xFFFFCFFF;
      HIDWORD(v26) &= 0xFFFFCFFF;
    }
    else
    {
      v20 = HIDWORD(v26);
    }
    if ( (v19 & 2) != 0 )
    {
      v20 = (unsigned int)v20 & 0xFFFFF3FF;
      HIDWORD(v26) = v20;
    }
    if ( (v19 & 1) != 0 )
    {
      v20 = (unsigned int)v20 & 0xFFFFFCFF;
      HIDWORD(v26) = v20;
    }
    if ( (v19 & 8) != 0 )
    {
      v20 = (unsigned int)v20 & 0xC0FFFFFF;
      v7 = 0;
      HIDWORD(v26) = v20;
      v27 = 0;
    }
    if ( (unsigned int)((__int64 (__fastcall *)(__int64 *, __int64, __int64, _QWORD))wil_details_StagingConfigFeature_HasUniqueState)(
                         &v26,
                         a2,
                         v20,
                         0i64) )
    {
      *(_DWORD *)(v9 + 12) = v7;
      *(_DWORD *)(v9 + 8) = v23 >> 30;
      *(_BYTE *)(v9 + 4) = HIBYTE(v23) & 0x3F;
      *(_DWORD *)(v9 + 20) = (v23 >> 1) & 1;
      v24 = (v23 >> 12) & 3;
      if ( v24 || (v24 = (v23 >> 10) & 3) != 0 )
      {
        *(_DWORD *)v9 = v24;
      }
      else
      {
        v25 = (v23 >> 8) & 3;
        if ( v25 )
          *(_DWORD *)v9 = v25;
      }
      v14 = 1;
    }
    a3 = v28;
  }
  v15 = v5;
  v16 = *(_DWORD **)(a1 + 40);
  if ( *(_WORD *)(v4 + 6) )
  {
    while ( *v16 != a3 )
    {
      ++v15;
      v16 += 4;
      if ( v15 >= *(unsigned __int16 *)(v4 + 6) )
        goto LABEL_4;
    }
    v5 = 1;
  }
LABEL_4:
  result = v14;
  *(_DWORD *)(v9 + 16) = v5;
  return result;
}
_BOOL8 __fastcall wil_details_StagingConfigFeature_HasUniqueState(_DWORD *a1)
{
  unsigned int v1; // edx
  _BOOL8 result; // rax

  result = 0;
  if ( *a1 )
  {
    v1 = a1[1];
    if ( ((v1 | ((v1 | (v1 >> 2)) >> 2)) & 0x300) != 0 || (v1 & 0x3F000000) != 0 || (v1 & 2) != 0 )
      return 1;
  }
  return result;
}
````
