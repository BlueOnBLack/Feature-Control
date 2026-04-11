using namespace System
using namespace System.IO
using namespace System.Reflection
using namespace System.Reflection.Emit
using namespace System.Security.Principal
using namespace System.Collections.Generic
using namespace System.Management.Automation
using namespace System.Runtime.InteropServices

#region "Misc"
Function Bor {
    param ([int[]] $Array) 
    $ret = $Array[0]
    foreach ($item in $Array) {
        $ret = $ret -bor $item
    }
    return [Int32]$ret
}
function New-field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}
function New-Struct {
    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = bor @(0,1,256,1048576)
    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}
function New-InMemoryModule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}
#endregion

# Fcon = Feature Configuration library (lives in System32) // Registry Part, On first Boot, using Winload.exe
# WNF  = Windows Notification Facility                     // LiveOS, Hot-Swap, temporary until next reboot
# RTL  = Run-Time Library functions inside ntdll           // Kernel Map Layer, lower level as possible

#region "Feature, Fcon"
Function Init-FCON {

    try {
        $Module = [AppDomain]::CurrentDomain.GetAssemblies()| ? { $_.ManifestModule.ScopeName -eq "FCON" } | select -Last 1
        $Global:FCON = $Module.GetTypes()[0]
    }
    catch {
        $Module = [AppDomain]::CurrentDomain.DefineDynamicAssembly("null", 1).DefineDynamicModule("FCON", $False).DefineType("null")
        @(
            @('null', 'null', [int], @()), # place holder
            @("ModifyStagingControls",        "fcon.dll", [Int32], @([byte], [Int64], [IntPtr], [byte])),
            @("ModifyStagingControlVariants", "fcon.dll", [Int32], @([byte], [Int64], [IntPtr], [byte]))
        ) | % {
            $Module.DefinePInvokeMethod(($_[0]), ($_[1]), 22, 1, [Type]($_[2]), [Type[]]($_[3]), 1, 3).SetImplementationFlags(128) # Def` 128, fail-safe 0
        }
        $Global:FCON = $Module.CreateType()
    }

    # Define an header for RTL_STAGING_FEATURE_ENTRY
    if (-not ([PSTypeName]'RTL_STAGING_FEATURE_ENTRY').Type) {
        New-Struct `
            -Module (New-InMemoryModule -ModuleName RTL_STAGING_FEATURE_ENTRY) `
            -FullName RTL_STAGING_FEATURE_ENTRY `
            -StructFields @{
                FeatureId = New-field 0 UInt32 # 0x00: The ID (e.g., 1234567)
                State     = New-field 1 Byte   # 0x04: 0=Default, 1=Disabled, 2=Enabled
                Padding1  = New-field 2 Byte   # 0x05: Aligns to 8 bytes total
                Padding2  = New-field 3 Byte   # 0x05: Aligns to 8 bytes total
                Padding3  = New-field 4 Byte   # 0x05: Aligns to 8 bytes total
            } | Out-Null
    }

    # Define an header for RTL_STAGING_VARIANT_ENTRY
    if (-not ([PSTypeName]'RTL_STAGING_VARIANT_ENTRY').Type) {
        New-Struct `
            -Module (New-InMemoryModule -ModuleName RTL_STAGING_VARIANT_ENTRY) `
            -FullName RTL_STAGING_VARIANT_ENTRY `
            -StructFields @{
                FeatureId = New-field 0 UInt32  # 0x00
                State     = New-field 1 Byte    # 0x04
                Variant   = New-field 2 Byte    # 0x05
                Reserved2 = New-field 3 Byte    # 0x06 - 0x0B (6 bytes)
                Reserved3 = New-field 4 Byte    # 0x06 - 0x0B (6 bytes)
                Reserved4 = New-field 5 Byte    # 0x06 - 0x0B (6 bytes)
                Reserved5 = New-field 6 Byte    # 0x06 - 0x0B (6 bytes)
                Reserved6 = New-field 7 Byte    # 0x06 - 0x0B (6 bytes)
                Reserved7 = New-field 8 Byte    # 0x06 - 0x0B (6 bytes)
            } | Out-Null
    }

}
function Modify-StagingControls {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [UInt32[]]$Feature,

        [ValidateSet("Default", "Disabled", "Enabled")]
        [string]$State = "Enabled",

        [ValidateSet("Service", "User", "Test")]
        [string]$Kind = "User",

        [switch]$WipeExisting
    )
    
    if (!$Global:FCON) {
        Init-FCON
    }

    # RTL_FEATURE_CONFIGURATION_PRIORITY
    $KindMap = @{ 
        "Service"  = 1  ; # 0x4
        "User"     = 2  ; # 0x8
        "Test"     = 3 ;  # 0x0C
    }

    # RTL_FEATURE_ENABLED_STATE
    $StateMap = @{
        "Default"  = 0;
        "Disabled" = 1;
        "Enabled"  = 2 
    }

    $Count  = $Feature.Count
    $Handle = [Marshal]::AllocHGlobal(0x0C * $Count)
    $Priority = [byte]$KindMap[$Kind]
    $WipeFlag = [Byte]($(if ($WipeExisting.IsPresent) { 1 } else { 0 }))

    try {
        for ($i = 0; $i -lt $Count; $i++) {
            $Entry           = [Activator]::CreateInstance([Type]'RTL_STAGING_FEATURE_ENTRY')
            $Entry.FeatureId = $Feature[$i]
            $Entry.State     = [byte]($StateMap[$State])
            $OffsetPtr       = [intptr]::Add($Handle, ($i * 0x0C))
            [Marshal]::StructureToPtr($Entry, $OffsetPtr, $false)
        }

        $hr = $Global:FCON::ModifyStagingControls(
            $Priority, $Count, $Handle, $WipeFlag)

        return $hr
    }
    catch {
        Write-Error "Staging modification failed: $($_.Exception.Message)"
    }
    finally {
        [Marshal]::FreeHGlobal($Handle)
    }
}
function Modify-StagingControlVariants {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [UInt32[]]$Feature,

        [ValidateSet("Default", "Disabled", "Enabled")]
        [string]$State = "Enabled",

        [ValidateSet("Service", "User", "Test")]
        [string]$Kind = "User",

        [Byte[]]$Variant,

        [switch]$WipeExisting
    )
    
    if (!$Global:FCON) {
        Init-FCON
    }

    # RTL_FEATURE_CONFIGURATION_PRIORITY
    $KindMap = @{ 
        "Service"  = 1  ; # 0x4
        "User"     = 2  ; # 0x8
        "Test"     = 3 ;  # 0x0C
    }

    # RTL_FEATURE_ENABLED_STATE
    $StateMap = @{
        "Default"  = 0;
        "Disabled" = 1;
        "Enabled"  = 2 
    }

    $Count  = $Feature.Count
    $Handle = [Marshal]::AllocHGlobal(0x0c * $Count)
    $Priority = [byte]$KindMap[$Kind]
    $WipeFlag = [Byte]($(if ($WipeExisting.IsPresent) { 1 } else { 0 }))

    try {
        for ($i = 0; $i -lt $Count; $i++) {
            $Entry           = [Activator]::CreateInstance([Type]'RTL_STAGING_VARIANT_ENTRY')
            $Entry.FeatureId = $Feature[$i]
            $Entry.State     = [byte]$StateMap[$State]
            $Entry.Variant   = if ($Variant.Count -gt $i) { $Variant[$i] } else { 0x00 }
            $OffsetPtr       = [intptr]::Add($Handle, ($i * 0x0C))
            [Marshal]::StructureToPtr($Entry, $OffsetPtr, $false)
        }

        return $Global:FCON::ModifyStagingControlVariants(
            $Priority, $Count, $Handle, $WipeFlag)
    }
    catch {
        Write-Error "Variant modification failed: $($_.Exception.Message)"
    }
    finally {
        [Marshal]::FreeHGlobal($Handle)
    }
}
#endregion
#region "Feature, RTL"

<#
Based on ViveTool Source code.
namespace --> Albacore.ViVeTool

@ ViVe \ ViVeTool GUI
@ https://github.com/thebookisclosed/ViVe
@ https://github.com/PeterStrick/ViVeTool-GUI

@ phnt Headers [private]
@ https://github.com/winsiderss/systeminformer
@ https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h

@ Consumer_ESU_Enrollment.ps1
@ https://github.com/abbodi1406/ConsumerESU/blob/master/Consumer_ESU_Enrollment.ps1

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

</
$Path = "C:\Windows\System32"
$Extensions = @("*.exe", "*.dll", "*.sys")
$Files = Get-ChildItem -Path $Path -File -ErrorAction SilentlyContinue | 
         Where-Object { $_.Extension -match '\.(exe|dll|sys)$' } | select FullName

$Files | % {
    $Name = $_.FullName
    $Data = Get-Strings -Path $Name -MinimumLength 15 | ? { $_ -match 'FeatureManagement' } 
    if ($Data) {
      write-host $Name -ForegroundColor Green
      $Data        
    }
}
/>

* Decode Script
* _byteswap_ulong(__ROL4__(v18 ^ 0x833EA8FF, 255) ^ 0x8FB23D4F) ^ 0x74161A4E;

// fcon.dll, IDA, Search, 833EA8FFh, OR FeatureManagement <Part Of Registry Path> <StorageWriter::??>
// __int64 __fastcall StorageWriter::GetAllFeatureProperties(__int64 a1, unsigned int a2)
// __int64 __fastcall StorageWriter::ReadFeaturesForPriority(__int64 a1, unsigned int a2, const unsigned __int16 *a3)

// Winload.exe, IDA, Search, 833EA8FFh, OR FeatureManagement <Part Of Registry Path>
// __int64 __fastcall FsepInitializeFeatureUsageSubscriptions(__int64 a1, unsigned int a2, unsigned int **a3, __int64 *a4)
// __int64 __fastcall FsepPopulateFeatureConfigurationsForPolicyKey( int a1, unsigned int a2, __int64 *a3, __int64 a4, _DWORD *a5)
// __int64 __fastcall FsepPopulateFeatureConfigurationsForPriorityKey( __int64 a1, ULONG a2, unsigned int a3, __int64 *a4, __int64 a5, _QWORD *a6, __int64 a7, _DWORD *a8)

* Encode Script
* __ROR4__(_byteswap_ulong(v18 ^ 0x74161A4E) ^ 0x8FB23D4F, 255) ^ 0x833EA8FF);

// fcon.dll, IDA, Search, 833EA8FFh, OR FeatureManagement <Part Of Registry Path> <StorageWriter::??>
// __int64 __fastcall StorageWriter::DeletePolicyFeatureState(int a1)
// __int64 __fastcall StorageWriter::WritePolicyFeatureState(int a1, int a2)
// __int64 __fastcall StorageWriter::DeleteFeatureState(unsigned int a1, int a2)
// __int64 __fastcall StorageWriter::OpenFeatureSubscriptionsKey(int a1, HKEY *a2)
// __int64 __fastcall StorageWriter::OpenSubscriptionsKeyForRead(int a1, HKEY *a2, const unsigned __int16 *a3)
// __int64 __fastcall StorageWriter::CreateFeatureSubscriptionsKey(int a1, HKEY *a2, const unsigned __int16 *a3)
// __int64 __fastcall StorageWriter::CreateFeatureKey(unsigned int a1, int a2, HKEY *a3, const unsigned __int16 *a4)
// __int64 __fastcall StorageWriter::OpenFeatureKeyForRead(unsigned int a1, int a2, HKEY *a3, const unsigned __int16 *a4)
// __int64 __fastcall StorageWriter::DeleteFeatureSubscriptions(struct _RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS *a1, unsigned __int64 a2)

// CmService.dll, IDA, Search, 833EA8FFh, OR FeatureManagement <Part Of Registry Path>
// __int64 __fastcall StorageWriter::CreateFeatureKey(unsigned int a1, int a2, HKEY *a3, const unsigned __int16 *a4)

// MitigationClient.dll, IDA, Search, 833EA8FFh, OR FeatureManagement <Part Of Registry Path>
// __int64 __fastcall StorageWriter::OpenFeatureKeyForRead(unsigned int a1, int a2, HKEY *a3)

// C+ Demo using <_rotr, _rotl> instead of <__ROL4__, __ROR4__>
// Decode Script, _byteswap_ulong(__ROL4__(v18 ^ 0x833EA8FF, 255) ^ 0x8FB23D4F) ^ 0x74161A4E; // Winload.exe
// Encode Script, __ROR4__(_byteswap_ulong(a2 ^ 0x74161A4E) ^ 0x8FB23D4F, 255) ^ 0x833EA8FF); // CmService.dll, MitigationClient.dll, fcon.dll
uint32_t DecodedID, EncodedID; DecodedID = 58755790U; EncodedID = 2642149007U;
std::cout << ((_byteswap_ulong(_rotl(EncodedID ^ 0x833EA8FF, (255 % 32)) ^ 0x8FB23D4F) ^ 0x74161A4E)) << "   Is Match to " << DecodedID << "\n"; // Decode Value
std::cout << (_rotr(_byteswap_ulong(DecodedID ^ 0x74161A4E) ^ 0x8FB23D4F, (255 % 32)) ^ 0x833EA8FF) << " Is Match to " << EncodedID << "\n";     // Encode Value

// Vive Code. Decode & Encode.
namespace Albacore.ViVe
{
    public static class ObfuscationHelpers
    {
        private static uint SwapBytes(uint x)
        {
            x = (x >> 16) | (x << 16);
            return ((x & 0xFF00FF00) >> 8) | ((x & 0x00FF00FF) << 8);
        }
        private static uint RotateRight32(uint value, int shift)
        {
            return (value >> shift) | (value << (32 - shift));
        }
        public static uint ObfuscateFeatureId(uint featureId)
        {
            return RotateRight32(SwapBytes(featureId ^ 0x74161A4E) ^ 0x8FB23D4F, -1) ^ 0x833EA8FF;
        }
        public static uint DeobfuscateFeatureId(uint featureId)
        {
            return SwapBytes(RotateRight32(featureId ^ 0x833EA8FF, 1) ^ 0x8FB23D4F) ^ 0x74161A4E;
        }
    }
}

+-+-+-+-+-+-+-+-
! OR ps1 demo. !
+-+-+-+-+-+-+-+-

Clear-Host
Write-Host

# Constants found in winload.exe / Fsep functions
$MAGIC_1 = 0x833EA8FF
$MAGIC_2 = 0x8FB23D4F
$MAGIC_3 = 0x74161A4E

function Invoke-BitOp {
    param (
        [uint32]$Value,
        [Parameter(Mandatory=$true)][ValidateSet("RotateLeft", "RotateRight", "SwapBytes")][string]$Operation,
        [int]$Shift = 0
    )
    switch ($Operation) {
        "RotateLeft"  { $s = $Shift % 32; return [uint32](($Value -shl $s) -bor ($Value -shr (32 - $s))) }
        "RotateRight" { $s = $Shift % 32; return [uint32](($Value -shr $s) -bor ($Value -shl (32 - $s))) }
        "SwapBytes"   { 
            $bytes = [BitConverter]::GetBytes($Value)
            [Array]::Reverse($bytes)
            return [BitConverter]::ToUInt32($bytes, 0)
        }
    }
}

# Values to verify
[uint32]$DecodedID = 58755790
[uint32]$EncodedID = 2642149007

# 1. DEOBFUSCATE (Encoded -> Decoded)
$d = $EncodedID -bxor $MAGIC_1
$d = Invoke-BitOp $d -Operation RotateLeft -Shift 255
$d = $d -bxor $MAGIC_2
$d = Invoke-BitOp $d -Operation SwapBytes
$FinalDecoded = $d -bxor $MAGIC_3

# 2. OBFUSCATE (Decoded -> Encoded)
$e = $DecodedID -bxor $MAGIC_3
$e = Invoke-BitOp $e -Operation SwapBytes
$e = $e -bxor $MAGIC_2
$e = Invoke-BitOp $e -Operation RotateRight -Shift 255
$FinalEncoded = $e -bxor $MAGIC_1

# Results Output
Write-Host "--- Feature ID Translation ---" -ForegroundColor Cyan
[String]::Format("Decoded: {0}   (Expected: {1})   - Match: {2}", $FinalDecoded, $DecodedID, ($FinalDecoded -eq $DecodedID))
[String]::Format("Encoded: {0} (Expected: {1}) - Match: {2}", $FinalEncoded, $EncodedID, ($FinalEncoded -eq $EncodedID))
Write-Host

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

(Query-KernelFeatureState -Store Runtime).Count -eq (Query-FeatureConfiguration -OutList -Store Runtime).Count == MATCH
(Query-KernelFeatureState -Store Boot).Count    -eq (Query-FeatureConfiguration -OutList -Store Boot).Count    == MATCH

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

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* RTL_FEATURE_CONFIGURATION_UPDATE - NtDoc
* https://ntdoc.m417z.com/rtl_feature_configuration_update

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

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
* _RTL_FEATURE_CONFIGURATION
* https://ntdoc.m417z.com/rtl_feature_configuration
* https://www.vergiliusproject.com/kernels/x64/windows-10/21h1/_RTL_FEATURE_CONFIGURATION

-- Same version, just compact one, 
-- instead of 32 bytes, just 12 bytes

[DllImport("ntdll.dll")]
public static extern int RtlQueryFeatureConfiguration(
    uint featureId,
    RTL_FEATURE_CONFIGURATION_TYPE featureConfigurationType,
    ref ulong changeStamp,
    out RTL_FEATURE_CONFIGURATION featureConfiguration
);

//0xc bytes (sizeof)
struct _RTL_FEATURE_CONFIGURATION
{
    ULONG FeatureId;                   //0x0
    ULONG Priority:4;                  //0x4
    ULONG EnabledState:2;              //0x4
    ULONG IsWexpConfiguration:1;       //0x4
    ULONG HasSubscriptions:1;          //0x4
    ULONG Variant:6;                   //0x4, Value Come from EnabledStateOptions
    ULONG VariantPayloadKind:2;        //0x4
    ULONG VariantPayload;              //0x8
};

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

### User Mode (Ring 3) Implementation

**1. Kernel-Mode (Ring 0) - The Compact Truth**
* **Format:** 12-byte `RTL_FEATURE_CONFIGURATION` structure.
* **Goal:** Memory conservation. Because the Kernel must track thousands of features in the System Paged Pool, it uses bitfields to keep the footprint small.
* **Storage:** The Enable State is not a standalone field; it is "hidden" inside a 32-bit Flags DWORD using specific bit-offsets.
* **Access:** Requires bitwise masks (&) and XOR operations to update without disturbing neighboring bits.

**2. User-Mode (Ring 3) - The Expanded Truth**
* **Format:** 32-byte `WIL_FEATURE_STATE` or `RTL_FEATURE_CONFIGURATION_UPDATE` structure.
* **Goal:** Developer efficiency and execution speed.
* **Storage:** The Enable State is expanded into a full 32-bit DWORD. In an update descriptor, this is at **Offset 0x08**. In a query result, it is moved to **Offset 0x00**.
* **Access:** Can be read directly by code (e.g., if (state == 2)) without any complex bit-shifting logic required by the caller.

### Summary of Offset Mapping

| Logic Role       | 32-Byte Staging Offset (Packer) | Kernel Bit-Slot (Storage) | 32-Byte Result Offset (Unpacker) |
| :--------------  | :----------------------------- | :------------------------ | :-------------------------------  |
| **Enable State** | **0x08** | Bits 4-5            | 0x00                      |                                   |
| **Variant ID**   | **0x10** | Bits 8-13           | 0x04                      |                                   |
| **Payload Kind** | 0x0C (High Bits)               | Bits 14-15                | 0x08                              |
| **Payload Value**| 0x18                           | Direct Offset 0x08        | 0x0C                              |

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

// RTL_FEATURE_CONFIGURATION

typedef struct _RTL_FEATURE_CONFIGURATION_UPDATE
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

// Ntoskrnl.exe
// IDA, Local Types

00000000 _RTL_FEATURE_CONFIGURATION struc ; (sizeof=0xC, align=0x4)
00000000 FeatureId       dd ?        ; 0x0, 4 bytes Feature identifier
00000004 Option          dw ?        ; 0x4, 2 bytes packed bitfield of options
00000006 padding         dw ?        ; 0x6, 2 bytes alignment padding
00000008 VariantPayload  dd ?        ; 0x8, 4 bytes payload value
0000000C _RTL_FEATURE_CONFIGURATION ends

// fcon.dll ,, BAse info ^ Offsets
// __int64 __fastcall StorageWriter::SetFeatureStates(struct _RTL_FEATURE_CONFIGURATION_UPDATE *a1, unsigned __int64 a2, const unsigned __int16 *a3)

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

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

// fcon.dll ==> [Packer]
// __int64 __fastcall StagingControls_EnumerateFeatures__lambda_025e1f4f593c8987aee57b4ee711a6c5____(_BYTE ***a1)

LODWORD(v28) = *(v8 - 1);
v15 = v8[5];
HIDWORD(v28) = v12 & 0xF | (16 * (v8[1] & 3 | (4 * (v8[2] & 1 | (4 * (((v8[4] & 3) << 6) | v8[3] & 0x3F))))));

// EditionUpgradeManagerObj.dll --> [Unpacker]
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
}

// ntoskrnl.exe --> [Unpacker]
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

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* _RTL_FEATURE_ENABLED_STATE_OPTIONS
* https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_RTL_FEATURE_ENABLED_STATE_OPTIONS

//0x4 bytes (sizeof)
enum _RTL_FEATURE_ENABLED_STATE_OPTIONS
{
    FeatureEnabledStateOptionsNone = 0,
    FeatureEnabledStateOptionsWexpConfig = 1
};
#>

Function Init-RTL {
    
    # Define the KERNEL FEATURE TABLE struct
    if (-not ([PSTypeName]'KERNEL_FEATURE_TABLE').Type) {
        New-Struct `
            -Module (New-InMemoryModule -ModuleName KERNEL_FEATURE_TABLE) `
            -FullName KERNEL_FEATURE_TABLE `
            -StructFields @{
                # --- Global Header ---
                ChangeStamp    = New-field 0  UInt64     # 0x00: Global Sequence

                # --- Boot Store Block (Offset 0x08 - 0x1F) ---
                Boot_Stamp     = New-field 1  UInt64     # 0x08:
                Boot_Handle    = New-field 2  UInt64     # 0x10:
                Boot_Size      = New-field 3  UInt64     # 0x18:

                # --- Runtime Store Block (Offset 0x20 - 0x37) ---
                Runtime_Stamp    = New-field 4  UInt64   # 0x20:
                Runtime_Handle   = New-field 5  UInt64   # 0x28:
                Runtime_Size     = New-field 6  UInt64   # 0x30:

                # --- Empty Store / Sentinel Block (Offset 0x38 - 0x4F) ---
                Default_Stamp    = New-field 7  UInt64   # 0x38:
                Default_Handle   = New-field 8  UInt64   # 0x40:
                Default_Size     = New-field 9  UInt64   # 0x48:
            } | Out-Null
    }

    # Define the RTL feature update Header struct
    if (-not ([PSTypeName]'RTL_FEATURE_CONFIGURATION_HEADER').Type) {
        New-Struct `
            -Module (New-InMemoryModule -ModuleName RTL_FEATURE_CONFIGURATION_HEADER) `
            -FullName RTL_FEATURE_CONFIGURATION_HEADER `
            -StructFields @{
                PreviousStamp     = New-field 0 UInt64  # 0x00
                ConfigurationType = New-field 1 Int32   # 0x08 Boot=0, Runtime=1
                FeatureCount      = New-field 2 Int32   # 0x0C Number of features
            } | Out-Null
    }

    # Define the RTL feature update Header struct
    if (-not ([PSTypeName]'RTL_FEATURE_CONFIGURATION_HEADER_EXT').Type) {
        New-Struct `
            -Module (New-InMemoryModule -ModuleName RTL_FEATURE_CONFIGURATION_HEADER_EXT) `
            -FullName RTL_FEATURE_CONFIGURATION_HEADER_EXT `
            -StructFields @{
                Reserved          = New-field 0 UInt64  # 0x00
                PreviousStamp     = New-field 1 UInt64  # 0x08
                ConfigurationType = New-field 2 Int32   # 0x0C Boot=0, Runtime=1
                FeatureCount      = New-field 3 Int32   # 0x14 Number of features
            } | Out-Null
    }

    # Define the RTL feature update struct (32-byte version)
    if (-not ([PSTypeName]'RTL_FEATURE_CONFIGURATION_UPDATE').Type) {
        New-Struct `
            -Module (New-InMemoryModule -ModuleName RTL_FEATURE_CONFIGURATION_UPDATE) `
            -FullName RTL_FEATURE_CONFIGURATION_UPDATE `
            -StructFields @{
                FeatureId           = New-field 0   UInt32   # 0x00
                Priority            = New-field 1   Int32    # 0x04
                LegacyState         = New-field 2   Int32    # 0x08
                PackedOptions       = New-field 3   Int32    # 0x0C (Controls Bit 6/7 in compact struct)
                ModernBucketState   = New-field 4   Byte     # 0x10
                Reserved1           = New-field 5   Byte     # 0x10
                Reserved2           = New-field 6   Byte     # 0x10
                Reserved3           = New-field 7   Byte     # 0x10
                VariantPayloadKind  = New-field 8   UInt32   # 0x14 (Source for Bits 14-15)
                VariantPayload      = New-field 9   UInt32   # 0x18
                Operation           = New-field 10   Int32   # 0x1C (Bitmask for the update action)
            } | Out-Null
    }

    # Define a simple struct for holding parsed RTL feature data.
    # This struct is used only for storing feature entries in an array/list.
    # Each instance represents one feature with its states, text description, and payload
    if (-not ([PSTypeName]'RTL_FEATURE_INFO').Type) {
        New-Struct `
            -Module (New-InMemoryModule -ModuleName RTL_FEATURE_INFO) `
            -FullName RTL_FEATURE_INFO `
            -StructFields @{
                FeatureId           = New-field 0  UInt32
                FlagsRaw            = New-field 1  String
                Priority            = New-field 2  UInt32
                EnabledState        = New-field 3  String
                EnabledStateRaw     = New-field 4  String
                IsWexpConfiguration = New-field 5  UInt32
                HasSubscriptions    = New-field 6  UInt32
                Variant             = New-field 7  UInt32  
                VariantPayloadKind  = New-field 8  UInt32
                VariantPayload      = New-field 9  String
                Reserved            = New-field 10 UInt32
                EnabledStateOptions = New-field 11 UInt32
            } | Out-Null
    }

    # Define a simple struct for holding parsed KERNEL RTL feature data.
    # This struct is used only for storing feature entries in an array/list.
    # Each instance represents one feature with its states, text description, and payload
    if (-not ([PSTypeName]'RTL_KERNEL_FEATURE_INFO').Type) {
    New-Struct `
        -Module (New-InMemoryModule -ModuleName RTL_KERNEL_FEATURE_INFO) `
        -FullName RTL_KERNEL_FEATURE_INFO `
        -StructFields @{
            FeatureId           = New-field 0  UInt32
            HasUniqueState      = New-field 1  Boolean
            EnabledState        = New-field 2  String
            EnabledStateRaw     = New-field 3  UInt32
            Variant             = New-field 4  UInt32
            VariantPayloadKind  = New-field 5  UInt32
            VariantPayload      = New-field 6  String
            HasSubscriptions    = New-field 7  UInt32
            Priority            = New-field 8  UInt32
            State_Service       = New-field 9  UInt32
            State_Override      = New-field 10 UInt32
            State_Default       = New-field 11 UInt32
            FlagsRaw            = New-field 12 String
            FlagsEffective      = New-field 13 String
            MaskApplied         = New-field 14 UInt32
            IsWexpConfiguration = New-field 15 UInt32
        } | Out-Null
}

    try {
        $Module = [AppDomain]::CurrentDomain.GetAssemblies()| ? { $_.ManifestModule.ScopeName -eq "RTL" } | select -Last 1
        $Global:RTL = $Module.GetTypes()[0]
    }
    catch {
        $Module = [AppDomain]::CurrentDomain.DefineDynamicAssembly("null", 1).DefineDynamicModule("RTL", $False).DefineType("null")
        @(
            @('null', 'null', [int], @()), # place holder
            @('NtSetSystemInformation',       'ntdll.dll', [Int32], @([Int32], [IntPtr], [Int32])),
            @('RtlGetSystemBootStatus',       'ntdll.dll', [Int32], @([Int], [Int32].MakeByRefType(), [Int], [IntPtr])),
            @('RtlSetSystemBootStatus',       'ntdll.dll', [Int32], @([Int], [Int32].MakeByRefType(), [Int], [IntPtr])),
            @('RtlSetFeatureConfigurations',  'ntdll.dll', [Int32], @([Int].MakeByRefType(), [Int32], [IntPtr], [Int])),
            @('RtlCreateBootStatusDataFile',  'ntdll.dll', [Int32], @([IntPtr])),
            @('RtlQueryFeatureConfiguration', 'ntdll.dll', [Int32], @([UInt32], [UInt32], [UInt64].MakeByRefType(), [IntPtr])),
            @('NtQuerySystemInformationEx',   'ntdll.dll', [Int32], @([Int32], [IntPtr], [Int32], [IntPtr], [Int32], [IntPtr])),
            @('ZwMapViewOfSection',           'ntdll.dll', [Int32], @([IntPtr], [IntPtr], [IntPtr].MakeByRefType(), [UIntPtr], [UIntPtr], [Int64].MakeByRefType(), [IntPtr].MakeByRefType(), [Int32], [Int32], [Int32])),
            @('ZwUnmapViewOfSection',         'ntdll.dll', [Int32], @([IntPtr], [IntPtr])),
            @('RtlPublishWnfStateData',       'ntdll.dll', [Int32], @([UInt64], [Int64], [Int64], [Int64])),
            @('NtClose',                      'ntdll.dll', [Int32], @([IntPtr])),
            @('RtlQueryFeatureConfigurationChangeStamp', 'ntdll.dll', [Int32], @()),
            @('RtlQueryAllFeatureConfigurations', 'ntdll.dll', [Int32], @([Int32], [UInt64].MakeByRefType(), [IntPtr], [Int32].MakeByRefType()))

        ) | % {
            $Module.DefinePInvokeMethod(($_[0]), ($_[1]), 22, 1, [Type]($_[2]), [Type[]]($_[3]), 1, 3).SetImplementationFlags(128) # Def` 128, fail-safe 0
        }
        $Global:RTL = $Module.CreateType()
    }
}
function Write-FeatureData {
    param(
        [int]$Index,
        [int]$BaseOffset,
        [IntPtr]$UpdatePackage,
        [int]$FeatureId = 0x0,

        [ValidateSet(1,2,3,4,5,6,8,9,10,11,12,13,14)]
        [int]$Priority = 0x0,

        [ValidateSet(0,1,2)]
        [int]$EnabledState = 0x0,

        [ValidateSet(0,1,2)]
        [int]$EnabledStateOptions = 0x0,

        [ValidateSet(0,1)]
        [int]$PackedOptions = 0x0,

        [ValidateSet(0,1,2)]
        [int]$Variant = 0x0,

        [ValidateSet(0,1)]
        [int]$IsWexpConfiguration = 0x0,

        [ValidateSet(0,1)]
        [int]$IsSubscribed = 0x0,

        [ValidateSet(0,1,2,3)]
        [int]$VariantPayloadKind = 0x0,

        [ValidateSet(1,2,3,4)]
        [int]$Operation = 0x0,

        [int]$VariantPayload = 0x0
    )

    <#
        Rules Section
        RtlpFcValidateFeatureConfigurationBuffer

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
    #>

    $data = New-Object byte[] 32

    if ($Variant -gt 0x00) {
        $VariantPayloadKind = 1
    }

    [Buffer]::BlockCopy([BitConverter]::GetBytes($FeatureId), 0, $data, 0, 4)              # 0x00
    [Buffer]::BlockCopy([BitConverter]::GetBytes($Priority), 0, $data, 4, 4)               # 0x04
    [Buffer]::BlockCopy([BitConverter]::GetBytes($PackedOptions), 0, $data, 12, 4)         # 0x0C
    [Buffer]::BlockCopy([BitConverter]::GetBytes($VariantPayloadKind), 0, $data, 20, 4)    # 0x14
    [Buffer]::BlockCopy([BitConverter]::GetBytes($VariantPayload), 0, $data, 24, 4)        # 0x18
    [Buffer]::BlockCopy([BitConverter]::GetBytes($Operation), 0, $data, 28, 4)             # 0x1C
    
    # Legacy Slot (0x08)
    # Provides raw state for older tools that check this specific offset.
    $data[8]  = [byte]$EnabledState

    # Windows Experience Configuration Slot
    $data[12] = $IsWexpConfiguration

    # Modern Hybrid Byte (0x10)
    # The Hybrid Byte (Offset 0x10) - ONLY for State/Variant
    # We keep this CLEAN (Bits 0-5 only) to avoid the & 0x3F00 mask error
    $data[16] = [byte](
        (($EnabledState -band 0x03) -shl 4) -bor ($Variant -band 0x0F)
    )

    $ptr = [IntPtr]::Add($UpdatePackage, ($BaseOffset + (0x20 * $Index)))
    [Marshal]::Copy($data, 0, $ptr, 32)
}
function Obfuscate-FeatureId {
    param($featureId)
    # __ROR4__(_byteswap_ulong(v18 ^ 0x74161A4E) ^ 0x8FB23D4F, 255) ^ 0x833EA8FF) // Source, Winload.exe
    $x = [uint32]$featureId -bxor 0x74161A4E
    $x = [uint32]((($x -band 0xFF) -shl 24) -bor (($x -band 0xFF00) -shl 8) -bor (($x -band 0xFF0000) -shr 8) -bor ($x -shr 24))
    $x = $x -bxor 0x8FB23D4F
    $x = [uint32]( (($x -shl 1) -band 0xFFFFFFFF) -bor ($x -shr 31) )
    return $x -bxor 0x833EA8FF
}
function Set-FeatureConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uint32[]]$Feature,

        [Parameter(Mandatory = $false)]
        [uint32[]]$Variant,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Enable","Disable", "Reset")]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("User", "Policy")]
        [string]$Mode,

        [ValidateSet("Boot", "Runtime")]
        [String]$Store = "Runtime",

        [Switch]$KernelMode,
        [Switch]$SysCall,
        [Switch]$Log
    )

    if (!$Global:RTL) {
        Init-RTL
    }

    $results = $False
    $type = if ($Store -eq "Boot") { 0x00 } else { 0x01 }
    $Priority = if ($Mode -eq "Policy") {  0x0a } else { 0x08 }
    $OperationType = if ($Action -match "Enable|Disable") { 0x01 -bor 0x02 } else { 0x04 }
    $EnabledState = if ($Action -eq 'Enable') { 0x02 } elseif ($Action -eq 'Disable') { 0x01 } else { 0x00 }
    if (!([WindowsIdentity]::GetCurrent().Groups.Value -contains "S-1-5-32-544")) {
        Write-Error "User doesn't belong to Administrator's group"
        return
    }

    $idx = -1
    $VariantKind  = 0x0
    $variantValue = 0x0

    try {

        $header = if (([Environment]::OSVersion.Version.Build) -ge 22000) {
            [Activator]::CreateInstance([Type]'RTL_FEATURE_CONFIGURATION_HEADER_EXT')
        } else {
            [Activator]::CreateInstance([Type]'RTL_FEATURE_CONFIGURATION_HEADER')
        }

        $Count = $Feature.Count
        $BaseSize = [Marshal]::SizeOf($header)
        $PayloadSize = ((0x20 * $Count)+ 7) -band -bnot 7
        $updatePackage = [marshal]::AllocHGlobal($BaseSize + $PayloadSize)
        (0..((($BaseSize + $PayloadSize)/0x08)-1)) | % {
            [Marshal]::WriteInt64($updatePackage, ($_*0x08), 0L)
        }
        $PreviousStamp = [marshal]::ReadInt64([IntPtr]::Add(0x7FFE0000, 0x0710))
        $header.PreviousStamp = $PreviousStamp
        $header.ConfigurationType = $type
        $header.FeatureCount = $Count
        [Marshal]::StructureToPtr($header, $updatePackage, $false)

        $idx = -1;
        foreach ($f in $Feature) {
            ++$idx
            if ($Action -eq "Reset") {
                $FeatureObj = $null
                $FeatureObj = Query-FeatureConfiguration -Feature $f
                if($FeatureObj) {
                    $Priority = $FeatureObj.Priority
                }
            }
            if ($FeatureObj) {

                Write-FeatureData `
                    -Index ($idx) `
                    -BaseOffset $BaseSize `
                    -UpdatePackage $updatePackage `
                    -FeatureId $FeatureObj.FeatureId `
                    -Priority $FeatureObj.Priority `
                    -EnabledState $FeatureObj.EnabledStateRaw `
                    -Variant  $FeatureObj.Variant`
                    -VariantPayloadKind $FeatureObj.VariantPayloadKind `
                    -VariantPayload $FeatureObj.VariantPayload `
                    -Operation $OperationType `
                    -IsWexpConfiguration $FeatureObj.IsWexpConfiguration

            } else {
                $variantValue = 0x0
                if ($Variant -and $Variant.Count -gt $idx) {
                    $variantValue = $Variant[$idx]
                }
                Write-FeatureData `
                    -Index ($idx) `
                    -BaseOffset $BaseSize `
                    -UpdatePackage $updatePackage `
                    -FeatureId $f `
                    -Priority $Priority `
                    -EnabledState $EnabledState `
                    -Operation $OperationType `
                    -Variant $variantValue `
                    -Mode $CrossMode
            }
        }

        if ($SysCall) {

            # ntoskrnl.exe, CmUpdateFeatureConfiguration
            # ntoskrnl.exe, CmFcManagerUpdateFeatureConfigurations
            # ntoskrnl.exe, RtlpFcUpdateFeatureConfiguration
            # ntoskrnl.exe, RtlpFcApplyUpdateAndAddFeature
            # ntoskrnl.exe, RtlpFcCreateAndAddFeatureFromUpdate
            # ntoskrnl.exe, RtlpFcUpdateFeature >>> !

            $ret = $RTL::NtSetSystemInformation(
              [Int64]210,
              $updatePackage,
              ($BaseSize + $PayloadSize))

        } else {

            $ret = $RTL::RtlSetFeatureConfigurations(
              ([ref]$PreviousStamp), $type,
              ([IntPtr]::Add($updatePackage, $BaseSize)),
              $Count 
            )
        }
        #>

        if ($ret -ge 0) {
            
            $results = $true
            if ($ret -gt 0) {
              Write-Warning "NtSetSystemInformation Call End with {$ret}"
            }
            
            <#
            Not fail According RtlSetFeatureConfigurations Logic
            v7 = ZwSetSystemInformation(210i64, v11, (unsigned int)(v8 + 16));
            if ( v7 >= 0 )
              v7 = 0;
            #>

        } else {
            Write-warning "Failed calling NtSetSystemInformation: Code {$ret}"
            return $False
        }
    }
    catch {
        Write-warning "Failed calling NtSetSystemInformation: Code {$_}"
    }
    finally {
        [marshal]::FreeHGlobal($updatePackage)
    }

    try {
        $idx = -1
        foreach ($f in $Feature) {
            ++$idx
            if ($Variant -and $Variant.Count -ge 0) {

                # Start with the 'Windows Promotion' defaults
                # If we are enabling, Windows wants 2 and 1.
                $variantValue = 0x02
                $vPayloadKind = 0x01
    
                if ($Variant.Count -gt $idx) {
                    $variantValue = $Variant[$idx]
        
                    # If user explicitly wants 0, we drop the payload kind
                    if ($variantValue -eq 0) {
                        $vPayloadKind = 0
                    } else {
                        $vPayloadKind = 1
                    }
                }

            } else {

                # No Variant array provided at all? 
                # Use the "Standard Enabled" profile so Registry matches Memory.
                $variantValue = 2
                $vPayloadKind = 1
            }
            $properties = @(
                @{ Name = "EnabledState";          Value = [int]$EnabledState },
                @{ Name = "EnabledStateOptions";   Value = 0 },
                @{ Name = "Variant";               Value = $variantValue },
                @{ Name = "VariantPayload";        Value = 0x0 },
                @{ Name = "VariantPayloadKind";    Value = $vPayloadKind }
            )

            $ObfuscateId = Obfuscate-FeatureId $f
            
            # FeatureConfigurationPriorityUserPolicy  = 0Ah
            $PolicyPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides"

            # FeatureConfigurationPriorityUser  = 0x8
            $UserPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\$Priority\$($ObfuscateId)"

            if ($Action -eq "Reset") {
                try {
                    # As Per, fcon.dll, StorageWriter::DeleteFeatureState, Safe Check
                    if ($Priority -gt 15 -or @(0, 7, 15) -contains $Priority) {
                        if ($Log) {
                           Write-Warning "Priority $Priority is system-protected. Skipping." 
                        }
                        continue
                    }

                    # fcon.dll, __int64 __fastcall StorageWriter::DeleteFeatureState(unsigned int a1, int a2)
                    $SafePriorities = 1..6 + 8..9 + 11..14
                    if ($Priority -in $SafePriorities -and (Test-Path $UserPath)) { 
                        if ($Log) {
                            Write-Warning "Remove Path: $UserPath"
                        }
                        Remove-Item -Path $UserPath -Recurse -Force 
                    }

                    # fcon.dll, __int64 __fastcall StorageWriter::DeletePolicyFeatureState(int a1)
                    if ($Log) {
                      Write-Warning "Remove Path: $PolicyPath, $ObfuscateId"
                    }
                    Remove-ItemProperty -Path $PolicyPath -Name $ObfuscateId -ErrorAction SilentlyContinue
                }
                catch {}
            }

            if ($Action -match "Enable|Disable") {
                $targetPath = if ($Mode -eq "Policy") { $PolicyPath } else { $UserPath }
                if (!(Test-Path $targetPath)) {
                    New-Item -Path $targetPath -Force -ErrorAction Stop | Out-Null
                }
                if ($Mode -eq "Policy") {
                    if ($Log) {
                      Write-Warning "Write Path: $targetPath,$ObfuscateId,$EnabledState"
                    }
                    Set-ItemProperty -Path $targetPath -Name $ObfuscateId -Value ([int]$EnabledState) -Type DWord -ErrorAction Stop
                } else {
                    foreach ($property in $properties) {
                        if ($Log) {
                          Write-Warning "Write Path: $targetPath,$($property.Name),$($property.Value)"
                        }
                        Set-ItemProperty -Path $targetPath -Name $property.Name -Value $property.Value -Type DWord -ErrorAction Stop
                    }
                }
            }
        }

        # As Seen in fcon.dll, __int64 __fastcall StagingControls_SetFeatureEnabledState
        # Called ofter Set regitry value, & After call ZwSetSystemInformation

        $WnfPendingChange = [UInt64]0x0F890D2BA3BC2075
        $RTL::RtlPublishWnfStateData($WnfPendingChange, 0, 0, 0) | Out-Null

        # Instruction as found in,
        # Vive Tool, Consumer_ESU_Enrollment.ps1

        $BootPending = 0x01
        $ConfigurationState = 0x11

        [Uint32]$CurState = 0;
        $hr = $RTL::RtlGetSystemBootStatus(
            $ConfigurationState,
            ([ref]$CurState),
            0x04, [IntPtr]::Zero
        )

        # Object Name not found. ERROR
        if ($hr -eq 0xC0000034) {
            $hr = $RTL::RtlCreateBootStatusDataFile([IntPtr]::Zero)
            if ($hr -ne 0x0) {
                Write-warning "Failed calling RtlCreateBootStatusDataFile: Code {$ret}"
                return $results
            }
        }

        if ($CurState -ne $BootPending) {
            $RTL::RtlSetSystemBootStatus(
                $ConfigurationState,
                ([ref]$BootPending),
                0x04, [IntPtr]::Zero
            ) | Out-Null
        }

        return $results
    }
    catch {
        Write-Warning "Failed to create feature override: $_"
    }
    return $false
}

<#
.SYNOPSIS
    Decodes Ring 3 Feature Control (FCON) runtime records.

.DESCRIPTION
    This implementation is a clean-room reverse engineering of the Windows 10/11 
    Feature Management subsystem. It specifically mirrors the logic found in:
    
    1. fcon.dll (The Packer): 
       Logic: StagingControls_EnumerateFeatures__lambda_...
       Task: Squashes 32-byte update structures into 12-byte runtime entries.
       
    2. EditionUpgradeManagerObj.dll (The Unpacker):
       Logic: wil_QueryFeatureState
       Task: Extracts 'Effective State' and 'Variant' for User-Mode consumption.

.NOTES
    VIVE COMPATIBILITY:
    This function represents the "Legacy" truth. It expects the State at Bit 4 
    and the Variant at Bit 8. If a feature was enabled via 'KernelMode' (Staging), 
    this reader may report 'Default' because it does not walk the Priority 
    Bucket stack (Bits 8, 10, 12) used by ntoskrnl.exe.
#>

function Get-FeatureObjectFromPtr {
    param(
        [IntPtr]$Pointer,
        [byte[]]$Buffer
    )

    if ($Buffer) {
        $fId   = [BitConverter]::ToUInt32($Buffer, 0)
        $flags = [Uint32]([BitConverter]::ToUInt32($Buffer, 4))
        $vPay  = [BitConverter]::ToUInt32($Buffer, 8)
    } else {
        # Read as signed Int32/Int16 first
        $rawId    = [Marshal]::ReadInt32($Pointer, 0)
        $rawFlags = [Marshal]::ReadInt32($Pointer, 4)
        $rawPay   = [Marshal]::ReadInt32($Pointer, 8)

        # Use BitConverter to re-interpret the bits as Unsigned
        $fId   = [BitConverter]::ToUInt32([BitConverter]::GetBytes($rawId), 0)
        $flags = [uint32]([BitConverter]::ToUInt32([BitConverter]::GetBytes($rawFlags), 0))
        $vPay  = [BitConverter]::ToUInt32([BitConverter]::GetBytes($rawPay), 0)
    }
    
    $Info = [Activator]::CreateInstance([RTL_FEATURE_INFO])

    $rawEnabledState = ($flags -shr 4) -band 0x3
    $StateLookup = @{ 0 = 'Default'; 1 = 'Disabled'; 2 = 'Enabled' }

    $rawState = ($flags -shr 4) -band 0x3
    $EnabledState = if ($StateLookup.ContainsKey([int]$rawState)) { $StateLookup[[int]$rawState] } else { "N/A" }

    $Info.FeatureId            = [uint32]$fId
    $Info.FlagsRaw             = '0x{0:X8}' -f $flags
    $Info.Priority             = $flags -band 0xF
    $Info.EnabledState         = $EnabledState
    $Info.EnabledStateRaw      = $rawState
    $Info.IsWexpConfiguration  = (($flags -shr 6) -band 0x1)
    $Info.HasSubscriptions     = [bool](($flags -shr 7) -band 0x1)

    $Info.Variant              = ($flags -shr 8) -band 0x03
    $Info.VariantPayloadKind   = ($flags -shr 14) -band 0x3
    $Info.VariantPayload       = '0x{0:X8}' -f [uint32]$vPay
    $Info.Reserved             = 0 #($flags -shr 16) -band 0xFFFF
    $Info.EnabledStateOptions  = ($flags -shr 8) -band 0x3F

    return $Info
}
Function Query-FeatureConfiguration {
    [CmdletBinding(DefaultParameterSetName = 'Single')]
    param (
      [Parameter(Mandatory, Position = 0, ParameterSetName = 'Single')]
      [Int32[]]$Feature,

      [Parameter(ParameterSetName = 'List')]
      [switch]$OutList,

      [ValidateSet("Boot", "Runtime")]
      [string]$Store = "Runtime",

      [switch]$Atomic,
      [switch]$SysCall
    )
    
    if (!$Global:RTL) {
        Init-RTL
    }

    [IntPtr]$ConfigPtr = 0L
    [Int32]$configCount = 0x0

    # Ntdll!RtlQueryFeatureConfigurationChangeStamp, KI_USER_SHARED_DATA, KSYSTEM_TIME FeatureConfigurationChangeStamp;
    [UInt64]$changeStamp = [marshal]::ReadInt64([IntPtr]::Add(0x7FFE0000, 0x0710))
    
    $Results = [List[RTL_FEATURE_INFO]]::new()
    $type = if ($Store -eq "Boot") { 0x00 } else { 0x01 }
    $Filter = $Feature -and $Feature.Count -and $Feature.Count -gt 1 -and !($Atomic.IsPresent)

    try {
        # Case !Single !Atomic -Or $OutList

        if ($OutList.IsPresent -or $Filter) {
            
            if ($SysCall.IsPresent) {
                return (
                    Query-KernelFeatureState -Feature $Feature
                )
            }
            $hr = $RTL::RtlQueryAllFeatureConfigurations($type, [ref]$changeStamp, [IntPtr]::Zero, [ref]$configCount)
            if ($configCount -le 0) { 
                return $null
            }

            $bufferSize = 0x0C * $configCount
            $ConfigPtr = [Marshal]::AllocHGlobal($bufferSize)
            $hr = $RTL::RtlQueryAllFeatureConfigurations($type, [ref]$changeStamp, $ConfigPtr, [ref]$configCount)
            if ($hr -ne 0) { 
                return $null 
            }

            for ($i = 0; $i -lt $configCount; $i++) {
                $Obj = [RTL_FEATURE_INFO](Get-FeatureObjectFromPtr -Pointer ([IntPtr]::Add($ConfigPtr, ($i * 0x0C))))
                if ($Filter -and !($Obj.FeatureId -in $Feature)) {
                    continue
                }
                $Results.Add($Obj)
                
                # Some duplicate items can have different priority
                # if ($Filter -and $Results.Count -eq $Feature.Count) { break }
            }
            return $results

        } else {

            # Case Single -Or Atomic
            
            foreach ($f in $Feature) {
                if ($SysCall.IsPresent) {
                    
                    # Call To NtQuerySystemInformationEx
                    $QueryPtr = [Marshal]::AllocHGlobal(0x08)
                    $OutPtr = [Marshal]::AllocHGlobal(0x18)
                    [marshal]::WriteInt32($QueryPtr, 0x00, $type)
                    [marshal]::WriteInt32($QueryPtr, 0x04, $f)

                    try {
                        $ret = $Global:RTL::NtQuerySystemInformationEx(
                            210,       # a1: SystemInformationClass (Feature Configuration)
                            $QueryPtr, # a2: QueryDetails (Input pointer)
                            0x08,      # a3: QueryDetailsLength (2 ints = 8 bytes)
                            $OutPtr,   # a4: SystemInformation (Output pointer)
                            0x18,      # a5: SystemInformationLength
                            0L         # a6: ReturnLength (Optional pointer, 0 is fine)
                        )

                        if ($ret -eq 0) {
                            $changeStamp = [Marshal]::ReadInt64($OutPtr, 0)    
                            $buffer = New-Object byte[] 0x0c
                            [Marshal]::Copy([IntPtr]($OutPtr.ToInt64() + 0x08), $buffer, 0, 0x0c)
                            $obj = [RTL_FEATURE_INFO](Get-FeatureObjectFromPtr -Buffer $buffer)
                            $Results.Add($obj)
                        }
                    }
                    finally {
                        [Marshal]::FreeHGlobal($QueryPtr)
                        [Marshal]::FreeHGlobal($OutPtr)
                    }

                } else {
                    
                    # Call To RtlQueryFeatureConfiguration
                    $ConfigPtr = [Marshal]::AllocHGlobal(0x0c)
                    try {
                        $hr = $RTL::RtlQueryFeatureConfiguration($f, $type, [ref]$changeStamp, $ConfigPtr)
                        if ($hr -eq 0) {
                            $buffer = New-Object byte[] 0x0C
                            [Marshal]::Copy($ConfigPtr, $buffer, 0, 0x0C)
                            $obj = [RTL_FEATURE_INFO](Get-FeatureObjectFromPtr -Buffer $buffer)
                            $Results.Add($obj)
                        }
                    }
                    finally {
                        [Marshal]::FreeHGlobal($ConfigPtr)
                        $ConfigPtr = 0L
                    }
                }
            }
            return $Results
        }
    }
    finally {
        if ($ConfigPtr -ne [IntPtr]::Zero) {
            [Marshal]::FreeHGlobal($ConfigPtr)
        }
    }
}

<#
.SYNOPSIS
    Decodes Ring 0 Kernel Feature Configuration runtime records.

.DESCRIPTION
    This function is a clean-room reverse engineering of the Windows Executive 
    Feature Manager (ntoskrnl.exe). It implements the high-fidelity bit-masking 
    and priority-ladder logic used by the OS to resolve 'Staging' configurations.

    REVERSED FROM:
    1. wil_details_StagingConfig_QueryFeatureState:
       The primary kernel-mode state resolver.
       
    2. wil_details_StagingConfigFeature_HasUniqueState:
       The "Gatekeeper" logic. Determines if a record entry is valid or should 
       be ignored based on bucket occupancy and variant assignment.

.NOTES
    STAGING TRUTH:
    This function ignores the 'Legacy' bits (Bit 4) used by User-Mode tools. 
    Instead, it parses the Priority Buckets (Service, Override, Default) located 
    at Bits 8-13. This is the "Absolute Truth" of what the Kernel is actually 
    executing, regardless of what the UI reports.
#>

function Get-KernelObjectFromPtr {
    param(
        [IntPtr]$Pointer,
        [byte[]]$Buffer,
        [bool]$ApplyMaskingFlag = $false,  # Kernel a4 / v5
        [uint32]$GlobalMask = 0            # Kernel bitmask
    )

    # ==============================================
    # 1. Read raw struct (12B) - Standard wil entry
    # ==============================================

        if ($Buffer) {
                
            $fId   = [BitConverter]::ToUInt32($Buffer, 0)
            $flags = [BitConverter]::ToUInt32($Buffer, 4)
            $vPay  = [BitConverter]::ToUInt32($Buffer, 8)
                 
        } else {

            # Read the raw 4-byte signed integers first
            $rawId    = [Marshal]::ReadInt32($Pointer, 0)
            $rawFlags = [Marshal]::ReadInt32($Pointer, 4)
            $rawPay   = [Marshal]::ReadInt32($Pointer, 8)

            # Convert to bytes and re-interpret as UInt32 to bypass the sign-bit crash
            $fId   = [BitConverter]::ToUInt32([BitConverter]::GetBytes($rawId), 0)
            $flags = [BitConverter]::ToUInt32([BitConverter]::GetBytes($rawFlags), 0)
            $vPay  = [BitConverter]::ToUInt32([BitConverter]::GetBytes($rawPay), 0)
        }

    $originalFlags = $flags

    # ==========================================
    # 2. Kernel masking stage (LABEL_10 logic)
    # ==========================================

    if ($ApplyMaskingFlag) {

        if ($GlobalMask -band 0x4) { $flags = $flags -band 0xFFFFCFFF } # clear bits 1213
        if ($GlobalMask -band 0x2) { $flags = $flags -band 0xFFFFF3FF } # clear bits 1011
        if ($GlobalMask -band 0x1) { $flags = $flags -band 0xFFFFFCFF } # clear bits 89
        if ($GlobalMask -band 0x8) {
            $flags = $flags -band 0xC0FFFFFF  # clear variant + payload
            $vPay  = 0
        }
    }

    # =============================================================
    # 3. HasUniqueState Gatekeeper (wil_details_...HasUniqueState)
    # =============================================================

    # Kernel logic: ((v1 | ((v1 | (v1 >> 2)) >> 2)) & 0x300) != 0 || (v1 & 0x3F000000) != 0 || (v1 & 2) != 0
    $v1 = $flags
    $checkBuckets = (($v1 -bor (($v1 -bor ($v1 -shr 2)) -shr 2)) -band 0x300) -ne 0
    $checkVariant = ($v1 -band 0x3F000000) -ne 0
    $checkModified = ($v1 -band 2) -ne 0
    $hasUniqueState = ($fId -ne 0) -and ($checkBuckets -or $checkVariant -or $checkModified)

    # ====================================================
    # 4. Extraction Logic (Only if Unique State is valid)
    # ====================================================

    $rawState = 0
    $stateService  = 0
    $stateOverride = 0
    $stateDefault  = 0

    if ($hasUniqueState) {

        # Extract state buckets
        $stateService  = ($flags -shr 12) -band 0x3
        $stateOverride = ($flags -shr 10) -band 0x3
        $stateDefault  = ($flags -shr 8)  -band 0x3

        # Kernel priority logic (v24/v25 logic)
        if ($stateService -ne 0) {
            $rawState = $stateService
        }
        elseif ($stateOverride -ne 0) {
            $rawState = $stateOverride
        }
        elseif ($stateDefault -ne 0) {
            $rawState = $stateDefault
        }
    }

    # ==========================================
    # 5. Build Result Object
    # ==========================================

    $StateLookup = @{ 0 = 'Default'; 1 = 'Disabled'; 2 = 'Enabled' }
    $EnabledState = if ($StateLookup.ContainsKey([int]$rawState)) { $StateLookup[[int]$rawState] } else { "Unknown" }

    $kObj = [Activator]::CreateInstance([Type]'RTL_KERNEL_FEATURE_INFO')
    
    # Header
    $kObj.FeatureId           = $fId
    $kObj.HasUniqueState      = $hasUniqueState
        
    # Effective Data
    $kObj.EnabledState        = $EnabledState
    $kObj.EnabledStateRaw     = [int]$rawState

    # XOR happens inside the kernel merge logic when updating the 0x10 byte:
    # it preserves unrelated bits in the original 32-byte flags while updating
    # EnabledState (bits 4-5) and Variant (bits 0-3/0-5 depending on struct).
    # During unpack, we extract the raw byte: ($flags -shr 8) -band 0xFF,
    # then decode EnabledState = bits 4-5, Variant = bits 0-3/0-5. The XOR is internal.

    $kObj.Variant             = (($flags -shr 8) -band 0x3F) -band 0x0F

    $kObj.VariantPayloadKind  = ($flags -shr 14) -band 0x3
    $kObj.VariantPayload      = ('0x{0:X8}' -f [uint32]$vPay)
        
    # Bit 7: HasSubscriptions
    # This bit is ignored by the Packer (fcon.dll/RtlpFcUpdateFeature). 
    # It is dynamically set by the Kernel ONLY if:
    #   A) The FeatureId is in the hardcoded Master Subscription Table.
    #   B) A Ring 3 caller has invoked RtlSubscribeForFeatureUsageNotification.
    $kObj.HasSubscriptions = [bool](($flags -shr 7) -band 0x1)

    # Bit 6: IsWexpConfiguration 
    # Identifies if the feature is part of a Windows Experience Pack.
    $kObj.IsWexpConfiguration = ($flags -shr 6) -band 0x1

    $kObj.Priority            = $flags -band 0xF
        
    # Debugging / Internal buckets
    $kObj.State_Service       = $stateService
    $kObj.State_Override      = $stateOverride
    $kObj.State_Default       = $stateDefault
        
    # Flags
    $kObj.FlagsRaw            = ('0x{0:X8}' -f $originalFlags)
    $kObj.FlagsEffective      = ('0x{0:X8}' -f $flags)
    $kObj.MaskApplied         = $GlobalMask

    return $kObj
}
function Query-KernelFeatureState {
    param (
        [ValidateSet("Boot", "Runtime")]
        [String]$Store = "Runtime",
        [Int32[]]$Feature,
        [switch]$ApplyFlags,
        [switch]$Log
    )

    if (!$Global:RTL) {
        Init-RTL
    }

    # ntdll.dll
    # __int64 __fastcall RtlpFcUpdateLocalConfiguration(__int64 a1, unsigned __int64 a2, char a3)
    # __int64 __fastcall RtlpFcQueryAllFeatureConfigurationsFromBufferSet(__int64 a1, unsigned int a2)
    # __int64 __fastcall RtlpFcQueryAllFeatureConfigurationsFromBuffers(__int64 a1, void *a2, unsigned __int64 *a3)

    # ntoskrnl.exe
    # __int64 __fastcall CmQueryFeatureConfigurationSections
    # __int64 __fastcall CmFcManagerUpdateFeatureConfigurations(__int64 a1, __int64 a2, int a3, __int64 a4, unsigned int a5)
    # __int64 __fastcall CmFcManagerQueryFeatureConfigurationSectionInformation(__int64 a1, _QWORD *a2, __int64 *a3, KPROCESSOR_MODE a4)
    
    $inSz, $outSz = 0x18, 0x50
    $pIn  = [Marshal]::AllocHGlobal($inSz)
    $pOut = [Marshal]::AllocHGlobal($outSz)
    [IntPtr]$hSec = [IntPtr]$baseAddr = 0L
    
    for ($i = 0; $i -lt $outSz; $i += 8) { [Marshal]::WriteInt64($pOut, $i, 0) }
    for ($i = 0; $i -lt $inSz;  $i += 8) { [Marshal]::WriteInt64($pIn,  $i, 0) }

    try {
        $status = $Global:RTL::NtQuerySystemInformationEx(211, $pIn, $inSz, $pOut, $outSz, 0L)
        if ($status -ne 0) { throw "NtQuerySystemInformationEx failed: 0x$($status.ToString('X8'))" }
        $FeatureTable = [KERNEL_FEATURE_TABLE]$pOut

        $hSec = switch ($Store) {
            'Boot'    { [Int64]::Parse($FeatureTable.Boot_Handle) }
            'Runtime' { [Int64]::Parse($FeatureTable.Runtime_Handle) }
            Default   { 0L }
        }
        if ($hSec -eq [IntPtr]::Zero) { return @() }

        $viewSize = [IntPtr]::Zero
        $status = $Global:RTL::ZwMapViewOfSection($hSec, [IntPtr](-1), [ref]$baseAddr, [UIntPtr]::Zero, [UIntPtr]::Zero, [ref]0, [ref]$viewSize, 0x2, 0x0, 0x2)
        if ($status -ne 0) { throw "ZwMapViewOfSection failed: 0x$($status.ToString('X8'))" }

        #$hCount = [Marshal]::ReadInt32($baseAddr, 0)
        #$hSize  = 0x04 + ($hCount * 0x0C)

        $hSize = switch ($Store) {
            'Boot'    { [Int32]($FeatureTable.Boot_Size) }
            'Runtime' { [Int32]($FeatureTable.Runtime_Size) }
        }

        $buffer = [byte[]]::new($hSize)
        [Marshal]::Copy($baseAddr, $buffer, 0, $hSize)
        
        $ms = [IO.MemoryStream]::new($buffer)
        $br = [IO.BinaryReader]::new($ms)
        $results = [List[RTL_KERNEL_FEATURE_INFO]]::new()

        try {
            $ms.Position = 0x04 # Skip count header
            while ($ms.Position -lt $ms.Length) {
                $entry = $br.ReadBytes(0x0C)
                if ($Feature -and ([BitConverter]::ToInt32($entry, 0) -notin $Feature)) { continue }
                $featureObj = (Get-KernelObjectFromPtr -Buffer $entry -ApplyMaskingFlag $ApplyFlags.IsPresent)
                $results.Add($featureObj)
                
                # Some duplicate items can have different priority
                # if ($Feature -and $results.Count -eq $Feature.Count) { break }
            }
        }
        finally {
            $br.Close();
            $ms.Dispose()
        }
        return $results
    }
    catch {
        Write-Error $_.Exception.Message
    }
    finally {
        if ($baseAddr -ne [IntPtr]::Zero) {
            $Global:RTL::ZwUnmapViewOfSection([IntPtr](-1), $baseAddr) | Out-Null
        }
        if ($hSec -ne [IntPtr]::Zero) {
            $Global:RTL::NtClose($hSec) | Out-Null
        }
        [Marshal]::FreeHGlobal($pIn)
        [Marshal]::FreeHGlobal($pOut)
    }
}

#endregion
#region "Feature, WNF"
<#
Based on mach2
https://github.com/riverar/mach2

NTSTATUS
NTAPI
NtQueryWnfStateData(
    [In]      PCWNF_STATE_NAME  StateName,
    [In_opt]  PCWNF_TYPE_ID     TypeId,
    [In_opt]  const VOID*       ExplicitScope,
    [Out]     PWNF_CHANGE_STAMP ChangeStamp,
    [Out_opt] PVOID             Buffer,
    [In_out]  PULONG            BufferSize
);

EditionUpgradeManagerObj.dll
__int64 __fastcall wil_details_StagingConfig_Load(__int64 a1, int a2, __int64 a3, __int64 a4)
__int64 __fastcall wil_details_StagingConfig_QueryFeatureState(__int64 a1, __int64 a2, int a3, int a4)
__int64 __fastcall wil_StagingConfig_QueryFeatureState(int a1, __int64 a2, __int64 a3, int a4, _DWORD *a5)
__int64 __fastcall wil_details_NtQueryWnfStateData(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)

ntoskrnl.exe
__int64 __fastcall ExpCaptureWnfStateName(__int64 *a1, unsigned __int64 *a2, char a3)
__int64 __fastcall wil_details_StagingConfig_Load(__int64 a1, int a2, __int64 a3, __int64 a4)
__int64 __fastcall NtQueryWnfStateData(__int64 a1, __int64 a2, __int64 a3, _DWORD *a4, volatile void *Address,_DWORD *a6)

Visiting Vibranium Velocity
A look at new changes to everyone favorite A/B system
https://medium.com/@thebookisclosed/visiting-vibranium-velocity-f1ae76253c67

Enter build 18963
Among the features this build introduces are these two: FconWritesToWNF and FconWritesToRTL. Here a quick rundown of the terminology used in these names.

* Fcon = Feature Configuration library (lives in System32)
* WNF = Windows Notification Facility
* RTL = Run-Time Library functions inside ntdll

Until this build, 
there were no centralized functions in the OS which would let developers explicitly work with features.
Programs had to work with a specific WNF state (basically a data blob) which was used for configuring features, 
the contents of which can be queried or written to.

Starting with build 18963, 
ntdll now sports a set of exports designed precisely for feature work. Those being:
RtlNotifyFeatureUsage
RtlQueryAllFeatureConfigurations
RtlQueryFeatureConfiguration
RtlQueryFeatureConfigurationChangeStamp
RtlQueryFeatureUsageNotificationSubscriptions
RtlRegisterFeatureConfigurationChangeNotification
RtlSetFeatureConfigurations
RtlSubscribeForFeatureUsageNotification
RtlUnregisterFeatureConfigurationChangeNotification
RtlUnsubscribeFromFeatureUsageNotifications
#>
function Init-WNF {
    
    # Define the WNF feature entry struct
    if (-not ([PSTypeName]'WNF_FEATURE_ENTRY').Type) {
        New-Struct `
            -Module (New-InMemoryModule -ModuleName WNF_FEATURE_ENTRY) `
            -FullName WNF_FEATURE_ENTRY `
            -StructFields @{
                FeatureId   = New-field 0 UInt32   # offset 0x00
                PackedBits  = New-field 1 UInt32   # offset 0x04
                Payload     = New-field 2 UInt32   # offset 0x08
            } | Out-Null
    }

    # Define the WNF update header struct
    if (-not ([PSTypeName]'WNF_FEATURE_UPDATE').Type) {
        New-Struct `
            -Module (New-InMemoryModule -ModuleName WNF_FEATURE_UPDATE) `
            -FullName WNF_FEATURE_UPDATE `
            -StructFields @{
                Version                   = New-field 0 Byte      # 0x00
                VersionMinor              = New-field 1 Byte      # 0x01
                HeaderSizeBytes           = New-field 2 UInt16    # 0x02
                FeatureCount              = New-field 3 UInt16    # 0x04
                FeatureUsageTriggerCount  = New-field 4 UInt16    # 0x06
                SessionProperties         = New-field 5 UInt32    # 0x08
                Properties                = New-field 6 UInt32    # 0x0C
            } | Out-Null
    }

    # Define a simple struct for holding parsed WNF feature data.
    # This struct is used only for storing feature entries in an array/list.
    # Each instance represents one feature with its states, text description, and payload
    if (-not ([PSTypeName]'WNF_FEATURE_INFO').Type) {
        New-Struct `
            -Module (New-InMemoryModule -ModuleName WNF_FEATURE_INFO) `
            -FullName WNF_FEATURE_INFO `
            -StructFields @{
                FeatureId     = New-field 0 UInt32
                ServiceState  = New-field 1 UInt32
                UserState     = New-field 2 UInt32
                TestState     = New-field 3 UInt32
                Kind          = New-field 4 UInt32
                StateText     = New-field 5 String
                Payload       = New-field 6 UInt32
                InVariantList = New-field 7 Bool
            } | Out-Null
    }

    try {
        $Module = [AppDomain]::CurrentDomain.GetAssemblies()| ? { $_.ManifestModule.ScopeName -eq "WNF" } | select -Last 1
        $Global:WNF = $Module.GetTypes()[0]
    }
    catch {
        $Module = [AppDomain]::CurrentDomain.DefineDynamicAssembly("null", 1).DefineDynamicModule("WNF", $False).DefineType("null")
        @(
            @('null', 'null', [int], @()), # place holder
            @( "NtQueryWnfStateData",  "ntdll.dll", [Int32], @([UInt64].MakeByRefType(), [Int64], [Int64], [UInt32].MakeByRefType(), [IntPtr], [UInt32].MakeByRefType())),
            @( "NtUpdateWnfStateData", "ntdll.dll", [Int32], @([UInt64].MakeByRefType(), [IntPtr], [UInt32], [UInt32].MakeByRefType(), [UInt64], [UInt32], [UInt32]))
        ) | % {
            $Module.DefinePInvokeMethod(($_[0]), ($_[1]), 22, 1, [Type]($_[2]), [Type[]]($_[3]), 1, 3).SetImplementationFlags(128) # Def` 128, fail-safe 0
        }
        $Global:WNF = $Module.CreateType()
    }
}
function Get-WnfObjectFromPtr {
    param (
        [Parameter(Mandatory)]
        [IntPtr]$Buffer,

        [Parameter(Mandatory)]
        [UInt32]$BufferSize,

        [Parameter(Mandatory)]
        [UInt32]$ChangeStamp,

        [UInt32[]]$Feature,

        [switch]$UseAltFlags
    )

    # EditionUpgradeManagerObj.dll
    # __int64 __fastcall wil_details_StagingConfig_QueryFeatureState(__int64 a1, __int64 a2, int a3, int a4)
    # __int64 __fastcall wil_StagingConfig_QueryFeatureState(int a1, __int64 a2, __int64 a3, int a4, _DWORD *a5)

    $Version      = [Marshal]::ReadByte($Buffer, 0)
    $HeaderSize   = [Marshal]::ReadInt16($Buffer, 2)
    $FeatureCount = [Marshal]::ReadInt16($Buffer, 4)
    $VariantCount = [Marshal]::ReadInt16($Buffer, 6)

    if ($Version -ne 2) {
        Write-Warning "Unexpected WNF Version ($Version)"
    }

    $FeatureObjects = [List[WNF_FEATURE_INFO]]::new()

    $FeatureListOffset = $HeaderSize
    $VariantListOffset = $HeaderSize + ($FeatureCount * 0x0C)

    $FlagsOffset = if ($UseAltFlags.IsPresent) { 0x0C } else { 0x08 }
    $Flags = [Marshal]::ReadInt32($Buffer, $FlagsOffset)

    $Remaining = $null
    if ($Feature) {
        $Remaining = [HashSet[uint32]]::new($Feature)
    }

    for ($i = 0; $i -lt $FeatureCount; $i++) {

        $CurrentOffset = $FeatureListOffset + ($i * 0x0C)
        if (($CurrentOffset + 0x0C) -gt $BufferSize) { break }

        $FeatureId = [Marshal]::ReadInt32($Buffer, $CurrentOffset)
        if ($Remaining) {
            if (!($Remaining.Contains($FeatureId))) {
                continue
            }
            $Remaining.Remove($FeatureId) | Out-Null
        }
        $bits      = [Marshal]::ReadInt32($Buffer, $CurrentOffset + 4)
        $Payload   = [Marshal]::ReadInt32($Buffer, $CurrentOffset + 8)

        if ($Flags -band 4) { $bits = $bits -band 0xFFFFCFFF }
        if ($Flags -band 2) { $bits = $bits -band 0xFFFFF3FF }
        if ($Flags -band 1) { $bits = $bits -band 0xFFFFFCFF }
        if ($Flags -band 8) {
            $bits    = $bits -band 0xC0FFFFFF
            $Payload = 0
        }

        $ServState = ($bits -shr 8)  -band 0x3
        $UserState = ($bits -shr 10) -band 0x3
        $TestState = ($bits -shr 12) -band 0x3
        $Kind      = ($bits -shr 30) -band 0x3

        if ($TestState -ne 0) {
            $EffectiveState = $TestState
        }
        elseif ($UserState -ne 0) {
            $EffectiveState = $UserState
        }
        else {
            $EffectiveState = $ServState
        }

        $byte1 = ($bits -shr 8) -band 0xFF

        $valid =
            ($FeatureId -ne 0) -and (
                ((($byte1 -bor (($bits -shr 10) -band 0xFF) -bor (($bits -shr 12) -band 0xFF)) -band 3) -ne 0) -or
                (($bits -band 0x3F000000) -ne 0) -or
                (($bits -band 2) -ne 0)
            )

        if (-not $valid) {
            continue
        }

        # ----------------------------------------
        # Variant list check (matches tail loop)
        # ----------------------------------------

        $InVariantList = $false
        if ($VariantCount -gt 0) {
            for ($v = 0; $v -lt $VariantCount; $v++) {
                $VarOffset = $VariantListOffset + ($v * 16)  # 4 DWORD stride
                if (($VarOffset + 4) -gt $BufferSize) { break }

                $VarFeatureId = [Marshal]::ReadInt32($Buffer, $VarOffset)
                if ($VarFeatureId -eq $FeatureId) {
                    $InVariantList = $true
                    break
                }
            }
        }

        # ----------------------------------------
        # Human-readable state
        # ----------------------------------------

        $StateText = switch ($EffectiveState) {
            1 { "Disabled" }
            2 { "Enabled" }
            default { "Default/Unknown" }
        }

        # ----------------------------------------
        # Build object
        # ----------------------------------------

        $featureObj = [WNF_FEATURE_INFO]::new()
        $featureObj.FeatureId     = $FeatureId
        $featureObj.ServiceState  = $ServState
        $featureObj.UserState     = $UserState
        $featureObj.TestState     = $TestState
        $featureObj.Kind          = $Kind
        $featureObj.StateText     = $StateText
        $featureObj.Payload       = $Payload
        $featureObj.InVariantList = $InVariantList

        $FeatureObjects.Add($featureObj)
        
        # Some duplicate items can have different priority
        # if ($Remaining -and $Remaining.Count -eq 0) { break }
    }

    return $FeatureObjects
}
function Set-WnfFeatureConfig {
    param (
        [Parameter(Mandatory)]
        [ValidateSet("User","Machine")]
        [string]$Store,

        [Parameter(Mandatory)]
        [ValidateSet("Enable","Disable","Default")]
        [string]$Mode,

        [Parameter(Mandatory)]
        [uint32[]]$Feature
    )
    if (!$Global:wnf) {
      Init-WNF
    }

    # Map mode to numeric ServiceState
    $modeMap = @{
        "Default" = 0
        "Disable" = 1
        "Enable"  = 2
    }
    $StateValue = $modeMap[$Mode]

    # WNF Store ID
    $WnfStore = switch ($Store) {
        "User"    { 0x418A073AA3BC88F5L }
        "Machine" { 0x418A073AA3BC7C75L }
    }

    # Query existing WNF change stamp
    $ChangeStamp = [UInt32]0
    $BufferSize = [UInt32]0
    $hr = $Global:wnf::NtQueryWnfStateData([ref]$WnfStore, 0L, 0L, [ref]$ChangeStamp, 0L, [ref]$BufferSize)

    $Count = $Feature.Count
    $BufferSize = 16 + (12 * $Count)
    $Buffer = [Marshal]::AllocHGlobal($BufferSize)

    try {
        $update = [Activator]::CreateInstance([Type]'WNF_FEATURE_UPDATE')
        $update.Version = 2
        $update.VersionMinor = 2
        $update.HeaderSizeBytes = 16
        $update.FeatureCount = $Count
        $update.FeatureUsageTriggerCount = 0
        $update.SessionProperties = 0
        $update.Properties = 0
        [marshal]::StructureToPtr($update, $Buffer, $false)

        for ($i=0; $i -lt $Count; $i++) {
            $featureEntry = [Activator]::CreateInstance([Type]'WNF_FEATURE_ENTRY')
            $featureEntry.FeatureId = [UInt32]$Feature[$i]
            $featureEntry.PackedBits = [UInt32]($StateValue -shl 8) # ServiceState at bits 8-9
            $featureEntry.Payload = 0
            [Marshal]::StructureToPtr(
                $featureEntry, 
                ([IntPtr]::Add($Buffer, 16 + ($i * 12))), 
                $false
            )
        }

        # Update WNF
        $hr = $Global:wnf::NtUpdateWnfStateData(
                [ref]$WnfStore,
                $Buffer,
                [UInt32]$BufferSize,
                [ref]$ChangeStamp,
                0L,
                $ChangeStamp,
                0x1
            )

        return $hr
    }
    finally {
        [Marshal]::FreeHGlobal($Buffer)
    }
}
function Query-WnfFeatureConfig {
    [CmdletBinding(DefaultParameterSetName = 'Single')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("User","Machine")]
        [string]$Store,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Single')]
        [Uint32[]]$Feature,

        [Parameter(ParameterSetName = 'List')]
        [switch]$OutList
    )

    if (!$Global:wnf) {
      Init-WNF
    }

    $WnfStore = switch ($Store) {
        "User"    { 0x418A073AA3BC88F5L }
        "Machine" { 0x418A073AA3BC7C75L }
    }

    $ChangeStamp = [UInt32]0
    $BufferSize = [UInt32]0
    $Buffer = [IntPtr]::Zero

    try {
        # Query size & stamp
        $hr = $Global:wnf::NtQueryWnfStateData([ref]$WnfStore, 0L, 0L, [ref]$ChangeStamp, 0L, [ref]$BufferSize)

        if ($hr -eq 0xC0000023 -and $BufferSize -gt 0) {
            $Buffer = [Marshal]::AllocHGlobal($BufferSize)

            # Query actual data
            $hr = $Global:wnf::NtQueryWnfStateData([ref]$WnfStore, 0L, 0L, [ref]$ChangeStamp, $Buffer, [ref]$BufferSize)

            if ($hr -eq 0) {
            switch ($PSCmdlet.ParameterSetName) {
                'List' {
                    Get-WnfObjectFromPtr -Buffer $Buffer -BufferSize $BufferSize -ChangeStamp $ChangeStamp
                }
                'Single' {
                    Get-WnfObjectFromPtr -Buffer $Buffer -BufferSize $BufferSize -ChangeStamp $ChangeStamp -Feature $Feature
                }
            }
                return;
            }
        }
    }
    finally {
        if ($Buffer -ne [IntPtr]::Zero) {
            [Marshal]::FreeHGlobal($Buffer)
        }
    }
}
#endregion

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
Write-Host "Registry Look Up" -ForegroundColor Magenta

# Write-Host "WNF, Mode: Enable`n" -ForegroundColor Green
# Set-WnfFeatureConfig   -Store User    -Mode Enable -Feature $Feature | Out-Null
# Set-WnfFeatureConfig   -Store Machine -Mode Enable -Feature $Feature | Out-Null
# Query-WnfFeatureConfig -Store User    -Feature $Feature
# Query-WnfFeatureConfig -Store Machine -Feature $Feature

return