using namespace System
using namespace System.IO
using namespace System.Reflection
using namespace System.Reflection.Emit
using namespace System.Collections.Generic
using namespace System.Management.Automation
using namespace System.Runtime.InteropServices

# Fcon = Feature Configuration library (lives in System32)
# WNF = Windows Notification Facility
# RTL = Run-Time Library functions inside ntdll

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
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

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
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
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
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
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
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
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
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
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
function Register-NativeMethods {
    param (
        [Parameter(Mandatory)]
        [Array]$FunctionList,

        # Global defaults
        $NativeCallConv      = [CallingConvention]::Winapi,
        $NativeCharSet       = [CharSet]::Unicode,
        $ImplAttributes      = [MethodImplAttributes]::PreserveSig,
        $TypeAttributes      = [TypeAttributes]::Public -bor [TypeAttributes]::Abstract -bor [TypeAttributes]::Sealed,
        $Attributes          = [MethodAttributes]::Public -bor [MethodAttributes]::Static -bor [MethodAttributes]::PinvokeImpl,
        $CallingConventions  = [CallingConventions]::Standard
    )

    # Dynamic assembly + module
    $asmName = New-Object System.Reflection.AssemblyName "DynamicDllHelperAssembly"
    $asm     = [AppDomain]::CurrentDomain.DefineDynamicAssembly($asmName, [AssemblyBuilderAccess]::Run)
    $mod     = $asm.DefineDynamicModule("DynamicDllHelperModule")
    $tb      = $mod.DefineType("NativeMethods", $TypeAttributes)

    foreach ($func in $FunctionList) {
        # Per-function overrides
        $funcCharSet = if ($func.ContainsKey("CharSet")) { 
            [CharSet]::$($func.CharSet) 
        } else { 
            $NativeCharSet 
        }

        $funcCallConv = if ($func.ContainsKey("CallConv")) { 
            $func.CallConv 
        } else { 
            $NativeCallConv 
        }

        $tb.DefinePInvokeMethod(
            $func.Name,
            $func.Dll,
            $Attributes,
            $CallingConventions,
            $func.ReturnType,
            $func.Parameters,
            $funcCallConv,
            $funcCharSet
        ).SetImplementationFlags($ImplAttributes)
    }

    return $tb.CreateType()
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

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* RTL_FEATURE_CONFIGURATION_UPDATE - NtDoc
* https://ntdoc.m417z.com/rtl_feature_configuration_update

// Ntoskrnl.exe
// __int64 __fastcall RtlpFcUpdateFeatureConfiguration(_DWORD *a1, __int64 a2, char *a3, size_t a4, void *a5, size_t *a6)
// v18 += 32;
// qsort(a3, a4, 0x20ui64, RtlpFcCompareUpdates);

// ntdll.dll
// __int64 __fastcall RtlSetFeatureConfigurations(_QWORD *a1, int a2, const void *a3, unsigned __int64 a4)
// v8 = 32i64 * (unsigned int)a4;

// ntoskrnl.exe, Function RtlpFcUpdateFeature
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

typedef struct _RTL_FEATURE_CONFIGURATION_UPDATE
{
    /* 0x00 */ ULONG FeatureId;
    /* 0x04 */ RTL_FEATURE_CONFIGURATION_PRIORITY Priority;
    /* 0x08 */ RTL_FEATURE_ENABLED_STATE EnabledState;

    /* 0x0C */ ULONG PackedOptions;       // Read at a2 + 12

    /* 0x10 */ UCHAR EnabledStateOptions; // Read at a2 + 16 (The byte access)
    /* 0x11 */ UCHAR Reserved[3];         // Padding to reach next 4-byte boundary

    /* 0x14 */ union {
        ULONG Flags;
        struct {
            ULONG Variant : 6;
            ULONG ChangeTimeUpgrade : 1;
            ULONG HasGroupBypass : 1;
            ULONG Reserved : 24;
        } FeatureFlags;
    } FeatureConfig; // Read at a2 + 20

    /* 0x18 */ ULONG VariantPayload;      // Read at a2 + 24

    /* 0x1C */ RTL_FEATURE_CONFIGURATION_OPERATION Operation; // Read at a2 + 28

} RTL_FEATURE_CONFIGURATION_UPDATE;

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

// Ntoskrnl.exe, IDA, Local Types
00000000 _RTL_FEATURE_CONFIGURATION struc ; (sizeof=0xC, align=0x4)
00000000 FeatureId       dd ?        ; 0x0, 4 bytes — Feature identifier
00000004 Option          dw ?        ; 0x4, 2 bytes — packed bitfield of options
00000006 padding         dw ?        ; 0x6, 2 bytes — alignment padding
00000008 VariantPayload  dd ?        ; 0x8, 4 bytes — payload value
0000000C _RTL_FEATURE_CONFIGURATION ends

//0xc bytes (sizeof)
struct _RTL_FEATURE_CONFIGURATION
{
    ULONG FeatureId;                                                        //0x0
    ULONG Priority:4;                                                       //0x4
    ULONG EnabledState:2;                                                   //0x4
    ULONG IsWexpConfiguration:1;                                            //0x4
    ULONG HasSubscriptions:1;                                               //0x4
    ULONG Variant:6;                                                        //0x4
    ULONG VariantPayloadKind:2;                                             //0x4
    ULONG VariantPayload;                                                   //0x8
};

// ntoskrnl.exe
// __int64 __fastcall wil_details_StagingConfig_QueryFeatureState(__int64 a1, __int64 a2, int a3, int a4)
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

// EditionUpgradeManagerObj.dll
// __int64 __fastcall wil_QueryFeatureState(__int64 a1, unsigned int a2, int a3, int a4, _DWORD *a5, _DWORD *a6)
{
    ....
    v14 = HIDWORD(v18);
    v10 = 1;
    v15 = HIDWORD(v18);
    *(_DWORD *)(a1 + 12) = v19;
    *(_DWORD *)(a1 + 8) = (unsigned __int16)v15 >> 14;
    *(_DWORD *)a1 = (v15 >> 4) & 3;
    *(_BYTE *)(a1 + 4) = BYTE1(v14) & 0x3F;
    *(_DWORD *)(a1 + 16) = (v14 >> 7) & 1;
    *(_DWORD *)(a1 + 20) = (v14 >> 6) & 1;
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

    # Define the RTL feature update struct
    if (-not ([PSTypeName]'RTL_FEATURE_CONFIGURATION_UPDATE').Type) {
        New-Struct `
            -Module (New-InMemoryModule -ModuleName RTL_FEATURE_CONFIGURATION_UPDATE) `
            -FullName RTL_FEATURE_CONFIGURATION_UPDATE `
            -StructFields @{
                FeatureId           = New-field 0  UInt32   # 0x00
                Priority            = New-field 1  Int32    # 0x04
                EnabledState        = New-field 2  Int32    # 0x08
                PackedOptions       = New-field 3  Int32    # 0x0C (The mask 0x40 source)
                EnabledStateOptions = New-field 4  Byte     # 0x10 (The byte read at a2+16)
                reserved1           = New-field 5  byte     # 0x10 ++
                reserved2           = New-field 6  byte     # 0x10 ++
                reserved3           = New-field 7  byte     # 0x10 ++
                VariantFlags        = New-field 8  Int32    # 0x14 (The bits at a2+20)
                VariantPayload      = New-field 9 UInt32    # 0x18 (The value at a2+24)
                Operation           = New-field 10 Int32    # 0x1C (The v2 check at a2+28)
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
                IsWexpConfiguration = New-field 4  Boolean
                HasSubscriptions    = New-field 5  Boolean
                Variant             = New-field 6  UInt32
                VariantPayloadKind  = New-field 7  UInt32
                VariantPayload      = New-field 8  String
                Reserved            = New-field 9  UInt32
                EnabledStateOptions = New-field 10 UInt32
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
            @('RtlQueryFeatureConfigurationChangeStamp', 'ntdll.dll', [Int32], @()),
            @('RtlQueryAllFeatureConfigurations', 'ntdll.dll', [Int32], @([Int32], [UInt64].MakeByRefType(), [IntPtr], [Int32].MakeByRefType())),
            @('NtQuerySystemInformationEx', 'ntdll.dll', [Int32], @([Int32], [IntPtr], [Int32], [IntPtr], [Int32], [IntPtr])),
            @('ZwMapViewOfSection',         'ntdll.dll', [Int32], @([IntPtr], [IntPtr], [IntPtr].MakeByRefType(), [UIntPtr], [UIntPtr], [Int64].MakeByRefType(), [IntPtr].MakeByRefType(), [Int32], [Int32], [Int32])),
            @('ZwUnmapViewOfSection',       'ntdll.dll', [Int32], @([IntPtr], [IntPtr])),
            @('NtClose',                    'ntdll.dll', [Int32], @([IntPtr]))
        ) | % {
            $Module.DefinePInvokeMethod(($_[0]), ($_[1]), 22, 1, [Type]($_[2]), [Type[]]($_[3]), 1, 3).SetImplementationFlags(128) # Def` 128, fail-safe 0
        }
        $Global:RTL = $Module.CreateType()
    }
}
function Write-FeatureData {
    param(
        [int]     $Index,
        [int]     $BaseOffset,
        [IntPtr]  $UpdatePackage,
        [int]     $FeatureId = 0x0,
        [int]     $Priority = 0x0,
        [int]     $EnabledState = 0x0,
        [int]     $EnabledStateOptions = 0x0,
        [int]     $VariantFlags = 0x0,
        [int]     $VariantPayloadKind = 0x0,
        [int]     $VariantPayload = 0x0,
        [int]     $Operation = 0x0
    )

    $structure = [Activator]::CreateInstance([RTL_FEATURE_CONFIGURATION_UPDATE])
    $structure.FeatureId           = $FeatureId
    $structure.Priority            = $Priority
    $structure.EnabledState        = $EnabledState
    $structure.PackedOptions       = ($VariantPayloadKind -band 0x1) -shl 6
    $structure.EnabledStateOptions = [byte]$EnabledStateOptions
    $structure.VariantFlags        = $VariantFlags
    $structure.VariantPayload      = [uint32]$VariantPayload
    $structure.Operation           = $Operation

    $ptr = ([IntPtr]::Add($UpdatePackage, ($BaseOffset + (0x20 * $Index))))
    [marshal]::StructureToPtr($structure, $ptr, $true)
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

        [Parameter(Mandatory = $true)]
        [ValidateSet("Enable","Disable", "Reset")]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("User", "Policy")]
        [string]$Mode,

        [ValidateSet("Boot", "Runtime")]
        [String]$Store = "Runtime",

        [switch]$SysCall,
        [switch]$Log
    )

    if (!$Global:RTL) {
        Init-RTL
    }

    $results = $False
    $BootPending = 0x01
    $ConfigurationState = 0x11
    $type = if ($Store -eq "Boot") { 0x00 } else { 0x01 }
    $Priority = if ($Mode -eq "Policy") {  0x0a } else { 0x08 }
    $OperationType = if ($Action -match "Enable|Disable") { 0x01 -bor 0x02 } else { 0x04 }
    $EnabledState = if ($Action -eq 'Enable') { 0x02 } elseif ($Action -eq 'Disable') { 0x01 } else { 0x00 }
    if (!([Security.Principal.WindowsIdentity]::GetCurrent().Groups.Value -contains "S-1-5-32-544")) {
        Write-Error "User doesn't belong to Administrator's group"
        return
    }

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
        [Marshal]::StructureToPtr($header, $updatePackage, $true)

        $idx = -1;
        foreach ($f in $Feature) {
            $ConfigObj = $null
            if ($Action -eq "Reset") {
                $FeatureObj = $null
                $FeatureObj = Query-FeatureConfiguration -Feature $f
                if($FeatureObj) {
                    $Priority = $FeatureObj.Priority
                }
            }
            if ($ConfigObj) {
                Write-FeatureData `
                    -Index (++$idx) `
                    -BaseOffset $BaseSize `
                    -UpdatePackage $updatePackage `
                    -FeatureId $ConfigObj.FeatureId `
                    -Priority $ConfigObj.Priority `
                    -EnabledState $ConfigObj.EnabledState `
                    -EnabledStateOptions $ConfigObj.EnabledStateOptions `
                    -VariantFlags $ConfigObj.Variant `
                    -VariantPayloadKind $ConfigObj.VariantPayloadKind `
                    -VariantPayload $ConfigObj.VariantPayload `
                    -Operation $ConfigObj.Operation
            } else {
                Write-FeatureData `
                    -Index (++$idx) `
                    -BaseOffset $BaseSize `
                    -UpdatePackage $updatePackage `
                    -FeatureId $f `
                    -Priority $Priority `
                    -EnabledState $EnabledState `
                    -Operation $OperationType
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
        foreach ($f in $Feature) {
            $properties = @(
                @{ Name = "EnabledState";          Value = [int]$EnabledState },
                @{ Name = "EnabledStateOptions";   Value = 0 },
                @{ Name = "Variant";               Value = 0 },
                @{ Name = "VariantPayload";        Value = 0 },
                @{ Name = "VariantPayloadKind";    Value = 0 }
            )

            $ObfuscateId = Obfuscate-FeatureId $f
            
            # FeatureConfigurationPriorityUserPolicy  = 0Ah
            $PolicyPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides"

            # FeatureConfigurationPriorityUser  = 0x8
            $UserPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\8\$($ObfuscateId)"

            if ($Action -eq "Reset") {
                try {
                    
                    if ($Log) {
                        Write-Warning "Remove Path: $UserPath"
                    }
                    Remove-Item -Path $UserPath -Recurse -Force -ErrorAction SilentlyContinue

                    # Also, remove any remains's if exist, in Policy Key
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

        [Uint32]$CurState = 0;
        $ret = $RTL::RtlGetSystemBootStatus(
            $ConfigurationState,
            ([ref]$CurState),
            0x04, [IntPtr]::Zero
        )
        if ($ret -eq 0xC0000034) {
            $ret = $RTL::RtlCreateBootStatusDataFile([IntPtr]::Zero)
            if ($ret -ne 0) {
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
function Get-FeatureObjectFromPtr {
    param(
        [IntPtr]$Pointer,
        [byte[]]$Buffer
    )

    if ($Buffer) {
        # Use managed byte array
        $fId   = [BitConverter]::ToInt32($Buffer, 0)
        $flags = [BitConverter]::ToInt32($Buffer, 4)
        $vPay  = [BitConverter]::ToInt32($Buffer, 8)
    } else {
        # Use unmanaged memory
        $fId   = [Marshal]::ReadInt32($Pointer, 0)
        $flags = [Marshal]::ReadInt32($Pointer, 4)
        $vPay  = [Marshal]::ReadInt32($Pointer, 8)
    }
    
    $StateLookup = @{
        0 = 'Default'
        1 = 'Disable'
        2 = 'Enable'
    }
    $rawEnabledState = ($flags -shr 4) -band 0x3
    $Info = [Activator]::CreateInstance([RTL_FEATURE_INFO])

    $rawState = ($flags -shr 4) -band 0x3
    $EnabledState = if ($StateLookup.ContainsKey($rawState)) { $StateLookup[$rawState] } else { "N/A" }

    $Info.FeatureId           = [uint32]$fId
    $Info.FlagsRaw            = '0x{0:X8}' -f $flags
    $Info.Priority            = $flags -band 0xF
    $Info.EnabledState        = $EnabledState
    $Info.IsWexpConfiguration = [bool](($flags -shr 6) -band 0x1)
    $Info.HasSubscriptions    = [bool](($flags -shr 7) -band 0x1)
    $Info.Variant             = ($flags -shr 8) -band 0x3F
    $Info.VariantPayloadKind  = ($flags -shr 14) -band 0x3
    $Info.VariantPayload      = '0x{0:X8}' -f [uint32]$vPay
    $Info.Reserved            = ($flags -shr 16) -band 0xFFFF
    $Info.EnabledStateOptions = if (($flags -shr 6) -band 0x1) { 0x01 } else { 0x00 }

    return $Info
}
function Query-KernelFeatureState {
    param (
        [ValidateSet("Boot", "Runtime")]
        [String]$Store = "Runtime",
        [Int32[]]$Feature,
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
        $results = [List[RTL_FEATURE_INFO]]::new()

        try {
            $ms.Position = 0x04 # Skip count header
            while ($ms.Position -lt $ms.Length) {
                $entry = $br.ReadBytes(0x0C)
                if ($Feature -and ([BitConverter]::ToInt32($entry, 0) -notin $Feature)) { continue }
                $featureObj = (Get-FeatureObjectFromPtr -Buffer $entry)
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
A look at new changes to everyone’s favorite A/B system
https://medium.com/@thebookisclosed/visiting-vibranium-velocity-f1ae76253c67

Enter build 18963
Among the features this build introduces are these two: FconWritesToWNF and FconWritesToRTL. Here’s a quick rundown of the terminology used in these names.

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

    $functions = @(
        @{
            Name       = "NtQueryWnfStateData";
            Dll        = "ntdll.dll";
            ReturnType = [Int32]; # NTSTATUS
            Parameters = [Type[]]@(
                [UInt64].MakeByRefType(), # WNF State Name
                [Int64],                  # TypeId (optional)
                [Int64],                  # Explicit Scope
                [UInt32].MakeByRefType(), # ChangeStamp
                [IntPtr],                 # Buffer
                [UInt32].MakeByRefType()  # BufferSize
            )
        },
        @{
            Name       = "NtUpdateWnfStateData";
            Dll        = "ntdll.dll";
            ReturnType = [Int32]; # NTSTATUS
            Parameters = [Type[]]@(
                [UInt64].MakeByRefType(), # WNF State Name
                [IntPtr],                 # Buffer
                [UInt32],                 # Length
                [UInt32].MakeByRefType(), # TypeId
                [UInt64],                 # Nothing
                [UInt32],                 # ChangeStamp
                [UInt32]                  # Optional
            )
        }
    )
    $Global:wnf = Register-NativeMethods $functions
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
        [marshal]::StructureToPtr(
            $update, $Buffer, $true
        )

        for ($i=0; $i -lt $Count; $i++) {
            $featureEntry = [Activator]::CreateInstance([Type]'WNF_FEATURE_ENTRY')
            $featureEntry.FeatureId = [UInt32]$Feature[$i]
            $featureEntry.PackedBits = [UInt32]($StateValue -shl 8) # ServiceState at bits 8-9
            $featureEntry.Payload = 0
            [Marshal]::StructureToPtr(
                $featureEntry, 
                ([IntPtr]::Add($Buffer, 16 + ($i * 12))), 
                $true
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
$Feature = 57517687, 58755790, 59064570

Write-Host "RTL, Mode: Enable" -ForegroundColor Green -NoNewline

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