using namespace System
using namespace System.IO
using namespace System.Reflection
using namespace System.Reflection.Emit
using namespace System.Runtime.InteropServices
using namespace System.Management.Automation

Clear-Host
Write-Host

<#
Based on ViveTool Source code.
namespace --> Albacore.ViVeTool
           
@ Mach2
@ https://github.com/riverar/mach2

@ ViVe \ ViVeTool GUI
@ https://github.com/thebookisclosed/ViVe
@ https://github.com/PeterStrick/ViVeTool-GUI

@ phnt Headers [private]
@ https://github.com/winsiderss/systeminformer
@ https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h

@ Consumer_ESU_Enrollment.ps1
@ https://github.com/abbodi1406/ConsumerESU/blob/master/Consumer_ESU_Enrollment.ps1

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
00000000 FeatureId       dd ?        ; 0x0, 4 bytes ? Feature identifier
00000004 Option          dw ?        ; 0x4, 2 bytes ? packed bitfield of options
00000006 padding         dw ?        ; 0x6, 2 bytes ? alignment padding
00000008 VariantPayload  dd ?        ; 0x8, 4 bytes ? payload value
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

Function Bor {
    param ([int[]] $Array) 
    $ret = $Array[0]
    foreach ($item in $Array) {
        $ret = $ret -bor $item
    }
    return [Int32]$ret
}
function New-Module {
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
function Adjust-Feature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uint32[]]$FeatureIds,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Enable","Disable", "Reset")]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("User", "Policy")]
        [string]$Mode,

        [switch]$SysCall,
        [switch]$Log
    )
    $results = $False
    $BootPending = 0x01
    $ConfigurationState = 0x11
    $Priority = if ($Mode -eq "Policy") {  0x0a } else { 0x08 }
    $OperationType = if ($Action -match "Enable|Disable") { 0x01 -bor 0x02 } else { 0x04 }
    $EnabledState = if ($Action -eq 'Enable') { 0x02 } elseif ($Action -eq 'Disable') { 0x01 } else { 0x00 }

    if (!([Security.Principal.WindowsIdentity]::GetCurrent().Groups.Value -contains "S-1-5-32-544")) {
        Write-Error "User doesn't belong to Administrator's group"
        return
    }

    if (-not ([PSTypeName]'RTL_FEATURE_CONFIGURATION_UPDATE').Type) {
        New-Struct `
            -Module (New-Module -ModuleName RTL_FEATURE_CONFIGURATION_UPDATE) `
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
    function Obfuscate-FeatureId {
        param(
            [uint32]$featureId
        )
        [uint32]$x = [uint32]($featureId -bxor 0x74161A4E)
        $x = [uint32]((($x -shr 16) -bor ($x -shl 16)) -band 0xFFFFFFFF)
        $x = [uint32]((($x -band 0xFF00FF00) -shr 8) -bor (($x -band 0x00FF00FF) -shl 8))
        $x = [uint32]($x -band 0xFFFFFFFF)
        [uint32]$intermediate = [uint32]($x -bxor 0x8FB23D4F)
        [uint32]$rot = [uint32]( (($intermediate -shl 1) -band 0xFFFFFFFF) -bor (($intermediate -shr 31) -band 0x1) )
        $rot = [uint32]($rot -band 0xFFFFFFFF)
        [uint32]$result = [uint32]($rot -bxor 0x833EA8FF)
        return $result
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

        [RTL_FEATURE_CONFIGURATION_UPDATE]$update = [Activator]::CreateInstance([RTL_FEATURE_CONFIGURATION_UPDATE])
        $update.FeatureId           = $FeatureId
        $update.Priority            = $Priority
        $update.EnabledState        = $EnabledState
        $update.PackedOptions       = $VariantPayloadKind
        $update.EnabledStateOptions = [byte]$EnabledStateOptions
        $update.VariantFlags        = $VariantFlags
        $update.VariantPayload      = [uint32]$VariantPayload
        $update.Operation           = $Operation

        [marshal]::StructureToPtr(
            $update,
            ([IntPtr]::Add($UpdatePackage, ($BaseOffset + (0x20 * $Index)))), 
            $true
        )
    }
    try {
        $Module = [AppDomain]::CurrentDomain.GetAssemblies()| ? { $_.ManifestModule.ScopeName -eq "RTL" } | select -Last 1
        $RTL = $Module.GetTypes()[0]
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
            @('RtlQueryFeatureConfigurationChangeStamp', 'ntdll.dll', [Int32], @())
        ) | % {
            $Module.DefinePInvokeMethod(($_[0]), ($_[1]), 22, 1, [Type]($_[2]), [Type[]]($_[3]), 1, 3).SetImplementationFlags(128) # Def` 128, fail-safe 0
        }
        $RTL = $Module.CreateType()
    }

    try {
        
        ## RtlSetFeatureConfigurations in Windows 11, have few change's
        ## Like, 24 as Base size, instead 16, etc, etc.
        ## So, += 0x08 for all offset, Solve the problem.
        
        $Shift = 0x00
        $Build = [System.Environment]::OSVersion.Version.Build
        if ($Build -ge 22000) {
            $Shift += 0x08
        }
        $Offset = [PSObject]@{
            BaseSize   = ( $Shift + 0x10 )
            PrevStamp  = ( $Shift + 0x00 )
            FlagType   = ( $Shift + 0x08 )
            Count      = ( $Shift + 0x0C )
        }

        $Count = $FeatureIds.Count
        $PayloadSize = ((0x20 * $Count)+ 7) -band -bnot 7
        $updatePackage = [marshal]::AllocHGlobal($Offset.BaseSize + $PayloadSize)
        (0..((($Offset.BaseSize + $PayloadSize)/0x08)-1)) | % {
            [Marshal]::WriteInt64($updatePackage, ($_*0x08), 0L)
        }
        
        $PreviousStamp = try { $RTL::RtlQueryFeatureConfigurationChangeStamp() } catch { 0x00 }
        [marshal]::WriteInt64($updatePackage, $Offset.PrevStamp, $PreviousStamp)       # Previous Stamp / 0x00 / RtlQueryFeatureConfigurationChangeStamp
        [marshal]::WriteInt32($updatePackage, $Offset.FlagType, 0x01)                  # RunTime = 0x1
        [marshal]::WriteInt32($updatePackage, $Offset.Count, $Count)                   # Feature Id Total Count

        $idx = -1;
        foreach ($Feature in $FeatureIds) {
            $ConfigObj = $null
            if ($Action -eq "Reset") {
                $changeStamp = 0L
                [IntPtr]$ConfigPtr = [Marshal]::AllocHGlobal(0x0C)
                $hr = $RTL::RtlQueryFeatureConfiguration(
                        [Int32]$Feature,
                        0x01,
                        ([ref]$changeStamp),
                        $ConfigPtr
                    )
                try {
                    if ($hr -eq 0) {
                        $bytes = New-Object byte[] 12
                        [Marshal]::Copy($ConfigPtr, $bytes, 0, 12)
                        $featureId       = [BitConverter]::ToUInt32($bytes, 0x00)
                        $flags           = [BitConverter]::ToUInt32($bytes, 0x04)
                        $variantPayload  = [BitConverter]::ToUInt32($bytes, 0x08)
                        $ConfigObj = [PSCustomObject]@{
                            FeatureId            = $featureId
                            FlagsRaw             = ('0x{0:X8}' -f $flags)
                            Priority             = $flags -band 0xF
                            EnabledState         = ($flags -shr 4) -band 0x3
                            IsWexpConfiguration  = [bool](($flags -shr 6) -band 0x1)
                            HasSubscriptions     = [bool](($flags -shr 7) -band 0x1)
                            Variant              = (($flags -shr 8) -band 0x3F)
                            VariantPayloadKind   = (($flags -shr 14) -band 0x3)
                            VariantPayload       = ('0x{0:X8}' -f $variantPayload)
                            Reserved             = (($flags -shr 16) -band 0xFFFF)
                            Operation            = 0x04
                            EnabledStateOptions  = if ([bool](($flags -shr 6) -band 0x1)) {
                                                        0x01  # IsWexpConfiguration ? TRUE  -> [FeatureEnabledStateOptionsWexpConfig, 1]
                                                    } else {
                                                        0x00  # IsWexpConfiguration ? FALSE -> [FeatureEnabledStateOptionsNone, 0]
                                                    }
                        }

                        # for later, Registry Clean, Cause Problem
                        # if value is 0x0a instead 0x08 ... well
                        $Priority = $ConfigObj.Priority
                    }
                }
                finally {
                    [marshal]::FreeHGlobal($ConfigPtr)
                }
            }
            if ($ConfigObj) {
                Write-FeatureData `
                    -Index (++$idx) `
                    -BaseOffset $Offset.BaseSize `
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
                    -BaseOffset $Offset.BaseSize `
                    -UpdatePackage $updatePackage `
                    -FeatureId $Feature `
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
              ($Offset.BaseSize + $PayloadSize))
        } else {
            $ret = $RTL::RtlSetFeatureConfigurations(
              ([ref]$PreviousStamp),
              0x01,
              ([IntPtr]::Add($updatePackage,$Offset.BaseSize)),
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
        foreach ($Feature in $FeatureIds) {
            $properties = @(
                @{ Name = "EnabledState";          Value = [int]$EnabledState },
                @{ Name = "EnabledStateOptions";   Value = 0 },
                @{ Name = "Variant";               Value = 0 },
                @{ Name = "VariantPayload";        Value = 0 },
                @{ Name = "VariantPayloadKind";    Value = 0 }
            )

            $ObfuscateId = Obfuscate-FeatureId $Feature
            
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

Adjust-Feature `
    -FeatureIds @(57517687, 58755790, 59064570) `
    -Action Enable `
    -Mode User `
    -Log
Write-Host

Adjust-Feature `
    -FeatureIds @(57517687, 58755790, 59064570) `
    -Action Disable `
    -Mode User `
    -Log
Write-Host

Adjust-Feature `
    -FeatureIds @(57517687, 58755790, 59064570) `
    -Action Reset `
    -Mode User `
    -Log
Write-Host