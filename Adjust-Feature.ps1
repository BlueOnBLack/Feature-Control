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
@ https://github.com/abbodi1406/ConsumerESU

# Struct Size 32 byte's, for x86 & x64
# 8 Properties, SizeOf Int32, [8x4] Format
# So, only set few thing's to just Enable & Disable

__int64 __fastcall RtlSetFeatureConfigurations(_QWORD *a1, int a2, const void *a3, unsigned __int64 a4)
v8 = 32i64 * (unsigned int)a4;

[marshal]::WriteInt32($update, 0x00, [int]$FeatureId)      # FeatureId            // Provide by user
[marshal]::WriteInt32($update, 0x04, [int]$Priority)       # Priority             // 0x08
[marshal]::WriteInt32($update, 0x08, [int]$EnabledState)   # EnabledState         // 0x01 = Dis, 0x02 = Ena
[marshal]::WriteInt32($update, 0x1C, [int]$Operation)      # CONFIG.. OPERATION   // 0x01 -bor 0x02 // 0x04
#>
function Adjust-Feature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uint32[]]$FeatureIds,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Enable","Disable", "Reset")]
        [string]$State,

        [switch]$Global
    )
    $results = $False
    $Priority = if ($Global) { 0x0a } else { 0x08 }
    $BootPending = 0x01
    $ConfigurationState = 0x11
    $OperationType = if ($State -match "Enable|Disable") { 0x01 -bor 0x02 } else { 0x04 }
    $EnabledState = if ($State -eq 'Enable') { 0x02 } elseif ($State -eq 'Disable') { 0x01 } else { 0x00 }

    if (!([Security.Principal.WindowsIdentity]::GetCurrent().Groups.Value -contains "S-1-5-32-544")) {
        Write-Error "User doesn't belong to Administrator's group"
        return
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
            [int]     $Operation = 0x0,
            [int]     $BlockSize = 0x20
        )

        $Offset = $BaseOffset + ($BlockSize * $Index)
        [marshal]::WriteInt32($UpdatePackage, $Offset + 0x00, $FeatureId)           # 0x00 - FeatureId
        [marshal]::WriteInt32($UpdatePackage, $Offset + 0x04, $Priority)            # 0x04 - Priority
        [marshal]::WriteInt32($UpdatePackage, $Offset + 0x08, $EnabledState)        # 0x08 - EnabledState
        [marshal]::WriteInt32($UpdatePackage, $Offset + 0x0C, $EnabledStateOptions) # 0x0C - EnabledStateOptions
        [marshal]::WriteInt32($UpdatePackage, $Offset + 0x10, $VariantFlags)        # 0x10 - VariantFlags
        [marshal]::WriteInt32($UpdatePackage, $Offset + 0x14, $VariantPayloadKind)  # 0x14 - VariantPayloadKind
        [marshal]::WriteInt32($UpdatePackage, $Offset + 0x18, $VariantPayload)      # 0x18 - VariantPayload
        [marshal]::WriteInt32($UpdatePackage, $Offset + 0x1C, $Operation)           # 0x1C - Operation
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
            @('RtlCreateBootStatusDataFile',  'ntdll.dll', [Int32], @([IntPtr])),
            @('RtlQueryFeatureConfiguration', 'ntdll.dll', [Int32], @([Int], [Int], [Int].MakeByRefType(), [IntPtr])),
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
        $PayloadSize = 0x20 * $Count
        $updatePackage = [marshal]::AllocHGlobal($Offset.BaseSize + $PayloadSize)
        (0..((($Offset.BaseSize + $PayloadSize)/0x04)-1)) | % {
            [Marshal]::WriteInt32($updatePackage, ($_*0x04), 0x00)
        }
        
        $PreviousStamp = try { $RTL::RtlQueryFeatureConfigurationChangeStamp() } catch { 0x00 }
        [marshal]::WriteInt64($updatePackage, $Offset.PrevStamp, $PreviousStamp)       # Previous Stamp / 0x00 / RtlQueryFeatureConfigurationChangeStamp
        [marshal]::WriteInt32($updatePackage, $Offset.FlagType, 0x01)                  # RunTime = 0x1
        [marshal]::WriteInt32($updatePackage, $Offset.Count, $Count)                   # Feature Id Total Count

        $idx = -1;
        foreach ($Feature in $FeatureIds) {
            $ConfigObj = $null
            if ($State -eq "Reset") {
                [Int32]$changeStamp = 0
                [IntPtr]$ConfigPtr = [Marshal]::AllocHGlobal(0x0A)
                $ret = $RTL::RtlQueryFeatureConfiguration(
                        [Int32]$Feature,
                        0x01,
                        ([ref]$changeStamp),
                        $ConfigPtr
                    )
                try {
                    if ($ret -eq 0) {
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
                                                        0x01  # IsWexpConfiguration ? TRUE  -> FeatureEnabledStateOptionsWexpConfig
                                                    } else {
                                                        0x00  # IsWexpConfiguration ? FALSE -> FeatureEnabledStateOptionsNone
                                                    }
                        }
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

        $ret = $RTL::NtSetSystemInformation(
            [Int64]210,
            $updatePackage,
            ($Offset.BaseSize + $PayloadSize)
        )
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
            $targetPathGlobal = "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides"
            $targetPathUser   = "HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\$($Priority)\$($ObfuscateId)"

            if ($State -eq "Reset") {
                try {
                    Remove-Item -Path $targetPathUser -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $targetPathGlobal -Name $ObfuscateId -ErrorAction SilentlyContinue
                }
                catch {}
            }
            if ($State -match "Enable|Disable") {
                $targetPath = if ($Global) { $targetPathGlobal } else { $targetPathUser }
                New-Item -Path $targetPath -Force -ErrorAction Stop | Out-Null
                if ($Global) {
                    Set-ItemProperty -Path $targetPath -Name $ObfuscateId -Value ([int]$EnabledState) -Type DWord -ErrorAction Stop
                } else {
                    foreach ($property in $properties) {
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

Adjust-Feature -FeatureId @(48796508) -State Enable
Adjust-Feature -FeatureId @(48796508) -State Disable
Adjust-Feature -FeatureId @(48796508) -State Reset
Adjust-Feature -FeatureId @(48796508) -State Reset