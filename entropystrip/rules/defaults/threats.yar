/*
    EntropyStrip Curated Incident Triage YARA Rules
    Detects prominent threat stagers, crypters, loaders, and ransomware primitives.
*/

rule CobaltStrike_Beacon_Indicators
{
    meta:
        description = "Cobalt Strike beacon staging strings and default named pipes"
        author = "EntropyStrip Curated"
        score = 50
        severity = "critical"
        mitre = "T1071.001"
    strings:
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide nocase
        $pipe2 = "\\\\.\\pipe\\status_" ascii wide nocase
        $pipe3 = "\\\\.\\pipe\\postex_" ascii wide nocase
        $ua1 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1;" ascii
        $ua2 = "%s.4444.%s" ascii
        $cmd1 = "%C2_SERVER%" ascii
    condition:
        2 of ($pipe*) or any of ($ua*) or $cmd1
}

rule Ransomware_ShadowCopy_Tampering
{
    meta:
        description = "Commands commonly executed by ransomware to inhibit system recovery"
        author = "EntropyStrip Curated"
        score = 45
        severity = "high"
        mitre = "T1490"
    strings:
        $vss1 = "vssadmin" ascii wide nocase
        $vss2 = "delete shadows" ascii wide nocase
        $wmic1 = "wmic" ascii wide nocase
        $wmic2 = "shadowcopy delete" ascii wide nocase
        $bcd1 = "bcdedit" ascii wide nocase
        $bcd2 = "bootstatuspolicy ignoreallfailures" ascii wide nocase
        $bcd3 = "recoveryenabled no" ascii wide nocase
        $wb1 = "wbadmin delete catalog" ascii wide nocase
    condition:
        ($vss1 and $vss2) or ($wmic1 and $wmic2) or ($bcd1 and ($bcd2 or $bcd3)) or $wb1
}

rule Suspicious_Process_Spawning_Primitives
{
    meta:
        description = "Obfuscated process spawning and download cradle commands"
        author = "EntropyStrip Curated"
        score = 35
        severity = "medium"
        mitre = "T1059.001"
    strings:
        $ps1 = "powershell -enc" ascii wide nocase
        $ps2 = "powershell -encodedcommand" ascii wide nocase
        $ps3 = "powershell.exe -w hidden -enc" ascii wide nocase
        $cu1 = "certutil -urlcache -split -f" ascii wide nocase
        $bits1 = "bitsadmin /transfer" ascii wide nocase
        $mshta1 = "mshta vbscript:Execute" ascii wide nocase
        $mshta2 = "mshta javascript:" ascii wide nocase
    condition:
        any of them
}

rule Reflective_DLL_Injection_Signature
{
    meta:
        description = "Reflective DLL injection export and loader signature"
        author = "EntropyStrip Curated"
        score = 40
        severity = "high"
        mitre = "T1055.001"
    strings:
        $s1 = "ReflectiveLoader" ascii
        $s2 = "?ReflectiveLoader@@" ascii
        $s3 = "reflective_dll" ascii wide nocase
    condition:
        any of them
}

rule Shellcode_EggHunter_Signature
{
    meta:
        description = "Egg hunter shellcode search stub"
        author = "EntropyStrip Curated"
        score = 45
        severity = "high"
        mitre = "T1055"
    strings:
        // x86 egg hunter marker search (NtAccessCheck / NtDisplayString loop)
        $egg_stub = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E }
        $w00t = "w00tw00t" ascii
        $c0d3 = "c0d3c0d3" ascii
    condition:
        $egg_stub or $w00t or $c0d3
}
