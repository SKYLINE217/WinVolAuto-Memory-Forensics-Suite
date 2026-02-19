rule Suspicious_Strings {
    meta:
        description = "Detects suspicious strings"
        author = "WinVolAuto"
    strings:
        $a = "cmd.exe" nocase
        $b = "powershell" nocase
    condition:
        any of them
}
