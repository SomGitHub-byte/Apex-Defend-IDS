rule WebShell_Command_Execution
{
    meta:
        description = "Detects webshell command execution parameters in stream"
        severity = "CRITICAL"
        rule_id = "YARA-PAYLOAD-01"
    strings:
        $cmd1 = "cmd.exe" ascii nocase
        $cmd2 = "/bin/bash" ascii nocase
        $cmd3 = "/bin/sh" ascii nocase
        $php1 = "system($_GET[" ascii nocase
        $php2 = "passthru($_POST[" ascii nocase
        $ps1  = "powershell -enc" ascii nocase
    condition:
        any of them
}

rule SQL_Injection_Attempt
{
    meta:
        description = "Detects SQL injection signatures in HTTP/TCP payload"
        severity = "HIGH"
        rule_id = "YARA-PAYLOAD-02"
    strings:
        $sqli1 = "' OR '1'='1" ascii nocase
        $sqli2 = "' OR 1=1--" ascii nocase
        $sqli3 = "UNION SELECT" ascii nocase
        $sqli4 = "waitfor delay '0:0:" ascii nocase
    condition:
        any of them
}

rule Directory_Traversal_LFI
{
    meta:
        description = "Detects Local File Inclusion (LFI) and path traversal"
        severity = "HIGH"
        rule_id = "YARA-PAYLOAD-03"
    strings:
        $lfi1 = "../../../../" ascii
        $lfi2 = "/etc/passwd" ascii nocase
        $lfi3 = "/etc/shadow" ascii nocase
        $lfi4 = "c:\\windows\\win.ini" ascii nocase
    condition:
        any of them
}

rule Log4Shell_JNDI_Exploit
{
    meta:
        description = "Detects Log4j JNDI remote code execution lookup"
        severity = "CRITICAL"
        rule_id = "YARA-PAYLOAD-04"
    strings:
        $jndi1 = "${jndi:ldap://" ascii nocase
        $jndi2 = "${jndi:rmi://" ascii nocase
        $jndi3 = "${jndi:dns://" ascii nocase
    condition:
        any of them
}

rule Plaintext_Sensitive_Credential
{
    meta:
        description = "Detects unencrypted credential transmission"
        severity = "MEDIUM"
        rule_id = "YARA-PAYLOAD-05"
    strings:
        $p1 = "password=" ascii nocase
        $p2 = "passwd=" ascii nocase
        $p3 = "Authorization: Basic" ascii
    condition:
        any of them
}
