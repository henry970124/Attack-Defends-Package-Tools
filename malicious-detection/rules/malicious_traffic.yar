/*
惡意流量偵測規則
*/

rule SQL_Injection_Attack {
    meta:
        description = "偵測SQL注入攻擊"
        severity = "high"
        
    strings:
        $a1 = "union select" nocase
        $a2 = "' or '1'='1" nocase
        $a3 = "'; drop table" nocase
        $a4 = "information_schema" nocase
        $a5 = "exec(char(" nocase
        
    condition:
        any of them
}

rule XSS_Attack {
    meta:
        description = "偵測跨站腳本攻擊"
        severity = "high"
        
    strings:
        $b1 = "<script" nocase
        $b2 = "javascript:" nocase
        $b3 = "document.cookie" nocase
        $b4 = "<iframe" nocase
        $b5 = "onload=" nocase
        
    condition:
        any of them
}

rule Command_Injection {
    meta:
        description = "偵測命令注入攻擊"
        severity = "high"
        
    strings:
        $c1 = "; cat /etc/passwd" nocase
        $c2 = "; ls -la" nocase
        $c3 = "; whoami" nocase
        $c4 = "| nc " nocase
        $c5 = "bash -i" nocase
        
    condition:
        any of them
}

rule Directory_Traversal {
    meta:
        description = "偵測目錄遍歷攻擊"
        severity = "medium"
        
    strings:
        $d1 = "../"
        $d2 = "..\\"
        $d3 = "/etc/passwd"
        $d4 = "/etc/shadow"
        $d5 = "c:\\windows\\system32" nocase
        
    condition:
        any of them
}

rule Malware_Signatures {
    meta:
        description = "偵測惡意軟體特徵"
        severity = "critical"
        
    strings:
        $e1 = "metasploit" nocase
        $e2 = "meterpreter" nocase
        $e3 = "mimikatz" nocase
        $e4 = "cobalt strike" nocase
        $e5 = "empire framework" nocase
        
    condition:
        any of them
}
