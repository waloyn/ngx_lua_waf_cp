local _M = {
    name = "Command Injection",
    desc = "检测到可能的命令执行行为",
    level = "high",
    position = "uri,body,cookie,user-agent",
    rules = {
        {
            pattern = [[(?:exec|system|passthru|shell_exec|proc_open|popen)\s*\(]],
            name = "PHP Functions",
            confidence = 3
        },
        {
            pattern = [[(?:os\.system|os\.popen|subprocess\.Popen|subprocess\.call|subprocess\.run)\s*\(|\beval\s*\(|\bexec\s*\(]],
            name = "Python Functions",
            confidence = 3
        },
        {
            pattern = [[(?:system|exec|popen|spawn|IO\.popen|IO\.sysopen)\s*\(|\beval\s*\(]],
            name = "Ruby Methods",
            confidence = 3
        },
        {
            pattern = [=[\b(?:system|exec)\s*\(|\bopen\s*\(\s*[\\'"/$|&;]|\beval\s*[\{\(]]=],
            name = "Perl Functions",
            confidence = 3
        },
        {
            pattern = [[Runtime\.getRuntime\s*\(|new\s+ProcessBuilder\s*\(]],
            name = "Java Methods",
            confidence = 3
        },
        {
            pattern = [=[\beval\s*[\(\{]]=],
            name = "General Eval Functions",
            confidence = 2
        },
        {
            pattern = [[(?:[|]{2}|&&|[|](?![|]))\s*(?:id|whoami|uname|ls|cat|curl|wget|nc|bash|sh|perl|python|php|powershell|cmd|net|rm|kill|chmod|ping)\b|\$\(\s*(?:id|whoami|uname|ls|cat|curl|wget|nc|bash|sh|perl|python|php|powershell|cmd|net|rm|kill|chmod|ping)\b|`\s*(?:id|whoami|uname|ls|cat|curl|wget|nc|perl|python|php|powershell|cmd|net|rm|kill|chmod|ping)\b]],
            name = "Shell Operators and Command Substitution",
            confidence = 2
        },
        {
            pattern = [[(?:^|[^a-zA-Z0-9_])(?:id|sh|bash|cat|whoami|uname|netstat|ifconfig|wget|curl|chmod|chown|find|grep|echo|kill)(?=[\s;|&`$<>(){}\[\]'"]|$)]],
            name = "Common Linux Commands",
            confidence = 2
        },
        {
            pattern = [[(?:/etc/passwd|/etc/shadow|/etc/hosts|/var/log/|/tmp/|/home/)]],
            name = "Common Linux Files",
            confidence = 2
        },
        {
            pattern = [[(?:C:\\Windows\\System32\\drivers\\etc\\hosts|C:\\Windows\\System32\\config\\|C:\\Users\\|C:\\Program Files\\|C:\\Temp\\)]],
            name = "Common Windows Files",
            confidence = 2
        },
        {
            pattern = [[(?:^|[;|&`<>(){}\[\]\s])(?:dir|whoami|systeminfo|tasklist|ipconfig|certutil|powershell|findstr|tracert|nslookup|netsh|wmic)(?=[\s;|&`<>(){}\[\]'"]|$)]],
            name = "Common Windows Commands",
            confidence = 2
        },
        {
            pattern = [=[\b(?:iex|invoke-expression|invoke-webrequest|invoke-restmethod|invoke-command|invoke-item)\b(?:\s+|\s*\()]=],
            name = "PowerShell Invoke Cmdlets",
            confidence = 3
        },
        {
            pattern = [[\bnew-object\s+(?:net\.webclient|system\.net\.webclient|net\.sockets\.tcpclient|scripting\.filesystemobject)\b]],
            name = "PowerShell New-Object Downloader",
            confidence = 3
        },
        {
            pattern = [[\.(?:downloadstring|downloadfile|downloaddata)\s*\(]],
            name = "PowerShell WebClient Download",
            confidence = 3
        },
        {
            pattern = [=[\b(?:powershell|pwsh)(?:\.exe)?\s+(?:-[a-z]+\s+)*-(?:e|en|enc|ec|encodedcommand)\s+[a-z0-9+/=]{16,}]=],
            name = "PowerShell EncodedCommand",
            confidence = 3
        },
        {
            pattern = [=[\$\([^)]*(?:get-|set-|new-|invoke-|start-|stop-|out-|write-|read-)[a-z]+]=],
            name = "PowerShell Subexpression with Cmdlet",
            confidence = 3
        },
        {
            pattern = [=[\b(?:bash|sh|zsh|ksh)\s+-c\s+['"][^'"]+['"]]=],
            name = "Shell -c Command Execution",
            confidence = 3
        },
        {
            -- ${IFS} 单独出现即为攻击特征；PATH/HOME/USER/SHELL 展开需紧跟命令字符（避免模板文本 ${user} 误报）
            pattern = [[\$\{IFS\}|\$\{(?:PATH|HOME|USER|SHELL)(?::[\d:-]+)?\}(?=[a-zA-Z/.\-_$])|\$IFS\$\d]],
            name = "Shell Variable Bypass",
            confidence = 3
        },
        {
            pattern = [[\b(?:bash|sh|zsh)\s+-i\s+>&|/dev/(?:tcp|udp)/\d{1,3}\.\d{1,3}|\bnc(?:\.traditional)?\s+(?:-[a-z]*e\s+|-[a-z]*c\s+)]],
            name = "Reverse Shell Payload",
            confidence = 3
        }
    }
}

return _M
