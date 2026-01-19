local _M = {
    name = "Command Injection",
    desc = "检测到可能的命令执行行为",
    level = "high",
    position = "uri,body",
    rules = {
        {
            pattern = [[(exec|system|passthru|shell_exec|proc_open|popen)\s*\(]],
            name = "PHP Functions",
            confidence = 3
        },
        {
            pattern = [[(os\.system|os\.popen|subprocess\.Popen|subprocess\.call|subprocess\.run)\s*\(|\beval\s*\(|\bexec\s*\(]],
            name = "Python Functions",
            confidence = 3
        },
        {
            pattern = [[(system|exec|popen|spawn|IO\.popen|IO\.sysopen)\s*\(|\beval\s*\(]],
            name = "Ruby Methods",
            confidence = 3
        },
        {
            pattern = [[\b(system|exec)\s*\(|\bopen\s*\((?!.*\bid\b)|\beval\s*[\{\(]]],
            name = "Perl Functions",
            confidence = 3
        },
        {
            pattern = [[Runtime\.getRuntime\s*\(|new\s+ProcessBuilder\s*\(]],
            name = "Java Methods",
            confidence = 3
        },
        {
            pattern = [[\beval\s*[\(\{]]],
            name = "General Eval Functions",
            confidence = 2
        },
        {
            pattern =
            [[(exec|system|passthru|shell_exec|proc_open|popen|os\.system|os\.popen|subprocess\.Popen|subprocess\.call|subprocess\.run|Runtime\.getRuntime|ProcessBuilder)\s*[\(]]],
            name = "Command Execution Function Calls",
            confidence = 3
        },
        {
            pattern = [[([|][|]|&(?=&)|\n|\r)]],
            name = "Logical Operators and Newline Characters",
            confidence = 2
        },
        {
            pattern = [[(?:^|[^a-zA-Z0-9_])(cat|whoami|uname|netstat|ifconfig|wget|curl|chmod|chown|find|grep|echo|kill)(?=[\s;|&`$<>(){}\[\]'"]|$)]],
            name = "Common Linux Commands",
            confidence = 1
        },
        {
            pattern = [[(/etc/passwd|/etc/shadow|/etc/hosts|/var/log/|/tmp/|/home/)]],
            name = "Common Linux Files",
            confidence = 2
        },
        {
            pattern =
            [[(C:\\Windows\\System32\\drivers\\etc\\hosts|C:\\Windows\\System32\\config\\|C:\\Users\\|C:\\Program Files\\|C:\\Temp\\)]],
            name = "Common Windows Files",
            confidence = 2
        },
        {
            pattern =
            [[(?:^|[;|&`<>(){}\[\]\s])(dir|whoami|systeminfo|tasklist|ipconfig|certutil|powershell|findstr|tracert|nslookup|netsh|wmic)(?=[\s;|&`<>(){}\[\]'"]|$)]],
            name = "Common Windows Commands",
            confidence = 1
        }
    }
}

return _M
