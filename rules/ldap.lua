local _M = {
    name = "Ldap Injection",
    desc = "检测是否存在可能绕过LDAP安全控制的字符串形式及JNDI注入。",
    level = "high",
    position = "uri,body,cookie,user-agent,headers",
    rules = {
        -- Log4j2 JNDI 注入
        {
            pattern = [[\$\{jndi:(?:ldap|ldaps|rmi|dns|nis|nds|corba|iiop):]],
            name = "Basic JNDI Injection",
            confidence = 3
        },
        {
            pattern = [[\$\{[^}]*\$\{.*?jndi:]],
            name = "Nested Lookup JNDI Injection",
            confidence = 3
        },
        {
            -- 单字符混淆绕过：${${lower:j}ndi:...} / ${${upper:J}NDI:...} / ${${::-j}ndi:...}
            pattern = [[\$\{[^}]*\$\{[^}]*\}[^}]*ndi\s*:]],
            name = "Obfuscated JNDI (Single-Char Split)",
            confidence = 3
        },
        {
            pattern = [[\$\{(?:[^}]*:.*?)?j\}?\$\{(?:[^}]*:.*?)?n\}?\$\{(?:[^}]*:.*?)?d\}?\$\{(?:[^}]*:.*?)?i\}?:]],
            name = "Split Character JNDI Injection",
            confidence = 3
        },
        {
            pattern = [[j\$\{[^}]*\}n\$\{[^}]*\}d\$\{[^}]*\}i\s*:]],
            name = "Default Value Bypass JNDI Injection",
            confidence = 3
        },
        {
            pattern = [[\$\{(?:lower|upper|env|sys|java|date|bundle|ctx|main|marker|sd|log4j)[^}]*:.*?jndi]],
            name = "Log4j Lookup Bypass JNDI Injection",
            confidence = 3
        },
        -- 经典 Web 应用程序 LDAP 注入
        {
            pattern = [[\(\s*[&|!]\s*\([^)]+=[^)]+\)]],
            name = "LDAP Logical Filter Injection",
            confidence = 3
        },
        {
            pattern = [[(?:\buid|\bcn|\bmail|\buser|\bsAMAccountName)\s*=\s*\*(?:\s*[\w*)]|$)]],
            name = "LDAP Attribute Wildcard Bypass",
            confidence = 3
        },
        {
            pattern = [[\bobject(?:Class|Category)\s*=\s*\*]],
            name = "LDAP ObjectClass Probe",
            confidence = 2
        },
        {
            pattern = [[(?:\x00|%00)(?=[&|();\s]|$)]],
            name = "LDAP Null Byte Injection",
            confidence = 3
        },
    }
}

return _M
