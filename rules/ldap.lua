local _M = {
    name = "Ldap Injection",
    desc = "检测是否存在可能绕过LDAP安全控制的字符串形式。",
    level = "high",
    position = "uri,body,cookie,user-agent,headers",
    rules = {
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
    }
}

return _M
