local _M = {
  name = "Path Traversal",
  desc = "检测路径遍历攻击，包括各种编码绕过方式。",
  level = "high",
  position = "uri,body",
  rules = {
    {
      pattern = [[ /\.\./ ]],
      name = "Parent Directory Traversal (/../)",
      confidence = 3
    },
    {
      pattern = [[ \.\./ ]],
      name = "Parent Directory Traversal (../)",
      confidence = 2
    },
    {
      pattern = [[ /\.\.\\|\\\.\./ ]],
      name = "Mixed Slash Traversal",
      confidence = 3
    },
    {
      pattern = [[ (?:\.\./){3,}|(?:\.\.\\){3,} ]],
      name = "Deep Directory Traversal",
      confidence = 3
    },
    {
      pattern = [[ /etc/(?:passwd|shadow|group|hosts|sudoers|crontab|profile|bashrc|issue)|/proc/self/ ]],
      name = "Linux Sensitive File Access",
      confidence = 3
    },
    {
      pattern = [[ (?:c:|C:)(?:\\|/)(?:windows|winnt|boot\.ini|inetpub) ]],
      name = "Windows Sensitive Path Access",
      confidence = 3
    },
    {
      pattern = [[ \\\\[\w.]+\\(?:c\$|admin\$|ipc\$) ]],
      name = "Windows UNC Admin Share Access",
      confidence = 3
    },
    {
      pattern = [[ (?:file|netdoc):///|jar:file:// ]],
      name = "File Protocol Access",
      confidence = 2
    },
    {
      pattern = [[ (?:\\u002e\\u002e|\\u002E\\u002E)(?:\\u002f|\\u005c|/|\\) ]],
      name = "Unicode-Encoded Traversal",
      confidence = 3
    },
    {
      pattern = [[ (?:\.\.;/|\.\.%u2215|\.\.%u2216) ]],
      name = "Non-standard Unicode/Semicolon Traversal",
      confidence = 3
    },
    {
      -- 引擎已在 UnEscapeUri 阶段把 %XX 解码为字节，因此规则匹配解码后的字面字节序列
      -- \xc0\xaf = overlong UTF-8 for '/'; \xc1\x9c = overlong UTF-8 for '\'
      pattern = [[ \.\.\xc0\xaf|\.\.\xc1\x9c ]],
      name = "Overlong UTF-8 Traversal (decoded)",
      confidence = 3
    }
  }
}

return _M
