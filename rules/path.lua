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
    }
  }
}

return _M
