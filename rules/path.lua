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
      confidence = 1
    },
    {
      pattern = [[ /\.\.\\|\\\.\./ ]],
      name = "Mixed Slash Traversal",
      confidence = 3
    },
    {
      pattern = [[ \.\.%2f|%2e%2e/|%2e%2e%2f ]],
      name = "URL Encoded Traversal",
      confidence = 3
    },
    {
      pattern = [[ \.\.%5c|%2e%2e\\|%2e%2e%5c ]],
      name = "URL Encoded Backslash Traversal",
      confidence = 3
    },
    {
      pattern = [[ (?:%252e%252e|%25252e%25252e)(?:%252f|%25252f|/) ]],
      name = "Double URL Encoded Traversal",
      confidence = 3
    },
    {
      pattern = [[ \.\.%c0%af|\.\.%c1%9c|%c0%ae%c0%ae ]],
      name = "UTF-8 Overlong Encoding Traversal",
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
      pattern = [[ (?:c:|C:)(?:\\|%5c)(?:windows|winnt|boot\.ini|inetpub) ]],
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
