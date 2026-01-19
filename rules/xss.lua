local _M = {
    name = "XSS",
    desc = "XSS是一种常见的攻击手段，通过在输入框中输入JavaScript代码，获取用户的Cookie信息。",
    level = "medium",
    position = "uri,body",
    rules = {
      {
        pattern = [[ <script\b[^>]*>[\s\S]*?</script> ]],
        name = "Script Tag Injection",
        confidence = 3
      },
      {
        pattern = [[ <iframe\b[^>]*>[\s\S]*?</iframe> ]],
        name = "Iframe Tag Injection",
        confidence = 3
      },
      {
        pattern = [[ <object\b[^>]*>[\s\S]*?</object> ]],
        name = "Object Tag Injection",
        confidence = 3
      },
      {
        pattern = [[ <embed\b[^>]*>[\s\S]*?</embed> ]],
        name = "Embed Tag Injection",
        confidence = 3
      },
      {
        pattern = [[ <style\b[^>]*>[\s\S]*?</style> ]],
        name = "Style Tag Injection",
        confidence = 3
      },
      {
        pattern = [[ <link\b[^>]*(?:href|src)\s*=[\s\S]*?> ]],
        name = "Link Tag Injection",
        confidence = 3
      },
      {
        pattern = [[ \bjavascript:[^\s<>"']+ ]],
        name = "Javascript URI",
        confidence = 3
      },
      {
        pattern = [[ data:text/html ]],
        name = "Data URI",
        confidence = 2
      },
      {
        pattern = [[ vbscript:[^<]+ ]],
        name = "VBScript URI",
        confidence = 2
      },
      {
        pattern =  [[(?i)<[a-zA-Z/!][^>]*[\s/]+on[a-z]+\s*=]],
        name = "Event Handler Injection",
        confidence = 3
      },
      {
        pattern = [[ <(div|a|img)\b[^>]*\s+on[a-z]+\s*=[\s\S]*?>]],
        name = "HTML Tag with Event Handler",
        confidence = 3
      },
      {
        pattern = [[ href\s*=\s*["']?javascript: ]],
        name = "Encoded JavaScript URL",
        confidence = 3
      }
    }
  }

  return _M