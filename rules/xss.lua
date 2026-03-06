local _M = {
    name = "XSS",
    desc = "XSS是一种常见的攻击手段，通过在输入框中输入JavaScript代码，获取用户的Cookie信息。",
    level = "medium",
    position = "uri,body,cookie",
    rules = {
      {
        pattern = [[ <script\b[^>]*> ]],
        name = "Script Tag Injection",
        confidence = 3
      },
      {
        pattern = [[ <iframe\b[^>]*> ]],
        name = "Iframe Tag Injection",
        confidence = 3
      },
      {
        pattern = [[ <object\b[^>]*> ]],
        name = "Object Tag Injection",
        confidence = 3
      },
      {
        pattern = [[ <embed\b[^>]*> ]],
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
        pattern = [[ <[a-zA-Z/!][^>]*[\s/]+on[a-z]+\s*= ]],
        name = "Event Handler Injection",
        confidence = 3
      },
      {
        pattern = [[ href\s*=\s*["']?javascript: ]],
        name = "JavaScript URL in href",
        confidence = 3
      },
      {
        pattern = [[ <svg\b[^>]*> ]],
        name = "SVG Tag Injection",
        confidence = 3
      },
      {
        pattern = [[ <math\b[^>]*> ]],
        name = "MathML Tag Injection",
        confidence = 2
      },
      {
        pattern = [[ <base\b[^>]*href\s*= ]],
        name = "Base Tag Hijacking",
        confidence = 3
      },
      {
        pattern = [[ <meta\b[^>]*http-equiv\s*=\s*["']?refresh[^>]*url\s*= ]],
        name = "Meta Refresh Redirect",
        confidence = 3
      },
    }
  }

  return _M
