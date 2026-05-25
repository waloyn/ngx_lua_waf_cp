local _M = {
  name = "XXE",
  desc = "检测是否存在通过XML实体加载外部资源的漏洞。",
  level = "high",
  position = "uri,body",
  rules = {
    {
      pattern = [[ <!ENTITY\s+.+> ]],
      name = "Generic ENTITY Declaration",
      confidence = 2
    },
    {
      pattern = [[ <!DOCTYPE\s+.+\[ ]],
      name = "DOCTYPE Declaration",
      confidence = 2
    },
    {
      pattern = [[ <!ENTITY\s+.+\s+SYSTEM\s+['\"].+['\"]\s*> ]],
      name = "SYSTEM Entity Declaration",
      confidence = 3
    },
    {
      pattern = [[ <!ENTITY\s+.+\s+PUBLIC\s+['\"].+['\"]\s+['\"].+['\"]\s*> ]],
      name = "PUBLIC Entity Declaration",
      confidence = 2
    },
    {
      pattern = [[ <!ENTITY\s+%\s+\S+\s+SYSTEM\s+['\"] ]],
      name = "Parameter Entity Declaration",
      confidence = 3
    },
    {
      pattern = [[ SYSTEM\s+['\"](?:expect|php|file|jar|netdoc|gopher|dict|ftp|http|https)://[^'\"]+['\"] ]],
      name = "XXE External Resource Loading",
      confidence = 3
    },
    {
      pattern = [[ <!ENTITY\s+%\s+\S+\s+['\"]%[^'\"]+;%[^'\"]+;['\"] ]],
      name = "Blind XXE Parameter Entity Chain",
      confidence = 3
    }
  }
}

return _M
