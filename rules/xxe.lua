local _M = {
  name = "XXE",
  desc = "检测是否存在通过XML实体加载外部资源的漏洞。",
  level = "high",
  position = "uri,body",
  rules = {
    -- 顺序约定：具体规则在前、泛化规则在后。
    -- 引擎在单个规则文件内“首个命中即停”，泛化规则排前会把 SYSTEM/PUBLIC 等具体命中降档为低置信度。
    {
      pattern = [[ <!ENTITY\s+.+\s+SYSTEM\s+['\"].+['\"]\s*> ]],
      name = "SYSTEM Entity Declaration",
      confidence = 3
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
    },
    {
      pattern = [[ <!ENTITY\s+.+\s+PUBLIC\s+['\"].+['\"]\s+['\"].+['\"]\s*> ]],
      name = "PUBLIC Entity Declaration",
      confidence = 2
    },
    {
      pattern = [[ <!DOCTYPE\s+.+\[ ]],
      name = "DOCTYPE Declaration",
      confidence = 2
    },
    {
      pattern = [[ <!ENTITY\s+.+> ]],
      name = "Generic ENTITY Declaration",
      confidence = 2
    }
  }
}

return _M
