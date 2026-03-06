local _M = {
  name = "Sql Injection",
  desc = "SQL注入是一种常见的攻击手段，通过在输入框中输入SQL语句，获取数据库中的数据。",
  level = "high",
  position = "uri,body,cookie",
  rules = {
    {
      pattern = [[ select\s+\S+.*?\s+from\s+\S+ ]],
      name = "Select-From Statement",
      confidence = 3
    },
    {
      pattern = [[ select\s+\S+.*?\s+limit\s+\d+ ]],
      name = "Select-Limit Statement",
      confidence = 3
    },
    {
      pattern = [[ UNION[\s/\*]+SELECT ]],
      name = "Union-Select Statement",
      confidence = 3
    },
    {
      pattern = [[ sleep\s*\(\s*\d+\s*\) ]],
      name = "Sleep Function",
      confidence = 3
    },
    {
      pattern = [[ benchmark\s*\(\s*\d+\s*,\s*[^)]+\) ]],
      name = "Benchmark Function",
      confidence = 3
    },
    {
      pattern = [[ FROM\s+information_schema ]],
      name = "Information Schema Access",
      confidence = 3
    },
    {
      pattern = [[ INTO\s+(?:dump|out)file\s+\S+ ]],
      name = "Into Outfile Statement",
      confidence = 3
    },
    {
      pattern = [[ load_file\s*\(\s*[^)]+\) ]],
      name = "Load File Function",
      confidence = 3
    },
    {
      pattern = [[ (?:\sor\s|\sand\s)[\w]+\s*=\s*[\w'"]+  ]],
      name = "Boolean Logic SQL Injection",
      confidence = 2
    },
    {
      pattern = [[ (?:\sunion\s|\sselect\s|\sinsert\s|\supdate\s|\sdelete\s|\sdrop\s|\salter\s) ]],
      name = "SQL Keywords",
      confidence = 2
    },
    {
      pattern = [[ ORDER\s+BY\s+\d+ ]],
      name = "Order By Column Number Probe",
      confidence = 2
    },
    {
      pattern = [[ WAITFOR\s+DELAY\s+['"] ]],
      name = "MSSQL Time-based Injection",
      confidence = 3
    },
    {
      pattern = [[ ['"]\s*(?:--|#|/\*) ]],
      name = "SQL Comment Truncation",
      confidence = 2
    },
    {
      pattern = [[ HAVING\s+\d+\s*=\s*\d+ ]],
      name = "Having Clause Injection",
      confidence = 3
    },
    {
      pattern = [[ IF\s*\(.*?,.*?(?:SLEEP|BENCHMARK)\s*\( ]],
      name = "Conditional Time-based Injection",
      confidence = 3
    },
    {
      pattern = [[ pg_sleep\s*\(\s*\d+\s*\) ]],
      name = "PostgreSQL Sleep Injection",
      confidence = 3
    },
  }
}

return _M
