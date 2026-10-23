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
      pattern = [[ \b(?:or|and)\s+[\w'"]+\s*=\s*[\w'"]+ ]],
      name = "Boolean Logic SQL Injection",
      confidence = 2
    },
    {
      pattern = [[ \b(?:union\s+all\s+select|union\s+select|select\s+[\w\*]+\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(?:table|database)|alter\s+table)\b ]],
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
    {
      pattern = [[ ;\s*(?:drop|alter|create|truncate|grant|revoke|rename)\s+(?:table|database|user|schema|view|index|procedure|function) ]],
      name = "Stacked Query DDL",
      confidence = 3
    },
    {
      pattern = [[ (?:utl_http\.|utl_inaddr\.|utl_smtp\.|dbms_pipe\.|dbms_ldap\.|xp_dirtree|xp_fileexist|xp_subdirs|xp_cmdshell|sp_makewebtask|sp_oacreate)\b ]],
      name = "Out-of-Band SQL Injection",
      confidence = 3
    },
    {
      pattern = [[ \b0x[0-9a-f]{16,}\b ]],
      name = "SQL Hex Literal Payload",
      confidence = 2
    },
    {
      pattern = [[ (?:char|chr|ascii|concat|substring|substr|hex|unhex|cast|convert)\s*\(\s*(?:0x[0-9a-f]+|\d+\s*,) ]],
      name = "SQL String Function Obfuscation",
      confidence = 2
    },
  }
}

return _M
