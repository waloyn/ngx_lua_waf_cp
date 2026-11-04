local _M = {
    name = "Bot",
    desc = "检测恶意爬虫、漏洞扫描器、自动化攻击工具。",
    level = "medium",
    position = "user-agent",
    rules = {
        {
            pattern = [[ user-agent:\s*(?:go-http|curl|wget|python-requests|libwww-perl|httpclient|python-urllib|http_request|java|scrapy|php|node\.js|mechanize|axios|httpie|okhttp|lua-resty-http|Go-http-client|Jakarta|Apache-HttpClient|libcurl|python-httpx|python-tornado|guzzlehttp|httplib2|perseus|resty|simplepie|typhoeus|aiohttp|http\.client|http\.request|Net::HTTP|HTTPie|PycURL|Requests|httplib|Mechanize|Scrapy|LWP::Simple|RestClient|async-http-client|got|ky|superagent|undici)(?![a-zA-Z0-9]) ]],
            name = "HTTP Client Library",
            confidence = 1
        },
        {
            pattern = [[ user-agent:\s*(?:sqlmap|nikto|nmap|masscan|zmap|nessus|openvas|acunetix|burpsuite|owasp|zaproxy|arachni|w3af|skipfish|wapiti|vega|golismero|xray|nuclei|jaeles|httpx|subfinder|amass|dirsearch|ffuf|gobuster|feroxbuster|wfuzz|dirb|dirbuster)(?![a-zA-Z0-9]) ]],
            name = "Vulnerability Scanner",
            confidence = 3
        },
        {
            pattern = [[ user-agent:\s*(?:havij|pangolin|dbpwaudit|sqlninja|bbqsql|jSQL|sqlsus|mole|bsqlbf|safe3|xenotix|xsser)(?![a-zA-Z0-9]) ]],
            name = "SQL Injection Tool",
            confidence = 3
        },
        {
            pattern = [[ user-agent:\s*(?:hydra|medusa|ncrack|brutus|patator|hashcat|john|aircrack|ophcrack|cain|l0phtcrack|thc)(?![a-zA-Z0-9]) ]],
            name = "Brute Force Tool",
            confidence = 3
        },
        {
            pattern = [[ user-agent:\s*(?:metasploit|meterpreter|cobalt|empire|mimikatz|bloodhound|crackmapexec|impacket|responder|bettercap|ettercap)(?![a-zA-Z0-9]) ]],
            name = "Penetration Testing Framework",
            confidence = 3
        },
        {
            pattern = [[ user-agent:\s*(?:semrush|ahref|mj12|dotbot|petalbot|baiduspider|yandex|sogou|exabot|gigabot|msnbot|teoma|askjeeves|blexbot|seokicks|sistrix|majestic)(?![a-zA-Z0-9]) ]],
            name = "SEO Crawler",
            confidence = 1
        },
        {
            -- 不使用裸 \bbot\b / \bspider\b：会命中 Googlebot UA 中的 "bot.html"（+http://www.google.com/bot.html）
            pattern = [[ user-agent:\s*(?:bot|spider|crawler|scraper|harvest|grab|fetch|extract|collect|download)(?![a-zA-Z0-9]) ]],
            name = "Generic Bot Keyword",
            confidence = 1
        },
        {
            pattern = [[ user-agent:\s*(?:-|""|''|null|undefined|none|test|debug|admin|root|anonymous|\x00|\s{5,})$|^user-agent:\s*$ ]],
            name = "Suspicious/Empty User-Agent",
            confidence = 2
        },
        {
            -- 工具名不在 UA 开头时（伪装成浏览器，如 "... (compatible; Nmap Scripting Engine; ...)"）也能识别；
            -- 仅收录不易与正常 UA 混淆的专有工具名（不含 cobalt/empire 等易误报词）
            pattern = [[ (?:^|[\s;(,:])(?:sqlmap|nikto|nmap|masscan|zmap|nessus|openvas|acunetix|burpsuite|owasp[\s-]*zap|zaproxy|arachni|w3af|skipfish|wapiti|nuclei|jaeles|havij|pangolin|sqlninja|dbpwaudit|jsql|xenotix|xsser|gobuster|feroxbuster|dirsearch|dirbuster|wfuzz|metasploit|meterpreter|mimikatz|bloodhound|crackmapexec|impacket|ettercap|bettercap|ysoserial)(?=[\s;/),:]|$) ]],
            name = "Scanner/Pentest Tool Token (any position)",
            confidence = 3
        }
    }
}

return _M
