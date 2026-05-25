local _M = {
    name = "File Upload",
    desc = "检测恶意文件上传行为，包括WebShell、危险脚本文件等。",
    level = "high",
    position = "uri,body",
    rules = {
        {
            pattern = [[filename=["'][^"']*\.(php[0-9]?|phtml|phar|inc|hphp|ctp|module)["']],
            name = "PHP File Upload",
            confidence = 3
        },
        {
            pattern = [[filename=["'][^"']*\.(asp|aspx|asa|asax|ascx|ashx|asmx|cer|cdx|config)["']],
            name = "ASP/ASPX File Upload",
            confidence = 3
        },
        {
            pattern = [[filename=["'][^"']*\.(jsp|jspx|jspa|jsw|jsv|jspf|jtml|jhtml)["']],
            name = "JSP File Upload",
            confidence = 3
        },
        {
            pattern = [[filename=["'][^"']*\.(cgi|pl|py|rb|sh|bash|zsh|ksh|csh)["']],
            name = "Script File Upload",
            confidence = 3
        },
        {
            pattern = [[filename=["'][^"']*\.(htaccess|htpasswd|web\.config)["']],
            name = "Server Config File Upload",
            confidence = 3
        },
        {
            pattern = [[filename=["'][^"']*\.(shtml|stm|shtm|lasso|plx|xslt|hta|htr)["']],
            name = "Other Dangerous File Upload",
            confidence = 3
        },
        {
            pattern = [[filename=["'][^"']*\.(exe|dll|bat|cmd|com|msi|vbs|vbe|js|jse|wsf|wsh|ps1|psm1)["']],
            name = "Windows Executable Upload",
            confidence = 3
        },
        {
            pattern = [[filename=["'][^"']*\.(elf|bin|run|out|so|dylib)["']],
            name = "Linux Executable Upload",
            confidence = 2
        },
        {
            pattern = [[filename=["'][^"']*\.(svg|xml|xsl|xslt|xsd|dtd)["']],
            name = "XML-based File Upload",
            confidence = 1
        },
        {
            pattern = [[Content-Type:\s*(application/x-httpd-php|application/x-php|text/x-php)]],
            name = "PHP Content-Type",
            confidence = 3
        },
        {
            pattern = [[\x00\.(?:jpg|jpeg|png|gif|bmp|ico)]],
            name = "Null Byte Extension Bypass",
            confidence = 3
        },
        {
            pattern = [[filename=["'][^"']*\.(?:jpg|jpeg|png|gif)\.(?:php|asp|jsp|exe)["']],
            name = "Double Extension Attack",
            confidence = 3
        },
        {
            pattern = [[<\?(?:php|=)|<%(?:@|=)?|<%[^>]{1,100}%>]],
            name = "Embedded Script Tags in Upload",
            confidence = 2
        },
        {
            pattern = [[filename\s*=\s*[^"';\s]+\.(?:php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|ashx|exe|sh|bat|cmd|ps1|cgi|pl)(?:[\s;]|$)]],
            name = "Unquoted Dangerous Filename Bypass",
            confidence = 3
        },
        {
            pattern = [[filename\*?\s*=\s*(?:utf-8''|iso-8859-1''|us-ascii'')?[^;]*%(?:00|0a|0d|2e|2f|5c)]],
            name = "RFC 5987 Filename Encoding Bypass",
            confidence = 3
        },
        {
            pattern = [[content-disposition\s*:[^\r\n]*filename[^=]*=[^"'\s]*\.(?:php|jsp|asp|exe|sh)\b]],
            name = "Content-Disposition Filename Bypass",
            confidence = 3
        }
    }
}

return _M
