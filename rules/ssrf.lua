local _M = {
  name = "SSRF",
  desc = "检测服务器端请求伪造攻击，包括内网访问、云元数据服务访问等。",
  level = "high",
  position = "uri,body",
  rules = {
    {
      pattern = [[ (?:gopher|doc|php|glob|file|phar|zlib|ftp|ldap|dict|ogg|data|smb|tftp|rsync|telnet|jdbc|rmi|dns|ws|wss|sftp|jar|netdoc|mailto|ssh2):// ]],
      name = "Dangerous Protocol SSRF",
      confidence = 3
    },
    {
      pattern = [[ (?:127\.0\.0\.1|localhost|0\.0\.0\.0|0x7f000001|2130706433|017700000001)(?::|/|$) ]],
      name = "Localhost Access",
      confidence = 3
    },
    {
      pattern = [[ (?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::|/|$) ]],
      name = "Private IP Address Access",
      confidence = 2
    },
    {
      pattern = [[ (?:169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2)(?::|/|$) ]],
      name = "Cloud Metadata Service Access",
      confidence = 3
    },
    {
      pattern = [[ /latest/(?:meta-data|user-data|dynamic|api/token)|/metadata/v1/ ]],
      name = "Cloud Metadata Endpoint",
      confidence = 3
    },
    {
      pattern = [[ (?:::1|::ffff:|fe80::|fc00::|fd00::)(?::|/|$) ]],
      name = "IPv6 Localhost/Private Access",
      confidence = 3
    },
    {
      pattern = [[ (?:http|https)://(?:\d+|\[[\da-f:]+\])(?:/|:|\?) ]],
      name = "Numeric/IPv6 URL Access",
      confidence = 2
    },
    {
      pattern = [[ (?:url|uri|path|file|page|src|href|target|redirect|callback|next|return|goto|link|fetch|load|include)=(?:https?://|//|\\\\|file://|ftp://) ]],
      name = "URL Parameter SSRF",
      confidence = 2
    },
    {
      pattern = [[ @(?:127\.0\.0\.1|localhost|10\.\d|172\.(?:1[6-9]|2\d|3[01])|192\.168)(?::|/|$) ]],
      name = "URL Credential Bypass SSRF",
      confidence = 3
    },
    {
      pattern = [[ (?:\.internal|\.local|\.corp|\.lan|\.home|\.intranet|\.private)(?:/|:|$) ]],
      name = "Internal Domain Access",
      confidence = 2
    }
  }
}

return _M
