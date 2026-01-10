local _M = {
    name = "Deserialization",
    desc = "检测不安全的反序列化攻击，包括Java/PHP/Python/.NET等平台的反序列化漏洞。",
    level = "high",
    position = "uri,body,cookie",
    rules = {
        -- Java 反序列化
        {
            pattern = [[(?:rO0AB|H4sIA|aced0005)]],
            name = "Java Serialized Object (Base64/Hex)",
            confidence = 3
        },
        {
            pattern = [[org\.apache\.commons\.collections\.(?:Transformer|functors)|org\.apache\.xalan\.xsltc\.trax\.]],
            name = "Java Commons Collections Gadget",
            confidence = 3
        },
        {
            pattern = [[com\.sun\.org\.apache\.(?:xalan|xerces)|javax\.management\.|java\.lang\.Runtime|java\.lang\.ProcessBuilder]],
            name = "Java Dangerous Class",
            confidence = 3
        },
        {
            pattern = [[org\.springframework\.(?:beans|context)|com\.mchange\.v2\.c3p0\.|org\.hibernate\.engine\.]],
            name = "Java Framework Gadget",
            confidence = 3
        },
        {
            pattern = [[ysoserial|JRMPClient|JRMPListener|CommonsCollections[0-9]|Jdk7u21|Groovy1]],
            name = "Ysoserial Payload",
            confidence = 3
        },
        -- PHP 反序列化
        {
            pattern = [[O:\d+:"[^"]+":[\d+:]],
            name = "PHP Serialized Object",
            confidence = 2
        },
        {
            pattern = [[a:\d+:\{(?:s:\d+:|i:\d+;)]],
            name = "PHP Serialized Array",
            confidence = 1
        },
        {
            pattern = [[phar://|php://filter.*convert|data://text/plain]],
            name = "PHP Wrapper Deserialization",
            confidence = 3
        },
        {
            pattern = [[__(?:destruct|wakeup|toString|call|callStatic|get|set|isset|unset|invoke|set_state|clone|debugInfo)\s*\(]],
            name = "PHP Magic Method in Payload",
            confidence = 2
        },
        -- Python 反序列化
        {
            pattern = [[(?:pickle|cPickle|_pickle)\.(?:loads|load|dumps|dump)|__reduce__|__reduce_ex__]],
            name = "Python Pickle Deserialization",
            confidence = 3
        },
        {
            pattern = [[c(?:builtin|posix|nt)\n(?:system|popen|exec|spawn)|cos\nsystem\n]],
            name = "Python Pickle RCE Payload",
            confidence = 3
        },
        {
            pattern = [[yaml\.(?:load|unsafe_load|full_load)\s*\(|!!python/(?:object|module|name)]],
            name = "Python YAML Deserialization",
            confidence = 3
        },
        -- .NET 反序列化
        {
            pattern = [[System\.(?:Data\.DataSet|Windows\.(?:Data|Markup))|Microsoft\.VisualStudio\.|ObjectDataProvider|XamlReader]],
            name = ".NET Dangerous Type",
            confidence = 3
        },
        {
            pattern = [[TypeNameHandling|ObjectCreationHandling|\$type.*System\.]],
            name = ".NET JSON Deserialization",
            confidence = 3
        },
        {
            pattern = [[BinaryFormatter|ObjectStateFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter]],
            name = ".NET Serializer",
            confidence = 2
        },
        {
            pattern = [[__ViewState(?:Encrypted)?=|(?:AAEAAAD|AQAAAA)]],
            name = ".NET ViewState",
            confidence = 2
        },
        -- Ruby 反序列化
        {
            pattern = [[Marshal\.(?:load|restore)|YAML\.(?:load|unsafe_load)|ERB\.new]],
            name = "Ruby Deserialization",
            confidence = 3
        },
        -- Node.js 反序列化
        {
            pattern = [[node-serialize|serialize-javascript|funcster|cryo|_\$\$ND_FUNC\$\$_]],
            name = "Node.js Deserialization",
            confidence = 3
        }
    }
}

return _M
