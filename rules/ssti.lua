local _M = {
    name = "SSTI",
    desc = "检测服务端模板注入攻击（Server-Side Template Injection），支持多种模板引擎。",
    level = "high",
    position = "uri,body",
    rules = {
        -- Jinja2/Twig/Django 模板注入
        {
            pattern = [[\{\{\s*(?:config|self|request|cycler|joiner|namespace|lipsum|range|dict|url_for|get_flashed_messages|session|g|app)\s*(?:\.|}})]],
            name = "Jinja2/Flask Object Access",
            confidence = 3
        },
        {
            pattern = [[\{\{\s*['"]?[^{}]*['"]?\.__(?:class|mro|base|bases|subclasses|init|globals|builtins|import)__]],
            name = "Python Magic Method Access",
            confidence = 3
        },
        {
            pattern = [[\{\{[^\r\n]*?\}\}[^\r\n]*?\{\%[^\r\n]*?\%\}|\{\%[^\r\n]*?\%\}[^\r\n]*?\{\{[^\r\n]*?\}\}]],
            name = "Jinja2 Mixed Syntax",
            confidence = 2
        },
        {
            pattern = [[\{\%\s*(?:for|if|block|extends|include|import|from|set|macro|call|filter|raw|autoescape)\s+]],
            name = "Jinja2 Control Structure",
            confidence = 2
        },
        -- Twig 特定语法
        {
            pattern = [[\{\{\s*(?:_self|_context|app|dump|include|source|parent|block)\s*(?:\(|\.|\|)]],
            name = "Twig Function/Object Access",
            confidence = 3
        },
        -- Smarty 模板注入
        {
            pattern = [[\{\s*(?:php|literal|foreach|if|include|section|capture|assign|eval)(?:\s+|})|\{/(?:php|literal|foreach|if|section|capture)\}]],
            name = "Smarty Template Tag",
            confidence = 3
        },
        -- Velocity 模板注入
        {
            pattern = [[#(?:set|if|elseif|else|end|foreach|include|parse|stop|macro|evaluate)\s*\(|\$(?:class|request|response|session|application)\.]],
            name = "Velocity Template Syntax",
            confidence = 3
        },
        -- Freemarker 模板注入
        {
            pattern = [[\$\{(?:\.data_model|\.globals|\.locals|\.main|\.namespace|\.current_template_name|object\s*\()|\<\#(?:assign|import|include|setting|function|macro|attempt)\s+]],
            name = "Freemarker Template Syntax",
            confidence = 3
        },
        {
            pattern = [[freemarker\.template\.utility\.Execute|freemarker\.template\.utility\.ObjectConstructor]],
            name = "Freemarker Dangerous Class",
            confidence = 3
        },
        -- Thymeleaf 模板注入
        {
            pattern = [[th:(?:text|utext|value|href|src|action|object|each|if|unless|switch|with|remove|insert|replace|fragment|assert)=]],
            name = "Thymeleaf Attribute",
            confidence = 2
        },
        {
            pattern = [[\$\{T\s*\(\s*(?:java\.lang\.|org\.springframework\.)|\__\$\{[^}]{1,100}\}__]],
            name = "Thymeleaf SpEL Injection",
            confidence = 3
        },
        -- Pebble 模板注入
        {
            pattern = [[\{\{\s*(?:beans|request|response|session|applicationContext)\s*\.|\{\%\s*(?:import|from|macro|block|filter|set)\s+]],
            name = "Pebble Template Injection",
            confidence = 3
        },
        -- Go Text/HTML Template
        {
            pattern = [[\{\{\s*(?:template|define|block|range|with|if|else|end|and|or|not|len|index|slice|printf|print|html|js|urlquery)\s+]],
            name = "Go Template Syntax",
            confidence = 2
        },
        -- Handlebars/Mustache
        {
            pattern = [[\{\{\{[^}]*?\}\}\}|\{\{(?:#|\/|>|!|else|unless|with|lookup|log)\s*]],
            name = "Handlebars/Mustache Syntax",
            confidence = 1
        },
        -- ERB (Ruby)
        {
            pattern = [[<\%=?\s*(?:system|exec|eval|`|require|load|open|IO\.|File\.|Dir\.)|\%>]],
            name = "ERB Ruby Code Injection",
            confidence = 3
        },
        -- 通用 SSTI 探测 payload
        {
            pattern = [[\{\{\s*[0-9]+\s*[\+\-\*\/]\s*[0-9]+\s*\}\}|\{\{\s*['"][^'"]*['"]\s*\*\s*[0-9]+\s*\}\}]],
            name = "SSTI Arithmetic Probe",
            confidence = 3
        }
    }
}

return _M
