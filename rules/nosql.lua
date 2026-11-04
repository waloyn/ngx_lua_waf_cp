local _M = {
    name = "NoSQL Injection",
    desc = "检测NoSQL数据库（MongoDB、Redis、Memcached等）的注入攻击。",
    level = "high",
    position = "uri,body",
    rules = {
        -- MongoDB 注入（具体规则先于通用操作符规则，避免引擎“文件内首个命中即停”导致置信度降档）
        {
            pattern = [[ (?:\$where\s*["']?\s*:\s*["']?(?:function|this\.)) ]],
            name = "MongoDB $where JavaScript Injection",
            confidence = 3
        },
        {
            -- 兼容 JSON 引号键（"$gt":）、数组参数（$ne]=）与裸写（$ne:）三种形态
            pattern = [=[ \$(?:where|gt|gte|lt|lte|ne|in|nin|exists|type|mod|regex|text|all|size|elemMatch|meta|slice|comment|rand|natural|maxTimeMS|maxScan|explain)(?:\s*["'\]]*\s*[:=]|$) ]=],
            name = "MongoDB Operator Injection",
            confidence = 2
        },
        {
            pattern = [[ (?:db\.[\w]+\.(?:find|insert|update|remove|drop|aggregate|mapReduce)) ]],
            name = "MongoDB Shell Command",
            confidence = 3
        },
        {
            pattern = [[ \{\s*["']?\$(?:or|and|not|nor)\s*["']?\s*:\s*\[ ]],
            name = "MongoDB Logical Operator Injection",
            confidence = 3
        },
        {
            pattern = [[ sleep\s*\(\s*\d+\s*\)|(?:new\s+)?Date\s*\(\s*\)|ISODate\s*\( ]],
            name = "MongoDB Time-based Injection",
            confidence = 2
        },
        {
            pattern = [[ ObjectId\s*\(\s*["'][0-9a-fA-F]{24}["']\s*\) ]],
            name = "MongoDB ObjectId Manipulation",
            confidence = 1
        },
        -- Redis 注入。
        -- 上下文约定（防误报）：无参数命令（FLUSHALL/SAVE/INFO 等）只允许出现在串首/行首（严格）；
        -- 带参数命令（CONFIG SET x、DEBUG SEGFAULT、SET k 0 0 5 等）才额外允许 / _ = ? & ; 前缀，
        -- 避免 ?action=stats、/api/version、/info 这类正常路径/参数命中。
        {
            pattern = [[ (?:^|[\r\n])\s*(?:FLUSHALL(?:\s|$)|FLUSHDB(?:\s|$)|SHUTDOWN(?:\s|$)|BGSAVE(?:\s|$)|BGREWRITEAOF(?:\s|$)|SAVE(?=\s*[\r\n]|$))|(?:^|[\r\n]|[/_=?&;])\s*(?:EVAL\s+\S+|EVALSHA\s+\S+|SCRIPT\s+(?:LOAD|FLUSH|EXISTS|KILL)|CONFIG\s+(?:SET|GET)\s+(?:dir|dbfilename|requirepass|appendonly|appendfilename|save|maxmemory|maxmemory-policy|bind|port|logfile|slaveof|maxclients|protected-mode|rename-command|client-output-buffer-limit|replicaof)\b|CONFIG\s+(?:REWRITE|RESETSTAT)\b|DEBUG\s+(?:SEGFAULT|SLEEP|OBJECT|JMAP|SET-ACTIVE-EXPIRE)|SLAVEOF\s+\S+|REPLICAOF\s+\S+) ]],
            name = "Redis Dangerous Command",
            confidence = 3
        },
        {
            pattern = [[ (?:^|[\r\n]|[/_=?&;])\s*(?:SET|GET|DEL|KEYS|HSET|HGET|LPUSH|RPUSH|SADD|SMEMBERS|ZADD|ZRANGE)\s+\S*\* ]],
            name = "Redis Wildcard Command",
            confidence = 2
        },
        {
            pattern = [[ (?:^|[\r\n])\s*(?:INFO(?=\s*[\r\n]|$)|MONITOR(?=\s*[\r\n]|$))|(?:^|[\r\n]|[/_=?&;])\s*(?:CLIENT\s+(?:LIST|KILL|GETNAME|SETNAME|PAUSE|REPLY|NO-EVICT|NO-TOUCH)|CLUSTER\s+(?:INFO|NODES|SLOTS|SHARDS|MYID|MEET|FORGET|REPLICATE)|SLOWLOG\s+(?:GET|LEN|RESET)|ACL\s+(?:WHOAMI|LIST|CAT|GETUSER|SETUSER|USERS)) ]],
            name = "Redis Administrative Command",
            confidence = 2
        },
        -- Memcached 注入（无参数命令严格行首，带参数形态允许路径/参数前缀）
        {
            pattern = [[ (?:^|[\r\n])\s*(?:stats(?=\s*[\r\n]|$)|version(?=\s*[\r\n]|$)|flush_all(?:\s|$)|quit(?=\s*[\r\n]|$))|(?:^|[\r\n]|[/_=?&;])\s*(?:set\s+\S+\s+\d+|add\s+\S+\s+\d+|replace\s+\S+\s+\d+|append\s+\S+\s+\d+|prepend\s+\S+\s+\d+|cas\s+\S+\s+\d+|delete\s+\S+|incr\s+\S+|decr\s+\S+|touch\s+\S+|slabs\s+(?:reassign|automove)|lru_crawler\s+\S+) ]],
            name = "Memcached Command Injection",
            confidence = 2
        },
        -- CouchDB 注入
        {
            pattern = [[ (?:_all_docs|_design|_view|_update|_show|_list|_rewrite) ]],
            name = "CouchDB Special Endpoint",
            confidence = 2
        },
        -- Elasticsearch 注入，排除类似ico_search的正常业务
        {
            pattern = [[ /(?:_search|_msearch|_bulk|_mapping|_settings|_analyze|_nodes|_cluster|_stats|_cat)(?:/|\?|$) ]],
            name = "Elasticsearch API Endpoint",
            confidence = 1
        },
        {
            pattern = [[ (?:"script"\s*:\s*\{|"inline"\s*:\s*"|"source"\s*:\s*") ]],
            name = "Elasticsearch Script Injection",
            confidence = 3
        }
    }
}

return _M
