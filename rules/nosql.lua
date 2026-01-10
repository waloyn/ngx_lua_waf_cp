local _M = {
    name = "NoSQL Injection",
    desc = "检测NoSQL数据库（MongoDB、Redis、Memcached等）的注入攻击。",
    level = "high",
    position = "uri,body",
    rules = {
        -- MongoDB 注入
        {
            pattern = [[\$(?:where|gt|gte|lt|lte|ne|in|nin|exists|type|mod|regex|text|all|size|elemMatch|meta|slice|comment|rand|natural|maxTimeMS|maxScan|explain)(?:\s*:|$)]],
            name = "MongoDB Operator Injection",
            confidence = 3
        },
        {
            pattern = [[(?:\$where\s*:\s*["']?function|\$where\s*:\s*["']?this\.)]],
            name = "MongoDB $where JavaScript Injection",
            confidence = 3
        },
        {
            pattern = [[(?:db\.[\w]+\.(?:find|insert|update|remove|drop|aggregate|mapReduce))]],
            name = "MongoDB Shell Command",
            confidence = 3
        },
        {
            pattern = [[\{\s*["']?\$(?:or|and|not|nor)\s*["']?\s*:\s*\[]],
            name = "MongoDB Logical Operator Injection",
            confidence = 3
        },
        {
            pattern = [[sleep\s*\(\s*\d+\s*\)|(?:new\s+)?Date\s*\(\s*\)|ISODate\s*\(]],
            name = "MongoDB Time-based Injection",
            confidence = 2
        },
        {
            pattern = [[ObjectId\s*\(\s*["'][0-9a-fA-F]{24}["']\s*\)]],
            name = "MongoDB ObjectId Manipulation",
            confidence = 1
        },
        -- Redis 注入
        {
            pattern = [[(?:^|\s)(?:EVAL|EVALSHA|SCRIPT|CONFIG|DEBUG|FLUSHALL|FLUSHDB|SHUTDOWN|SLAVEOF|REPLICAOF|BGSAVE|BGREWRITEAOF|SAVE)(?:\s|$)]],
            name = "Redis Dangerous Command",
            confidence = 3
        },
        {
            pattern = [[(?:^|\s)(?:SET|GET|DEL|KEYS|HSET|HGET|LPUSH|RPUSH|SADD|SMEMBERS|ZADD|ZRANGE)(?:\s.*\*|\s+\*)(?:\s|$)]],
            name = "Redis Wildcard Command",
            confidence = 2
        },
        {
            pattern = [[(?:^|\s)(?:INFO|CLIENT|CLUSTER|SLOWLOG|MONITOR|ACL)(?:\s|$)]],
            name = "Redis Administrative Command",
            confidence = 2
        },
        -- Memcached 注入
        {
            pattern = [[(?:^|\s)(?:stats|version|flush_all|quit|set|add|replace|append|prepend|cas|delete|incr|decr|touch|slabs|lru_crawler)(?:\s|$)]],
            name = "Memcached Command Injection",
            confidence = 2
        },
        -- CouchDB 注入
        {
            pattern = [[(?:_all_docs|_design|_view|_update|_show|_list|_rewrite)]],
            name = "CouchDB Special Endpoint",
            confidence = 2
        },
        -- Elasticsearch 注入
        {
            pattern = [[(?:_search|_msearch|_bulk|_mapping|_settings|_analyze|_nodes|_cluster|_stats|_cat)]],
            name = "Elasticsearch API Endpoint",
            confidence = 2
        },
        {
            pattern = [[(?:"script"\s*:\s*\{|"inline"\s*:\s*"|"source"\s*:\s*")]],
            name = "Elasticsearch Script Injection",
            confidence = 3
        }
    }
}

return _M
