local _M = {
    name = "Spring Boot",
    desc = "Spring Boot敏感路径检测。",
    level = "medium",
    position = "uri",
    rules = {
        {
          -- 末尾用 (?=...) 限制边界，放行 /health、/healthcheck 和 /info 等常规监控探针，防止 K8s/Nginx 探针误杀
          pattern = [[ /actuator(?:/auditLog|/auditevents|/autoconfig|/beans|/caches|/conditions|/configurationMetadata|/configprops|/dump|/env|/events|/exportRegisteredServices|/features|/flyway|/heapdump|/httptrace|/hystrix\.stream|/integrationgraph|/jolokia|/logfile|/loggers|/loggingConfig|/liquibase|/metrics|/mappings|/scheduledtasks|/swagger-ui\.html|/prometheus|/refresh|/registeredServices|/releaseAttributes|/resolveAttributes|/sessions|/springWebflow|/shutdown|/sso|/ssoSessions|/statistics|/status|/threaddump|/trace)(?=[\s/"'?#]|$) ]],
          name = "Actuator Path Access",
          confidence = 2
        },
        {
          -- 原分支 /api(?:...|/v2/api-docs) 使 /v2/api-docs 不可达；拆出为独立分支并补 /v3/api-docs
          pattern = [[ (?:/api/(?:index\.html|swagger-ui\.html)|/v2/api-docs|/v3/api-docs) ]],
          name = "API Documentation Access",
          confidence = 2
        },
        {
          pattern = [[ /druid(?:/index\.html|/login\.html|/websession\.html)?(?=[\s/"'?#]|$) ]],
          name = "Druid Path Access",
          confidence = 2
        },
        {
          pattern = [[ /heapdump(?:\.json)?(?=[\s/"'?#]|$) ]],
          name = "Heapdump Path Access",
          confidence = 3
        },
        {
          pattern = [[ /swagger-ui ]],
          name = "Swagger UI Path Access",
          confidence = 2
        },
        {
          pattern = [[ /swagger(?:/codes|/index\.html|/static/index\.html|/swagger-ui\.html)?(?=[\s/"'?#]|$) ]],
          name = "Swagger Path Access",
          confidence = 2
        },
    }
  }

  return _M
