# 安全扫描统一报告

**扫描对象**：虚拟工单系统 ticket-demo　**发现总数**：23 个问题

## 按问题等级分布

| 等级 | 数量 | 说明 |
|---|---|---|
| P0 | 8 | 阻断上线 |
| P1 | 9 | 本迭代内必须修复 |
| P2 | 6 | 下迭代修复 |
| P3 | 0 | 跟踪观察 |

## 按引擎分布

| 引擎 | 发现数 | 覆盖范围 |
|---|---|---|
| Semgrep(代码) | 11 | 注入/XSS/硬编码等代码缺陷 |
| Trivy(依赖) | 7 | 第三方依赖已知CVE |
| 密钥扫描 | 5 | 代码及Git历史中的密钥泄露 |

## 问题明细（按等级排序）

| 等级 | 引擎 | 规则/编号 | 文件 | 行号 | 问题摘要 |
|---|---|---|---|---|---|
| P0 | Trivy(依赖) | CVE-2021-44228 | pom.xml | 0 | log4j-core: Remote code execution in Log4j 2.x |
| P0 | Trivy(依赖) | CVE-2021-45046 | pom.xml | 0 | log4j-core: RCE DoS vulnerability |
| P0 | Trivy(依赖) | CVE-2017-18349 | pom.xml | 0 | fastjson: Remote code execution via deserialization |
| P0 | 密钥扫描 | company-cloud-access-key | src/main/java/com/demo/service/TicketService.java (commit a1b2c3d4) | 15 | 公司云平台AccessKey泄露 |
| P0 | 密钥扫描 | internal-api-secret | src/main/java/com/demo/service/TicketService.java (commit a1b2c3d4) | 21 | 内网API密钥泄露 |
| P0 | 密钥扫描 | payment-merchant-key | src/main/resources/application.properties (commit a1b2c3d4) | 9 | 第三方支付商户密钥泄露 |
| P0 | 密钥扫描 | prod-db-password | src/main/resources/application.properties (commit a1b2c3d4) | 5 | 生产数据库口令硬编码 |
| P0 | 密钥扫描 | company-cloud-access-key | src/main/resources/secret.properties (commit f0e1d2c3) | 1 | 公司云平台AccessKey泄露（Git历史提交） |
| P1 | Semgrep(代码) | java.lang.security.audit.sqli.jdbc-sql-injection.jdbc-sql-injection | src/main/java/com/demo/controller/UserController.java | 14 | Detected SQL statement that is tainted by user-input. This could lead to SQL injection. |
| P1 | Semgrep(代码) | hardcoded-password | src/main/java/com/demo/service/TicketService.java | 9 | 检测到硬编码密码，应移到环境变量或密钥管理服务 |
| P1 | Semgrep(代码) | hardcoded-cloud-access-key | src/main/java/com/demo/service/TicketService.java | 15 | 检测到硬编码云平台AccessKey（AKID开头），属于P0级密钥泄露 |
| P1 | Semgrep(代码) | mybatis-sql-injection | src/main/resources/mapper/UserMapper.xml | 8 | MyBatis使用 ${} 直接拼接SQL，存在SQL注入风险，应改为 #{} 预编译参数 |
| P1 | Semgrep(代码) | mybatis-sql-injection | src/main/resources/mapper/UserMapper.xml | 14 | MyBatis使用 ${} 直接拼接SQL，存在SQL注入风险，应改为 #{} 预编译参数 |
| P1 | Trivy(依赖) | CVE-2022-25845 | pom.xml | 0 | fastjson: Remote code execution via deserialization of crafted JSON |
| P1 | Trivy(依赖) | CVE-2019-12384 | pom.xml | 0 | jackson-databind: deep nesting array wrapper deserialization DoS |
| P1 | Trivy(依赖) | CVE-2019-14540 | pom.xml | 0 | jackson-databind: deserialization of untrusted data leads to RCE |
| P1 | Trivy(依赖) | CVE-2015-7501 | pom.xml | 0 | commons-collections: InvokerTransformer deserialization RCE |
| P2 | Semgrep(代码) | generic.path-traversal.open | src/main/java/com/demo/controller/FileController.java | 13 | Potential path traversal: unsanitized input used in file path construction. |
| P2 | Semgrep(代码) | generic.xss.reflected-xss | src/main/java/com/demo/controller/UserController.java | 30 | User input from keyword is returned in HTML response without escaping, potential reflected XSS. |
| P2 | Semgrep(代码) | password-string-equality | src/main/java/com/demo/controller/UserController.java | 37 | 使用==比较字符串（密码场景），应使用常量时间比较 |
| P2 | Semgrep(代码) | sensitive-data-in-log | src/main/java/com/demo/service/TicketService.java | 28 | 疑似在日志中打印手机号等个人信息，应脱敏后再输出 |
| P2 | Semgrep(代码) | insecure-random-for-token | src/main/java/com/demo/util/TokenUtil.java | 13 | 安全敏感场景使用java.util.Random（可预测），应使用SecureRandom |
| P2 | Semgrep(代码) | java.lang.security.audit.cipher-ecb.cipher-ecb | src/main/java/com/demo/util/TokenUtil.java | 23 | Detected ECB mode usage, which provides no semantic security. |

## 安全门禁结论

❌ **门禁不通过**：存在 8 个P0问题，阻断上线。

> ⚠️ 注意：工具扫描存在盲区（如越权/IDOR、业务逻辑漏洞），P0门禁通过不代表可以跳过人工检查清单。