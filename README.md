# 安全审核试点Demo：三引擎扫描流水线

在企业真实项目上落地前，用本虚拟项目验证「三引擎 + 自定义规则 + 结果归一化 + P0门禁」整套机制可行。

## 一、方案架构

```
代码提交（push）
   │
   ├── 引擎1 Semgrep ──────→ SAST代码扫描（注入/XSS/硬编码/弱加密）+ 自定义规则
   ├── 引擎2 密钥扫描 ──────→ 当前代码 + Git全历史密钥泄露 + 自定义AK规则
   ├── 引擎3 Trivy ────────→ pom.xml第三方依赖已知CVE
   │
   └──→ normalize.py 归一化（统一schema + P0~P3分级 + 去重）
            │
            ├── unified_report.csv / security_summary.md（统一报告）
            └── P0存在 → 流水线红灯 = 阻断上线（安全门禁）
```

**分工与盲区**：三个引擎各管一摊，但**均无法发现越权/IDOR和业务逻辑漏洞**——项目里故意埋了一个越权接口（`UserController.getTicketById`），三个引擎都会漏报，用于向领导论证「人工检查清单不可替代」。

## 二、虚拟项目埋点清单（15处）

| # | 漏洞 | 位置 | 负责引擎 |
|---|---|---|---|
| 1 | SQL注入（字符串拼接） | UserController.login | Semgrep |
| 2 | **越权/IDOR（工具盲区）** | UserController.getTicketById | ❌ 无人能扫出 |
| 3 | 反射型XSS | UserController.search | Semgrep |
| 4 | 弱口令比较（==） | UserController.verifyPassword | Semgrep |
| 5 | 路径穿越 | FileController.downloadAttachment | Semgrep |
| 6 | 不安全随机数（令牌） | TokenUtil.generateSessionToken | Semgrep(自定义) |
| 7 | ECB弱加密 | TokenUtil.encrypt | Semgrep |
| 8 | 硬编码DB密码 | TicketService | Semgrep(自定义)+密钥 |
| 9 | 硬编码云AccessKey | TicketService | 密钥(自定义AKID规则) |
| 10 | 硬编码内网API密钥 | TicketService | 密钥(自定义) |
| 11 | 日志打印手机号 | TicketService.logUserOperation | Semgrep(自定义) |
| 12-13 | MyBatis ${}注入×2 | UserMapper.xml | Semgrep(自定义) |
| 14 | 配置文件DB口令 | application.properties | 密钥 |
| 15 | 支付商户密钥 | application.properties | 密钥 |
| +4 | 依赖CVE（log4j/fastjson/jackson/commons-collections） | pom.xml | Trivy |
| +1 | Git历史泄露密钥 | 历史commit（脚本制造） | 密钥 |

> ⚠️ pom.xml 中的依赖版本是**故意埋入的漏洞版本，仅用于演示**，禁止用于真实项目。

## 三、使用步骤（约15分钟）

1. **创建GitHub仓库**并推送本项目：
   ```bash
   git init && git add -A && git commit -m "init: ticket demo"
   git remote add origin https://github.com/<你的用户名>/security-pilot-demo.git
   git push -u origin main
   ```
2. **制造Git历史泄露**（在任意有git的机器，或GitHub网页版Codespaces终端执行）：
   ```bash
   sh scripts/seed-git-history.sh
   git push
   ```
3. push后自动触发Actions（或到Actions页手动Run workflow）。
4. 查看结果：流水线将**红灯失败**（存在P0）→ 进入本次运行页面下载 `security-report` 产物，内含：
   - `security_summary.md` —— 统一汇总报告（一张表看完所有问题）
   - `unified_report.csv` —— 明细（可用Excel打开）
   - 三个引擎的原始JSON

## 四、本地预览（不依赖GitHub）

`scripts/samples/` 目录下有按埋点预制的三引擎样例输出，直接运行即可预览统一报告：

```bash
cd scripts/samples
python3 ../normalize.py .
```

## 五、等级映射与门禁标准（对齐《安全审核工作流程设计》）

| 原始严重度 | 映射等级 | 处置要求 |
|---|---|---|
| CRITICAL / 密钥泄露 | P0 | 阻断上线，立即修复 |
| HIGH / Semgrep ERROR | P1 | 本迭代内必须修复 |
| MEDIUM / WARNING | P2 | 下一迭代修复 |
| LOW / INFO | P3 | 跟踪观察 |

门禁逻辑：`normalize.py` 发现P0即退出码1 → CI红灯 → 阻断上线。映射关系在脚本头部 `SEV_TO_P` 表中维护，企业标准变化时只改一处。

## 六、扩展说明

- **密钥引擎可替换**：流水线用gitleaks实现密钥扫描；如改用其他引擎（如Betterleaks），把 `.gitleaks.toml` 中的正则规则迁移到对应引擎配置，替换workflow中该步骤即可，整体结构不变。
- **规则即资产**：`.semgrep/rules.yml` 和 `.gitleaks.toml` 中的自定义规则沉淀的是企业安全知识（公司AK格式、内网密钥格式、MyBatis规范），试点后应随审核经验持续补充。
- **真实项目接入**：把 `.github/workflows/security-scan.yml`、`.semgrep/`、`.gitleaks.toml`、`scripts/normalize.py` 四件套复制到真实项目仓库即可复用。
