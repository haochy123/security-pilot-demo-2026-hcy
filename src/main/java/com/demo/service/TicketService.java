package com.demo.service;

/**
 * 工单服务 —— 虚拟工单系统
 * ⚠️ 试点Demo专用，含【故意埋入】漏洞。
 */
public class TicketService {

    /**
     * 【埋点8 - 硬编码数据库密码】
     * 触发引擎：Semgrep / 密钥扫描引擎
     */
    private static final String DB_PASSWORD = "P@ssw0rd_prod_2026";

    /**
     * 【埋点9 - 硬编码云平台AccessKey】
     * 触发引擎：密钥扫描引擎（自定义规则 company-access-key）
     */
    private static final String OSS_ACCESS_KEY = "AKIDtGk9F7qZx2LmNoPqRsTuVwXyZ123456";

    /**
     * 【埋点10 - 硬编码内网API密钥】
     * 触发引擎：密钥扫描引擎（自定义规则 internal-api-secret）
     */
    private static final String INTERNAL_API_SECRET = "internal-secret-9f8e7d6c5b4a3f2e1d";

    /**
     * 【埋点11 - 日志打印敏感信息】将用户手机号明文写入日志
     * 触发引擎：Semgrep / 人工检查清单（个人信息保护）
     */
    public void logUserOperation(String userId, String phone) {
        System.out.println("用户 " + userId + "（手机号 " + phone + "）执行了工单操作");
    }
}
