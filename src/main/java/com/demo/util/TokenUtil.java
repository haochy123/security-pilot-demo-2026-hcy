package com.demo.util;

import java.util.Random;

/**
 * 工具类 —— 虚拟工单系统
 * ⚠️ 试点Demo专用，含【故意埋入】漏洞。
 */
public class TokenUtil {

    /**
     * 【埋点6 - 不安全的随机数】会话令牌使用 java.util.Random，可预测
     * 触发引擎：Semgrep（自定义规则 insecure-random）
     */
    public static String generateSessionToken() {
        Random random = new Random();
        return Long.toHexString(random.nextLong());
    }

    /**
     * 【埋点7 - 弱加密】使用ECB模式 + 静态初始化向量
     * 触发引擎：Semgrep
     */
    public static byte[] encrypt(byte[] data) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
        return cipher.doFinal(data);
    }
}
