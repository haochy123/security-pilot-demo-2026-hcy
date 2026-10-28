package com.demo.controller;

/**
 * 用户接口 —— 虚拟工单系统「内部工单系统」
 * ⚠️ 本文件为安全审核试点Demo专用，代码中【故意埋入】多个安全漏洞供扫描引擎识别。
 */
public class UserController {

    private UserDao userDao = new UserDao();

    /**
     * 【埋点1 - SQL注入】使用字符串拼接构造SQL语句
     * 触发引擎：Semgrep（auto规则库）
     */
    public User login(String username, String password) {
        String sql = "SELECT * FROM users WHERE name = '" + username
                + "' AND password = '" + password + "'";
        return userDao.query(sql);
    }

    /**
     * 【埋点2 - 越权/IDOR】按ID查询工单，未校验工单是否属于当前登录用户
     * 触发引擎：❌ 三个引擎均无法发现 —— 用于演示"工具盲区，必须人工检查"
     */
    public Ticket getTicketById(String ticketId) {
        // 直接用前端传入的ID查询，任何登录用户都可以遍历查看他人工单
        return userDao.findTicket(ticketId);
    }

    /**
     * 【埋点3 - XSS】将用户输入原样拼接到HTML响应中返回
     * 触发引擎：Semgrep
     */
    public String search(String keyword) {
        return "<div>搜索结果：" + keyword + "</div>";
    }

    /**
     * 【埋点4 - 弱口令比较】使用 == 比较密码，且明文存储
     * 触发引擎：Semgrep / 人工检查清单
     */
    public boolean verifyPassword(String input, String stored) {
        return input == stored;
    }
}
