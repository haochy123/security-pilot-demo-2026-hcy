package com.demo.controller;

/**
 * 文件接口 —— 虚拟工单系统附件下载
 * ⚠️ 试点Demo专用，含【故意埋入】漏洞。
 */
public class FileController {

    /**
     * 【埋点5 - 任意文件读取/路径穿越】未校验文件名，../ 可跳出目录
     * 触发引擎：Semgrep
     */
    public byte[] downloadAttachment(String filename) {
        String path = "/data/ticket/attachments/" + filename;
        return FileUtils.readAllBytes(path);
    }
}
