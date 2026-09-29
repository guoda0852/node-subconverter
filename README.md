# 节点订阅转换

纯前端静态网站：把代理节点订阅在不同客户端格式之间转换。

## 功能

- **输入**：粘贴订阅内容（整体 Base64 或每行一个节点链接），或填写订阅链接经 CORS 代理抓取
- **解析协议**：ss、ssr、vmess、vless、trojan、hysteria2 / hy2
- **输出格式**：
  - Clash / Mihomo（YAML）
  - sing-box（JSON）
  - Surge（conf）
  - Quantumult X
  - Loon
  - 通用 Base64 订阅
- 一键复制 / 下载转换结果
- 全部转换在浏览器本地完成，不经过服务器

## 本地预览

```bash
cd node-subconverter
python3 -m http.server 8000
# 浏览器打开 http://localhost:8000
```

## 部署

推送到 GitHub 后在仓库 Settings → Pages 中启用即可（纯静态页面，无需构建）。
