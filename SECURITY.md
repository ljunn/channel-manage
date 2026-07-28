# 安全说明

请勿在 Issue 中提交平台密码、API Key、访问令牌或生产地址。安全问题请通过 GitHub Security Advisory 私下报告。

生产部署必须设置不少于 32 字符的 `JWT_SECRET`，使用 HTTPS 反向代理，并保持 `ALLOW_INSECURE_UPSTREAMS=false` 与 `ALLOW_PRIVATE_UPSTREAMS=false`。凭据使用 AES-256-GCM 加密保存；更换加密密钥前必须先完成凭据轮换。
