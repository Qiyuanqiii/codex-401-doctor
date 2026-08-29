# codex-401-doctor 中文说明

这是一个用于排查 Codex / ChatGPT / GPT 相关 `401 Unauthorized` 问题的本地 Windows PowerShell 工具。

默认只诊断，不修改文件。涉及敏感文件或敏感修改时，必须传参数授权或在提示中输入 `YES`。脚本不会打印 `access_token`、`refresh_token`、cookie 或完整 request ID。

## 能识别的问题类型

| 类型 | 典型信号 | 常见原因 | 是否可自动修 |
|---|---|---|---|
| ChatGPT 登录态被路由到公开 Responses API | `api.responses.write`、`https://api.openai.com/v1/responses` | `config.toml` 选中了自定义 provider，导致 ChatGPT OAuth token 去调用公开 OpenAI API | 可以修本地 config |
| 顶层 openai_base_url 覆盖 | `openai_base_url = "https://api.openai.com/v1"` | ChatGPT OAuth token 被强制打到公开 OpenAI API 路径 | 可以删除该行 |
| ChatGPT backend 未授权 | `chatgpt.com/backend-api/codex/responses` + 401 | 登录态、账号 entitlement、workspace、SSO 或服务端授权不一致 | 不能直接修，只给建议 |
| 请求没带认证头 | `Missing bearer or basic authentication` | Authorization header 丢失、凭证没加载、fallback 请求异常 | 不能直接修，只给建议 |
| 环境变量覆盖 | `OPENAI_API_KEY`、`OPENAI_BASE_URL`、`CODEX_API_KEY`、代理变量存在 | API key、base URL 或代理影响 Codex 默认认证/传输 | 不自动清理，只提醒 |
| 自定义 provider 401 | OpenRouter、Azure、Vercel、Anthropic 等 provider 返回 401 | key、base_url、header、region、deployment 配置错误 | 不自动修第三方配置 |
| token 刷新/过期 | `invalid_token`、`expired`、`refresh token` | `auth.json` 或刷新流程异常 | 建议重新登录 |
| websocket/stream 反复重连 | `responses_websocket`、`stream disconnected`、`falling back to HTTP` | 网络、代理、传输层不稳定，不一定是认证问题 | 不自动改传输 |
| 会话索引损坏 | `session_index.jsonl` 条数明显少于 `sessions/**/*.jsonl` | 本地历史索引丢失或写入中断 | 可以重建索引 |

## 安全策略

脚本不会打印：

- `access_token`
- `refresh_token`
- cookie
- 完整 request ID
- 完整 UUID

敏感操作要求：

| 操作 | 授权方式 |
|---|---|
| 读取 `~/.codex/auth.json` 并解码 JWT payload scope | `-AllowReadAuth` 或手动输入 `YES` |
| 读取 `~/.codex/logs_2.sqlite` 扫日志 | `-AllowReadLogs` 或手动输入 `YES` |
| 修改 `~/.codex/config.toml` | `-FixConfig` 或 `-Fix`，并确认 |
| 重建 `~/.codex/session_index.jsonl` | `-RebuildIndex` 或 `-Fix`，并确认 |

写入前会自动备份。

## 推荐用法

只做基础诊断：

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1
```

完整只读诊断：

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -AllowReadAuth -AllowReadLogs
```

只输出中文：

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -AllowReadAuth -AllowReadLogs -Language zh
```

只输出英文：

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -AllowReadAuth -AllowReadLogs -Language en
```

默认中英文双语：

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -AllowReadAuth -AllowReadLogs -Language both
```

输出 JSON，方便贴 issue：

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -AllowReadAuth -AllowReadLogs -Json
```

查看脚本版本：

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -Version
```

只修复危险 provider 配置：

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -FixConfig
```

重建会话索引：

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -RebuildIndex
```

## 本工具最初针对的问题链路

```text
ChatGPT 登录态 / OAuth token
  + config.toml 选中了自定义 provider:
      base_url = "https://api.openai.com/v1"
      wire_api = "responses"
    或设置了:
      openai_base_url = "https://api.openai.com/v1"
  -> 请求打到公开 OpenAI Responses API
  -> token 没有 api.responses.write scope
  -> 401 Unauthorized
```

脚本会把这种情况判为：

```text
LIKELY_ROOT_CAUSE_SCOPE_MISMATCH
```

并提示可用 `-FixConfig` 删除危险的 `model_provider` 和对应 `[model_providers.xxx]` 段。

相关上游讨论：[openai/codex#31412](https://github.com/openai/codex/issues/31412)。
