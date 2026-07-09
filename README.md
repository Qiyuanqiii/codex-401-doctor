# codex-401-doctor

Local Windows PowerShell doctor for diagnosing common Codex / ChatGPT / GPT `401 Unauthorized` failures.

`codex-401-doctor` is report-only by default. It does not print `access_token`, `refresh_token`, cookies, or full request IDs. Sensitive reads and writes require an explicit flag or an interactive `YES` confirmation.

中文说明在下方；也可以直接看 [README.zh-CN.md](README.zh-CN.md)。

## What It Detects

| Type | Signal | Likely cause |
|---|---|---|
| `OPENAI_RESPONSES_SCOPE_MISMATCH` | `api.responses.write`, `https://api.openai.com/v1/responses` | ChatGPT OAuth credentials were routed to the public OpenAI Responses API |
| `OPENAI_BASE_URL_OVERRIDE` | root `openai_base_url = "https://api.openai.com/v1"` | ChatGPT OAuth credentials were forced onto the public OpenAI API path |
| `CHATGPT_BACKEND_UNAUTHORIZED` | `chatgpt.com/backend-api/codex/responses` + 401 | ChatGPT login, entitlement, workspace, SSO, or backend authorization mismatch |
| `MISSING_AUTH_HEADER` | `Missing bearer or basic authentication` | Request was sent without the expected Authorization header |
| `ENV_OVERRIDES_PRESENT` | `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `CODEX_API_KEY`, proxy env vars | Environment variables may override ChatGPT OAuth or affect transport |
| `CUSTOM_PROVIDER_401` | Third-party provider domain + 401 | Custom provider base URL, key, header, region, or deployment mismatch |
| `TOKEN_REFRESH_OR_EXPIRED` | refresh/expired/invalid token messages | Local auth state or token refresh problem |
| `TRANSPORT_RECONNECT_OR_FALLBACK` | websocket disconnect, stream reconnect, HTTP fallback | Network/proxy/transport instability, not always auth |
| `SESSION_INDEX_DEGRADED` | `session_index.jsonl` much smaller than `sessions/**/*.jsonl` | Local history index may be incomplete |

## Safety Model

| Operation | Why sensitive | Required action |
|---|---|---|
| Read `auth.json` | Contains tokens | Pass `-AllowReadAuth` or type `YES` when prompted |
| Read `logs_2.sqlite` | May contain prompts/snippets | Pass `-AllowReadLogs` or type `YES` when prompted |
| Edit `config.toml` | Changes Codex behavior | Pass `-FixConfig` or `-Fix`, then confirm unless `-AssumeYes` |
| Rebuild `session_index.jsonl` | Reads session metadata and writes index | Pass `-RebuildIndex` or `-Fix`, then confirm unless `-AssumeYes` |

Backups are created before writing.

## Common Commands

Report only:

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1
```

Full read-only diagnosis:

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -AllowReadAuth -AllowReadLogs
```

Chinese-only output:

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -AllowReadAuth -AllowReadLogs -Language zh
```

English-only output:

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -AllowReadAuth -AllowReadLogs -Language en
```

JSON output:

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -AllowReadAuth -AllowReadLogs -Json
```

Fix only the dangerous `api.openai.com/v1` + `wire_api = "responses"` provider mismatch:

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -FixConfig
```

Rebuild the local session index:

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -RebuildIndex
```

Run against a custom Codex home:

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -CodexHome "C:\Users\you\.codex" -AllowReadAuth -AllowReadLogs
```

## What It Can Repair

The script can repair local, deterministic issues:

- remove a root `openai_base_url = "https://api.openai.com/v1"` override that conflicts with ChatGPT OAuth.
- remove a selected dangerous custom provider such as:

```toml
model_provider = "openai-http"

[model_providers.openai-http]
base_url = "https://api.openai.com/v1"
wire_api = "responses"
requires_openai_auth = true
```

- rebuild `session_index.jsonl` from the first `session_meta` line of local session files.

It does not repair server-side account entitlement, SSO workspace access, subscription state, or third-party provider API-key permission issues. For those, it reports the likely category and next steps.

## Chinese / 中文说明

`codex-401-doctor` 是一个用于排查 Codex / ChatGPT / GPT 相关 `401 Unauthorized` 问题的本地 Windows PowerShell 工具。

默认只诊断，不修改文件。脚本不会打印 `access_token`、`refresh_token`、cookie 或完整 request ID。读取敏感文件、修改配置、重建索引前，都需要传参授权或在提示中输入 `YES`。

## 能识别的问题类型

| 类型 | 典型信号 | 常见原因 |
|---|---|---|
| ChatGPT 登录态被路由到公开 Responses API | `api.responses.write`、`https://api.openai.com/v1/responses` | `config.toml` 选中了自定义 provider，导致 ChatGPT OAuth token 去调用公开 OpenAI API |
| 顶层 openai_base_url 覆盖 | `openai_base_url = "https://api.openai.com/v1"` | ChatGPT OAuth token 被强制打到公开 OpenAI API 路径 |
| ChatGPT backend 未授权 | `chatgpt.com/backend-api/codex/responses` + 401 | 登录态、账号 entitlement、workspace、SSO 或服务端授权不一致 |
| 请求没带认证头 | `Missing bearer or basic authentication` | Authorization header 丢失、凭证没加载、fallback 请求异常 |
| 环境变量覆盖 | `OPENAI_API_KEY`、`OPENAI_BASE_URL`、`CODEX_API_KEY`、代理变量存在 | API key、base URL 或代理影响 Codex 默认认证/传输 |
| 自定义 provider 401 | OpenRouter、Azure、Vercel、Anthropic 等 provider 返回 401 | key、base_url、header、region、deployment 配置错误 |
| token 刷新/过期 | `invalid_token`、`expired`、`refresh token` | `auth.json` 或刷新流程异常 |
| websocket/stream 反复重连 | `responses_websocket`、`stream disconnected`、`falling back to HTTP` | 网络、代理、传输层不稳定，不一定是认证问题 |
| 会话索引损坏 | `session_index.jsonl` 条数明显少于 `sessions/**/*.jsonl` | 本地历史索引丢失或写入中断 |

## 推荐用法

完整只读诊断：

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -AllowReadAuth -AllowReadLogs
```

只输出中文：

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -AllowReadAuth -AllowReadLogs -Language zh
```

默认中英文双语：

```powershell
powershell -ExecutionPolicy Bypass -File .\codex-401-doctor.ps1 -AllowReadAuth -AllowReadLogs -Language both
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

The related upstream discussion is [openai/codex#31412](https://github.com/openai/codex/issues/31412).
