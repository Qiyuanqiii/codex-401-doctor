#requires -version 5.1
<#
codex-401-doctor.ps1

Diagnose common Codex 401 Unauthorized failures and optionally repair local,
well-understood misconfigurations. The script never prints access tokens,
refresh tokens, cookies, or full request IDs.

Default mode is report-only. Sensitive reads and writes require an explicit
flag or an interactive YES confirmation.
#>

[CmdletBinding()]
param(
    [string]$CodexHome = (Join-Path $HOME ".codex"),
    [int]$LogHours = 24,
    [switch]$AllowReadAuth,
    [switch]$AllowReadLogs,
    [switch]$FixConfig,
    [switch]$RebuildIndex,
    [switch]$Fix,
    [switch]$AssumeYes,
    [ValidateSet("en","zh","both")]
    [string]$Language = "both",
    [switch]$Json,
    [switch]$Version
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$Script:ToolVersion = "1.1.0"

$Script:Findings = New-Object System.Collections.Generic.List[object]
$Script:ActionsTaken = New-Object System.Collections.Generic.List[string]
$Script:Summary = [ordered]@{
    version = $Script:ToolVersion
    codex_home = $CodexHome
    language = $Language
    config_path = $null
    auth_path = $null
    logs_path = $null
    session_index_path = $null
    generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Get-SeverityZh {
    param([string]$Severity)
    switch ($Severity) {
        "Critical" { return "严重" }
        "High" { return "高" }
        "Medium" { return "中" }
        "Low" { return "低" }
        default { return "信息" }
    }
}

function Get-ZhTitle {
    param([string]$Id, [string]$Fallback)
    switch ($Id) {
        "CONFIG_NOT_FOUND" { return "未找到 Codex config.toml" }
        "CONFIG_OPENAI_RESPONSES_PROVIDER" { return "当前 provider 路由到了公开 OpenAI Responses API" }
        "CONFIG_OPENAI_BASE_URL_OVERRIDE" { return "检测到顶层 openai_base_url 覆盖" }
        "CONFIG_NO_OPENAI_RESPONSES_PROVIDER_MISMATCH" { return "未检测到已选中的 OpenAI Responses 自定义 provider 配置不匹配" }
        "AUTH_NOT_FOUND" { return "未找到 Codex auth.json" }
        "AUTH_SCOPE_SKIPPED" { return "已跳过 auth scope 检查" }
        "ACCESS_TOKEN_NOT_FOUND" { return "auth.json 中未找到 access_token" }
        "ACCESS_TOKEN_NOT_JWT" { return "access_token 不是 JWT 格式，无法安全检查 scope" }
        "AUTH_SCOPE_READ_FAILED" { return "读取 auth.json payload 失败" }
        "AUTH_SCOPE_HAS_RESPONSES_WRITE" { return "认证 payload 包含 api.responses.write" }
        "AUTH_SCOPE_MISSING_RESPONSES_WRITE" { return "认证 payload 不包含 api.responses.write" }
        "LIKELY_ROOT_CAUSE_SCOPE_MISMATCH" { return "可能根因：ChatGPT OAuth 被路由到公开 Responses API，但缺少 api.responses.write" }
        "LIKELY_ROOT_CAUSE_OPENAI_BASE_URL_SCOPE_MISMATCH" { return "可能根因：openai_base_url 把 ChatGPT OAuth 路由到公开 OpenAI API" }
        "ENV_OVERRIDES_PRESENT" { return "检测到 OpenAI/Codex/代理环境变量" }
        "ENV_OVERRIDES_NOT_FOUND" { return "当前进程未发现明显的 OpenAI/Codex/代理环境变量覆盖" }
        "LOG_DB_NOT_FOUND" { return "未找到 Codex logs_2.sqlite" }
        "LOG_SCAN_SKIPPED" { return "已跳过日志扫描" }
        "LOG_SCAN_FAILED" { return "日志扫描失败" }
        "PYTHON_NOT_FOUND" { return "未找到 Python，无法查询 logs_2.sqlite" }
        "LOG_OPENAI_RESPONSES_SCOPE_MISMATCH" { return "日志显示 api.responses.write / 公开 Responses API 401 路径" }
        "LOG_MISSING_AUTH_HEADER" { return "日志显示缺少 bearer/basic 认证头" }
        "LOG_CHATGPT_BACKEND_UNAUTHORIZED" { return "日志显示 ChatGPT backend Codex 未授权" }
        "LOG_CUSTOM_PROVIDER_401" { return "日志显示自定义 provider 返回 401" }
        "LOG_TOKEN_REFRESH_OR_EXPIRED" { return "日志提示 token 刷新或过期问题" }
        "LOG_TRANSPORT_RECONNECT_OR_FALLBACK" { return "日志显示 websocket/stream 重连或 fallback" }
        "LOG_GENERIC_401" { return "日志显示通用 401 Unauthorized" }
        "SESSION_INDEX_DEGRADED" { return "session_index.jsonl 似乎不完整" }
        "SESSION_INDEX_OK" { return "会话索引数量看起来正常" }
        "REBUILD_INDEX_NO_SESSIONS" { return "未找到 sessions 目录" }
        "REBUILD_INDEX_SKIPPED" { return "已跳过会话索引重建" }
        "REBUILD_INDEX_NO_RECORDS" { return "未能提取任何会话元数据" }
        "FIX_CONFIG_SKIPPED" { return "已跳过 config 修复" }
        "FIX_CONFIG_NOT_APPLICABLE" { return "未发现可修复的已选中危险 provider" }
        default { return $Fallback }
    }
}

function Get-ZhRecommendation {
    param([string]$Id, [string]$Fallback)
    switch ($Id) {
        "CONFIG_NOT_FOUND" { return "安装或登录 Codex，或用 -CodexHome 指定正确目录。" }
        "CONFIG_OPENAI_RESPONSES_PROVIDER" { return "如果使用 ChatGPT 登录态，这可能触发 Missing scopes: api.responses.write。请删除该 provider，或改用正确的 API-key 认证/provider 配置。" }
        "CONFIG_OPENAI_BASE_URL_OVERRIDE" { return "如果使用 ChatGPT 登录态，请删除 openai_base_url；它会把请求导向公开 OpenAI API，从而触发 api.responses.write scope 错误。" }
        "AUTH_NOT_FOUND" { return "如果预期使用 ChatGPT 登录态，请重新登录 Codex。" }
        "AUTH_SCOPE_SKIPPED" { return "使用 -AllowReadAuth 可检查 scope。" }
        "ACCESS_TOKEN_NOT_FOUND" { return "请退出并重新登录 Codex。" }
        "ACCESS_TOKEN_NOT_JWT" { return "无法安全检查 scope。" }
        "AUTH_SCOPE_READ_FAILED" { return "检查 auth.json 格式，或重新登录。" }
        "AUTH_SCOPE_MISSING_RESPONSES_WRITE" { return "这对很多 ChatGPT OAuth token 是正常的；但如果 provider 调用 https://api.openai.com/v1/responses，就会冲突。" }
        "LIKELY_ROOT_CAUSE_SCOPE_MISMATCH" { return "确认提示后运行 -FixConfig，或手动删除危险 provider。" }
        "LIKELY_ROOT_CAUSE_OPENAI_BASE_URL_SCOPE_MISMATCH" { return "确认提示后运行 -FixConfig，或手动删除 openai_base_url。" }
        "ENV_OVERRIDES_PRESENT" { return "这些变量可能覆盖 ChatGPT OAuth 或影响传输；请确认它们是有意设置的。" }
        "LOG_DB_NOT_FOUND" { return "未执行本地日志扫描。" }
        "LOG_SCAN_SKIPPED" { return "使用 -AllowReadLogs 可分类最近的 401 日志。" }
        "LOG_SCAN_FAILED" { return "请在有 Python 且可读取 logs_2.sqlite 的环境中运行。" }
        "LOG_OPENAI_RESPONSES_SCOPE_MISMATCH" { return "检查 config provider 路由，以及当前使用的是 ChatGPT 登录态还是 API key。" }
        "LOG_MISSING_AUTH_HEADER" { return "刷新登录，并确认请求路径带上了 Authorization。" }
        "LOG_CHATGPT_BACKEND_UNAUTHORIZED" { return "可能是登录态、账号 entitlement、workspace 或 backend 授权问题。重新登录可能有帮助；config 修复不一定能解决。" }
        "LOG_CUSTOM_PROVIDER_401" { return "检查 provider 的 base_url、API key、headers、deployment name 和 endpoint。" }
        "LOG_TOKEN_REFRESH_OR_EXPIRED" { return "退出并重新登录；检查 auth.json 是否可写。" }
        "LOG_TRANSPORT_RECONNECT_OR_FALLBACK" { return "这是传输层问题，不一定是认证问题。检查代理、VPN、网络稳定性。" }
        "LOG_GENERIC_401" { return "结合 endpoint 和认证方式进一步缩小原因。" }
        "SESSION_INDEX_DEGRADED" { return "确认提示后可用 -RebuildIndex 从 session metadata 重建索引。" }
        "REBUILD_INDEX_NO_SESSIONS" { return "无法重建 session_index.jsonl。" }
        "REBUILD_INDEX_NO_RECORDS" { return "未进行任何修改。" }
        default { return $Fallback }
    }
}

function Add-Finding {
    param(
        [Parameter(Mandatory=$true)][string]$Id,
        [Parameter(Mandatory=$true)][ValidateSet("Info","Low","Medium","High","Critical")][string]$Severity,
        [Parameter(Mandatory=$true)][string]$Title,
        [string]$Evidence = "",
        [string]$Recommendation = "",
        [bool]$CanAutoFix = $false
    )
    $Script:Findings.Add([pscustomobject]@{
        id = $Id
        severity = $Severity
        severity_zh = (Get-SeverityZh $Severity)
        title = $Title
        title_en = $Title
        title_zh = (Get-ZhTitle $Id $Title)
        evidence = $Evidence
        recommendation = $Recommendation
        recommendation_en = $Recommendation
        recommendation_zh = (Get-ZhRecommendation $Id $Recommendation)
        can_auto_fix = $CanAutoFix
    }) | Out-Null
}

function Write-Info {
    param([string]$Message)
    if (-not $Json) { Write-Host $Message }
}

function Sanitize-Text {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    $s = $Text
    $s = $s -replace '(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._\-]+', '$1[REDACTED]'
    $s = $s -replace '(?i)(access_token|refresh_token|id_token|cookie|set-cookie)(["''\s:=]+)([^"''\s,}]+)', '$1$2[REDACTED]'
    $s = $s -replace 'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', '[JWT_REDACTED]'
    $s = $s -replace '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '[UUID_REDACTED]'
    $s = $s -replace '(?i)cf-ray:\s*[^,\s]+', 'cf-ray: [REDACTED]'
    $s = $s -replace '\b(req|request|id)[:=]\s*[A-Za-z0-9_-]{16,}\b', '$1=[REDACTED]'
    if ($s.Length -gt 500) { $s = $s.Substring(0, 500) + "..." }
    return $s
}

function Request-Consent {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string]$Details
    )
    if ($AssumeYes) {
        return $true
    }
    Write-Host ""
    if ($Language -eq "zh") {
        Write-Host "敏感操作: $Title" -ForegroundColor Yellow
    } elseif ($Language -eq "both") {
        Write-Host "Sensitive operation / 敏感操作: $Title" -ForegroundColor Yellow
    } else {
        Write-Host "Sensitive operation: $Title" -ForegroundColor Yellow
    }
    Write-Host $Details
    $prompt = if ($Language -eq "zh") { "输入 YES 以允许此操作" } elseif ($Language -eq "both") { "Type YES to allow this operation / 输入 YES 以允许此操作" } else { "Type YES to allow this operation" }
    $answer = Read-Host $prompt
    return ($answer -ceq "YES")
}

function Get-UnquotedValue {
    param([string]$Value)
    $v = $Value.Trim()
    $commentIndex = $v.IndexOf("#")
    if ($commentIndex -ge 0) { $v = $v.Substring(0, $commentIndex).Trim() }
    if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) {
        return $v.Substring(1, $v.Length - 2)
    }
    return $v
}

function Read-CodexConfig {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        Add-Finding "CONFIG_NOT_FOUND" "High" "Codex config.toml not found" "Path: $Path" "Install or log in to Codex, or pass -CodexHome."
        return $null
    }

    $raw = Get-Content -LiteralPath $Path -Raw
    $lines = $raw -split "`r?`n"
    $root = @{}
    $providers = @{}
    $section = ""
    $providerName = $null

    foreach ($line in $lines) {
        $trim = $line.Trim()
        if ($trim -eq "" -or $trim.StartsWith("#")) { continue }
        if ($trim -match '^\[(.+)\]\s*$') {
            $section = $Matches[1]
            $providerName = $null
            if ($section -match '^model_providers\.(.+)$') {
                $providerName = Get-UnquotedValue $Matches[1]
                if (-not $providers.ContainsKey($providerName)) { $providers[$providerName] = @{} }
            }
            continue
        }
        if ($trim -match '^([A-Za-z0-9_\-]+)\s*=\s*(.+)$') {
            $key = $Matches[1]
            $value = Get-UnquotedValue $Matches[2]
            if ($providerName) {
                $providers[$providerName][$key] = $value
            } elseif ($section -eq "") {
                $root[$key] = $value
            }
        }
    }

    return [pscustomobject]@{
        path = $Path
        raw = $raw
        lines = $lines
        root = $root
        providers = $providers
    }
}

function Test-DangerousResponsesProvider {
    param([object]$Config)
    $danger = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Config) { return @() }
    foreach ($name in $Config.providers.Keys) {
        $p = $Config.providers[$name]
        $base = if ($p.ContainsKey("base_url")) { [string]$p["base_url"] } else { "" }
        $wire = if ($p.ContainsKey("wire_api")) { [string]$p["wire_api"] } else { "" }
        $requiresAuth = if ($p.ContainsKey("requires_openai_auth")) { [string]$p["requires_openai_auth"] } else { "" }
        $supportsWs = if ($p.ContainsKey("supports_websockets")) { [string]$p["supports_websockets"] } else { "" }
        $isOpenAiResponses = ($base.TrimEnd("/") -ieq "https://api.openai.com/v1" -and $wire -ieq "responses")
        if ($isOpenAiResponses) {
            $selected = ($Config.root.ContainsKey("model_provider") -and $Config.root["model_provider"] -eq $name)
            $danger.Add([pscustomobject]@{
                name = $name
                selected = $selected
                base_url = $base
                wire_api = $wire
                requires_openai_auth = $requiresAuth
                supports_websockets = $supportsWs
            }) | Out-Null
        }
    }
    return $danger.ToArray()
}

function Test-OpenAIBaseUrlOverride {
    param([object]$Config)
    if ($null -eq $Config) { return $null }
    if (-not $Config.root.ContainsKey("openai_base_url")) { return $null }

    $value = [string]$Config.root["openai_base_url"]
    $normalized = $value.TrimEnd("/")
    return [pscustomobject]@{
        key = "openai_base_url"
        value = $value
        is_public_openai_api = ($normalized -ieq "https://api.openai.com/v1")
    }
}

function ConvertFrom-Base64UrlJson {
    param([string]$Segment)
    $s = $Segment.Replace("-", "+").Replace("_", "/")
    while (($s.Length % 4) -ne 0) { $s += "=" }
    $bytes = [Convert]::FromBase64String($s)
    $jsonText = [Text.Encoding]::UTF8.GetString($bytes)
    return $jsonText | ConvertFrom-Json
}

function Read-AuthScopes {
    param([string]$AuthPath)
    if (-not (Test-Path -LiteralPath $AuthPath)) {
        Add-Finding "AUTH_NOT_FOUND" "Medium" "Codex auth.json not found" "Path: $AuthPath" "Log in to Codex again if ChatGPT auth is expected."
        return $null
    }

    $allowed = $AllowReadAuth -or (Request-Consent "Read auth.json JWT payload" "Path: $AuthPath`nThe script reads the access_token only to decode the JWT payload and list scopes. It will not print tokens.")
    if (-not $allowed) {
        Add-Finding "AUTH_SCOPE_SKIPPED" "Info" "Auth scope check skipped" "User did not allow reading auth.json." "Run with -AllowReadAuth to check scopes."
        return $null
    }

    try {
        $auth = Get-Content -LiteralPath $AuthPath -Raw | ConvertFrom-Json
        $token = $null
        if ($auth.PSObject.Properties.Name -contains "tokens" -and $auth.tokens.PSObject.Properties.Name -contains "access_token") {
            $token = [string]$auth.tokens.access_token
        } elseif ($auth.PSObject.Properties.Name -contains "access_token") {
            $token = [string]$auth.access_token
        }
        if ([string]::IsNullOrWhiteSpace($token)) {
            Add-Finding "ACCESS_TOKEN_NOT_FOUND" "High" "access_token not found in auth.json" "" "Log out and log in to Codex again."
            return $null
        }

        $parts = $token.Split(".")
        if ($parts.Count -lt 2) {
            Add-Finding "ACCESS_TOKEN_NOT_JWT" "Medium" "access_token is not a JWT-like token" "" "Cannot inspect scopes safely."
            return $null
        }
        $payload = ConvertFrom-Base64UrlJson $parts[1]
        $scopes = New-Object System.Collections.Generic.List[string]
        foreach ($prop in @("scope", "scp", "scopes")) {
            if ($payload.PSObject.Properties.Name -contains $prop) {
                $value = $payload.$prop
                if ($value -is [string]) {
                    foreach ($item in ($value -split "\s+")) { if ($item) { $scopes.Add($item) | Out-Null } }
                } elseif ($value -is [System.Array]) {
                    foreach ($item in $value) { if ($item) { $scopes.Add([string]$item) | Out-Null } }
                }
            }
        }
        $exp = $null
        if ($payload.PSObject.Properties.Name -contains "exp") {
            try { $exp = [DateTimeOffset]::FromUnixTimeSeconds([int64]$payload.exp).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz") } catch {}
        }
        return [pscustomobject]@{
            scopes = @($scopes | Sort-Object -Unique)
            has_api_responses_write = (@($scopes) -contains "api.responses.write")
            expires_local = $exp
        }
    } catch {
        Add-Finding "AUTH_SCOPE_READ_FAILED" "Medium" "Failed to inspect auth.json payload" (Sanitize-Text $_.Exception.Message) "Check auth.json format or log in again."
        return $null
    }
}

function Get-PythonCommand {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) { return @($python.Source) }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) { return @($py.Source, "-3") }
    return $null
}

function Invoke-LogScan {
    param([string]$DbPath, [int]$Hours)
    if (-not (Test-Path -LiteralPath $DbPath)) {
        Add-Finding "LOG_DB_NOT_FOUND" "Info" "Codex logs_2.sqlite not found" "Path: $DbPath" "No local log scan was performed."
        return $null
    }
    $allowed = $AllowReadLogs -or (Request-Consent "Read Codex logs database" "Path: $DbPath`nLogs may contain prompts or snippets. The script reports only redacted classifications and short redacted excerpts.")
    if (-not $allowed) {
        Add-Finding "LOG_SCAN_SKIPPED" "Info" "Log scan skipped" "User did not allow reading logs_2.sqlite." "Run with -AllowReadLogs to classify recent 401 errors."
        return $null
    }
    $pycmd = @(Get-PythonCommand)
    if (-not $pycmd) {
        Add-Finding "PYTHON_NOT_FOUND" "Low" "Python not found, cannot query logs_2.sqlite" "" "Install Python or run the script from an environment with python available."
        return $null
    }

    $tmp = [IO.Path]::ChangeExtension([IO.Path]::GetTempFileName(), ".py")
    $code = @'
import datetime, json, os, re, sqlite3, sys, time
db = sys.argv[1]
hours = int(sys.argv[2])
since = int(time.time() - hours * 3600)
conn = sqlite3.connect(db)
cur = conn.cursor()
query = """
select ts, level, target, feedback_log_body from logs
where ts >= ? and (
  lower(coalesce(feedback_log_body,'')) like '%401%' or
  lower(coalesce(feedback_log_body,'')) like '%unauthorized%' or
  lower(coalesce(feedback_log_body,'')) like '%api.responses.write%' or
  lower(coalesce(feedback_log_body,'')) like '%missing bearer%' or
  lower(coalesce(feedback_log_body,'')) like '%responses_websocket%' or
  lower(coalesce(feedback_log_body,'')) like '%stream disconnected%' or
  lower(coalesce(feedback_log_body,'')) like '%falling back to http%'
)
order by ts desc limit 250
"""
rows = cur.execute(query, (since,)).fetchall()
conn.close()

def sanitize(s):
    s = s or ""
    s = s.replace("\r", " ").replace("\n", " ")
    s = re.sub(r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._\-]+", r"\1[REDACTED]", s)
    s = re.sub(r"(?i)(access_token|refresh_token|id_token|cookie|set-cookie)([\"'\s:=]+)([^\"'\s,}]+)", r"\1\2[REDACTED]", s)
    s = re.sub(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "[JWT_REDACTED]", s)
    s = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "[UUID_REDACTED]", s)
    s = re.sub(r"(?i)cf-ray:\s*[^,\s]+", "cf-ray: [REDACTED]", s)
    s = re.sub(r"\b[A-Za-z0-9_-]{32,}\b", "[LONG_ID_REDACTED]", s)
    return s[:420]

def classify(body):
    b = (body or "").lower()
    if "api.responses.write" in b or "https://api.openai.com/v1/responses" in b:
        return "OPENAI_RESPONSES_SCOPE_MISMATCH"
    if "missing bearer or basic authentication" in b or "missing bearer" in b:
        return "MISSING_AUTH_HEADER"
    if "chatgpt.com/backend-api/codex/responses" in b and ("401" in b or "unauthorized" in b):
        return "CHATGPT_BACKEND_UNAUTHORIZED"
    if ("openrouter.ai" in b or "azure" in b or "vercel" in b or "anthropic" in b) and ("401" in b or "unauthorized" in b):
        return "CUSTOM_PROVIDER_401"
    if (
        "invalid_token" in b or
        "token expired" in b or
        "expired token" in b or
        "access token expired" in b or
        "refresh token failed" in b or
        "failed to refresh token" in b
    ):
        return "TOKEN_REFRESH_OR_EXPIRED"
    if "responses_websocket" in b or "stream disconnected" in b or "falling back to http" in b:
        return "TRANSPORT_RECONNECT_OR_FALLBACK"
    if "401" in b or "unauthorized" in b:
        return "GENERIC_401_UNAUTHORIZED"
    return "OTHER_RELATED_LOG"

counts = {}
samples = {}
latest = {}
for ts, level, target, body in rows:
    raw = body or ""
    low = raw.lower()
    # Request payloads and streamed assistant/tool deltas often echo the user's
    # pasted error text. Counting those as fresh 401s produces noisy results.
    if target in ("codex_api::sse::responses", "codex_core::stream_events_utils", "codex_core::spawn"):
        continue
    if "response.function_call_arguments.delta" in low or "response.output_item.done" in low:
        continue
    if ('"role":"user"' in low or '\\"role\\":\\"user\\"' in low) and (
        "api.responses.write" in low or "unexpected status 401" in low or "unauthorized" in low
    ):
        continue
    c = classify(body)
    counts[c] = counts.get(c, 0) + 1
    latest[c] = max(latest.get(c, 0), int(ts))
    if c not in samples:
        samples[c] = {
            "time_local": datetime.datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S %z"),
            "level": level,
            "target": target,
            "excerpt": sanitize(body),
        }
print(json.dumps({"rows_scanned": len(rows), "counts": counts, "latest": latest, "samples": samples}, ensure_ascii=False))
'@
    try {
        Set-Content -LiteralPath $tmp -Value $code -Encoding UTF8
        $pythonArgs = @()
        if ($pycmd.Count -gt 1) { $pythonArgs += $pycmd[1..($pycmd.Count - 1)] }
        $pythonArgs += @($tmp, $DbPath, $Hours)
        $output = & $pycmd[0] @pythonArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            Add-Finding "LOG_SCAN_FAILED" "Low" "Log scan failed" (Sanitize-Text ($output -join "`n")) "Run with Python installed and a readable logs_2.sqlite."
            return $null
        }
        return ($output -join "`n") | ConvertFrom-Json
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Test-SessionIndex {
    param([string]$CodexHomePath)
    $indexPath = Join-Path $CodexHomePath "session_index.jsonl"
    $sessionsPath = Join-Path $CodexHomePath "sessions"
    $Script:Summary["session_index_path"] = $indexPath
    $indexCount = 0
    if (Test-Path -LiteralPath $indexPath) {
        $indexCount = @(Get-Content -LiteralPath $indexPath -ErrorAction SilentlyContinue | Where-Object { $_.Trim() }).Count
    }
    $fileCount = 0
    if (Test-Path -LiteralPath $sessionsPath) {
        $fileCount = @(Get-ChildItem -LiteralPath $sessionsPath -Recurse -File -Filter "*.jsonl" -ErrorAction SilentlyContinue).Count
    }
    $Script:Summary["session_index_records"] = $indexCount
    $Script:Summary["session_files"] = $fileCount
    if ($fileCount -gt 0 -and $indexCount -lt [Math]::Max(1, [int]($fileCount * 0.6))) {
        Add-Finding "SESSION_INDEX_DEGRADED" "Medium" "session_index.jsonl appears incomplete" "Index records: $indexCount; session files: $fileCount" "Run with -RebuildIndex to rebuild from session metadata after reviewing the prompt." $true
    } elseif ($fileCount -gt 0) {
        Add-Finding "SESSION_INDEX_OK" "Info" "Session index count looks plausible" "Index records: $indexCount; session files: $fileCount" ""
    }
}

function Rebuild-SessionIndex {
    param([string]$CodexHomePath)
    $indexPath = Join-Path $CodexHomePath "session_index.jsonl"
    $sessionsPath = Join-Path $CodexHomePath "sessions"
    if (-not (Test-Path -LiteralPath $sessionsPath)) {
        Add-Finding "REBUILD_INDEX_NO_SESSIONS" "Low" "No sessions directory found" "Path: $sessionsPath" "Cannot rebuild session_index.jsonl."
        return
    }
    $allowed = Request-Consent "Rebuild session_index.jsonl" "This reads the first JSON line of each session file and writes a new index. A backup of the existing index will be created first.`nIndex path: $indexPath"
    if (-not $allowed) {
        Add-Finding "REBUILD_INDEX_SKIPPED" "Info" "Session index rebuild skipped" "User did not authorize writing session_index.jsonl." ""
        return
    }
    $records = New-Object System.Collections.Generic.List[object]
    foreach ($file in Get-ChildItem -LiteralPath $sessionsPath -Recurse -File -Filter "*.jsonl" -ErrorAction SilentlyContinue) {
        try {
            $first = Get-Content -LiteralPath $file.FullName -TotalCount 1 -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($first)) { continue }
            $obj = $first | ConvertFrom-Json
            $payload = if ($obj.PSObject.Properties.Name -contains "payload") { $obj.payload } else { $obj }
            $id = $null
            foreach ($k in @("session_id", "id", "thread_id")) {
                if ($payload.PSObject.Properties.Name -contains $k -and $payload.$k) { $id = [string]$payload.$k; break }
            }
            if (-not $id -and $file.Name -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
                $id = $Matches[1]
            }
            if (-not $id) { continue }
            $cwd = if ($payload.PSObject.Properties.Name -contains "cwd") { [string]$payload.cwd } else { "" }
            $threadName = if ($cwd) { Split-Path -Leaf $cwd } else { [IO.Path]::GetFileNameWithoutExtension($file.Name) }
            if ([string]::IsNullOrWhiteSpace($threadName)) { $threadName = $id.Substring(0, [Math]::Min(8, $id.Length)) }
            $records.Add([pscustomobject]@{
                id = $id
                thread_name = $threadName
                updated_at = $file.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
            }) | Out-Null
        } catch {
            # Skip unreadable or malformed session files.
        }
    }
    $records = @($records | Sort-Object updated_at -Descending)
    if ($records.Count -eq 0) {
        Add-Finding "REBUILD_INDEX_NO_RECORDS" "Medium" "No session metadata could be extracted" "" "No changes were made."
        return
    }
    if (Test-Path -LiteralPath $indexPath) {
        $backup = "$indexPath.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Copy-Item -LiteralPath $indexPath -Destination $backup
        $Script:ActionsTaken.Add("Backed up session_index.jsonl to $backup") | Out-Null
    }
    $lines = foreach ($r in $records) { $r | ConvertTo-Json -Compress }
    Set-Content -LiteralPath $indexPath -Value $lines -Encoding UTF8
    $Script:ActionsTaken.Add("Rebuilt session_index.jsonl with $($records.Count) records") | Out-Null
}

function Remove-DangerousProviderFromConfig {
    param([object]$Config, [string]$ProviderName)
    if ($null -eq $Config -or [string]::IsNullOrWhiteSpace($ProviderName)) { return }
    $allowed = Request-Consent "Edit config.toml" "This will backup config.toml, remove model_provider = `"$ProviderName`" if present, and remove the [model_providers.$ProviderName] block.`nPath: $($Config.path)"
    if (-not $allowed) {
        Add-Finding "FIX_CONFIG_SKIPPED" "Info" "Config fix skipped" "User did not authorize editing config.toml." ""
        return
    }

    $backup = "$($Config.path).bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item -LiteralPath $Config.path -Destination $backup
    $out = New-Object System.Collections.Generic.List[string]
    $skipBlock = $false
    foreach ($line in $Config.lines) {
        $trim = $line.Trim()
        if ($skipBlock) {
            if ($trim -match '^\[.+\]\s*$') {
                $skipBlock = $false
            } else {
                continue
            }
        }
        if ($trim -match ('^model_provider\s*=\s*["'']' + [regex]::Escape($ProviderName) + '["'']\s*(#.*)?$')) {
            continue
        }
        if ($trim -match ('^\[model_providers\.' + [regex]::Escape($ProviderName) + '\]\s*$')) {
            $skipBlock = $true
            continue
        }
        $out.Add($line) | Out-Null
    }
    Set-Content -LiteralPath $Config.path -Value $out -Encoding UTF8
    $Script:ActionsTaken.Add("Backed up config.toml to $backup") | Out-Null
    $Script:ActionsTaken.Add("Removed selected dangerous provider '$ProviderName' from config.toml") | Out-Null
}

function Remove-OpenAIBaseUrlOverrideFromConfig {
    param([object]$Config)
    if ($null -eq $Config) { return }
    $allowed = Request-Consent "Edit config.toml" "This will backup config.toml and remove the root openai_base_url entry if present.`nPath: $($Config.path)"
    if (-not $allowed) {
        Add-Finding "FIX_CONFIG_SKIPPED" "Info" "Config fix skipped" "User did not authorize editing config.toml." ""
        return
    }

    $backup = "$($Config.path).bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item -LiteralPath $Config.path -Destination $backup
    $out = New-Object System.Collections.Generic.List[string]
    $section = ""
    foreach ($line in $Config.lines) {
        $trim = $line.Trim()
        if ($trim -match '^\[(.+)\]\s*$') {
            $section = $Matches[1]
            $out.Add($line) | Out-Null
            continue
        }
        if ($section -eq "" -and $trim -match '^openai_base_url\s*=') {
            continue
        }
        $out.Add($line) | Out-Null
    }
    Set-Content -LiteralPath $Config.path -Value $out -Encoding UTF8
    $Script:ActionsTaken.Add("Backed up config.toml to $backup") | Out-Null
    $Script:ActionsTaken.Add("Removed root openai_base_url from config.toml") | Out-Null
}

function Test-EnvOverrides {
    $vars = @("OPENAI_API_KEY","OPENAI_BASE_URL","OPENAI_API_BASE","OPENAI_API_BASE_URL","CODEX_API_KEY","OPENAI_ORGANIZATION","OPENAI_PROJECT","OPENAI_PROJECT_ID","CODEX_ACCESS_TOKEN","HTTPS_PROXY","HTTP_PROXY","ALL_PROXY")
    $present = New-Object System.Collections.Generic.List[string]
    foreach ($v in $vars) {
        $value = [Environment]::GetEnvironmentVariable($v, "Process")
        if (-not [string]::IsNullOrWhiteSpace($value)) { $present.Add($v) | Out-Null }
    }
    if ($present.Count -gt 0) {
        Add-Finding "ENV_OVERRIDES_PRESENT" "Medium" "OpenAI/Codex/proxy environment variables are present" ("Present variables only, values hidden: " + (($present | Sort-Object) -join ", ")) "These may override ChatGPT OAuth or affect transport. Verify they are intentional."
    } else {
        Add-Finding "ENV_OVERRIDES_NOT_FOUND" "Info" "No obvious OpenAI/Codex/proxy env overrides in this process" "" ""
    }
}

function Add-LogFindings {
    param([object]$LogResult)
    if ($null -eq $LogResult) { return }
    $Script:Summary["log_rows_scanned"] = $LogResult.rows_scanned
    foreach ($name in $LogResult.counts.PSObject.Properties.Name) {
        $count = [int]$LogResult.counts.$name
        $sample = $LogResult.samples.$name
        $evidence = "Count in last $LogHours hours: $count"
        if ($sample) { $evidence += "; sample: " + (Sanitize-Text $sample.excerpt) }
        switch ($name) {
            "OPENAI_RESPONSES_SCOPE_MISMATCH" {
                Add-Finding "LOG_OPENAI_RESPONSES_SCOPE_MISMATCH" "High" "Logs show api.responses.write / public Responses API 401 path" $evidence "Check config provider routing and ChatGPT-vs-API-key auth mode."
            }
            "MISSING_AUTH_HEADER" {
                Add-Finding "LOG_MISSING_AUTH_HEADER" "High" "Logs show missing bearer/basic auth header" $evidence "Refresh login and verify the request path is carrying Authorization."
            }
            "CHATGPT_BACKEND_UNAUTHORIZED" {
                Add-Finding "LOG_CHATGPT_BACKEND_UNAUTHORIZED" "High" "Logs show ChatGPT backend Codex Unauthorized" $evidence "Likely login, entitlement, workspace, or backend authorization issue. Re-login may help; config fixes may not."
            }
            "CUSTOM_PROVIDER_401" {
                Add-Finding "LOG_CUSTOM_PROVIDER_401" "High" "Logs show custom provider 401" $evidence "Verify provider base_url, API key, headers, deployment name, and endpoint."
            }
            "TOKEN_REFRESH_OR_EXPIRED" {
                Add-Finding "LOG_TOKEN_REFRESH_OR_EXPIRED" "Medium" "Logs suggest token refresh or expiry trouble" $evidence "Log out and log in again; check auth.json write permissions."
            }
            "TRANSPORT_RECONNECT_OR_FALLBACK" {
                Add-Finding "LOG_TRANSPORT_RECONNECT_OR_FALLBACK" "Medium" "Logs show websocket/stream reconnect or fallback" $evidence "This is a transport issue, not necessarily auth. Check proxy/VPN/network stability."
            }
            "GENERIC_401_UNAUTHORIZED" {
                Add-Finding "LOG_GENERIC_401" "Medium" "Logs show generic 401 Unauthorized" $evidence "Use endpoint and auth mode to narrow the cause."
            }
            default {
                Add-Finding ("LOG_" + $name) "Info" "Related log pattern found: $name" $evidence ""
            }
        }
    }
}

function Write-HumanReport {
    Write-Host ""
    if ($Language -eq "zh") {
        Write-Host "codex-401-doctor 诊断报告 (v$Script:ToolVersion)" -ForegroundColor Cyan
        Write-Host "Codex 目录: $CodexHome"
        Write-Host "敏感信息: 不会打印 access_token、refresh_token、cookie 或完整 request ID。"
    } elseif ($Language -eq "both") {
        Write-Host "codex-401-doctor report / 诊断报告 (v$Script:ToolVersion)" -ForegroundColor Cyan
        Write-Host "Codex home / Codex 目录: $CodexHome"
        Write-Host "Secrets / 敏感信息: access_token, refresh_token, cookies, and full request IDs are not printed. / 不会打印 access_token、refresh_token、cookie 或完整 request ID。"
    } else {
        Write-Host "codex-401-doctor report (v$Script:ToolVersion)" -ForegroundColor Cyan
        Write-Host "Codex home: $CodexHome"
        Write-Host "Secrets: access_token, refresh_token, cookies, and full request IDs are not printed."
    }
    Write-Host ""

    $severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $ordered = @($Script:Findings | Sort-Object @{ Expression = { $severityOrder[$_.severity] } }, id)
    if ($ordered.Count -eq 0) {
        if ($Language -eq "zh") { Write-Host "未发现问题。" }
        elseif ($Language -eq "both") { Write-Host "No findings. / 未发现问题。" }
        else { Write-Host "No findings." }
    } else {
        foreach ($f in $ordered) {
            $color = switch ($f.severity) {
                "Critical" { "Red" }
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Gray" }
                default { "DarkGray" }
            }
            if ($Language -eq "zh") {
                Write-Host ("[{0}] {1} - {2}" -f $f.severity_zh, $f.id, $f.title_zh) -ForegroundColor $color
                if ($f.evidence) { Write-Host ("  证据: " + $f.evidence) }
                if ($f.recommendation_zh) { Write-Host ("  建议: " + $f.recommendation_zh) }
                if ($f.can_auto_fix) { Write-Host "  自动修复: 可通过显式修复参数并确认后执行。" }
            } elseif ($Language -eq "both") {
                Write-Host ("[{0}/{1}] {2}" -f $f.severity, $f.severity_zh, $f.id) -ForegroundColor $color
                Write-Host ("  EN: " + $f.title_en)
                Write-Host ("  中文: " + $f.title_zh)
                if ($f.evidence) { Write-Host ("  Evidence / 证据: " + $f.evidence) }
                if ($f.recommendation_en) { Write-Host ("  Recommendation: " + $f.recommendation_en) }
                if ($f.recommendation_zh) { Write-Host ("  建议: " + $f.recommendation_zh) }
                if ($f.can_auto_fix) { Write-Host "  Auto-fix / 自动修复: available with explicit repair flags and confirmation. / 可通过显式修复参数并确认后执行。" }
            } else {
                Write-Host ("[{0}] {1} - {2}" -f $f.severity, $f.id, $f.title_en) -ForegroundColor $color
                if ($f.evidence) { Write-Host ("  Evidence: " + $f.evidence) }
                if ($f.recommendation_en) { Write-Host ("  Recommendation: " + $f.recommendation_en) }
                if ($f.can_auto_fix) { Write-Host "  Auto-fix: available with explicit repair flags and confirmation." }
            }
        }
    }
    if ($Script:ActionsTaken.Count -gt 0) {
        Write-Host ""
        if ($Language -eq "zh") { Write-Host "已执行操作" -ForegroundColor Cyan }
        elseif ($Language -eq "both") { Write-Host "Actions taken / 已执行操作" -ForegroundColor Cyan }
        else { Write-Host "Actions taken" -ForegroundColor Cyan }
        foreach ($a in $Script:ActionsTaken) { Write-Host ("- " + $a) }
    }
    Write-Host ""
}

function Main {
    if ($Version) {
        Write-Output "codex-401-doctor $Script:ToolVersion"
        exit 0
    }
    $configPath = Join-Path $CodexHome "config.toml"
    $authPath = Join-Path $CodexHome "auth.json"
    $logsPath = Join-Path $CodexHome "logs_2.sqlite"
    $Script:Summary["config_path"] = $configPath
    $Script:Summary["auth_path"] = $authPath
    $Script:Summary["logs_path"] = $logsPath

    $config = Read-CodexConfig $configPath
    $dangerProviders = @(Test-DangerousResponsesProvider $config)
    $baseUrlOverride = Test-OpenAIBaseUrlOverride $config

    if ($config) {
        $selectedProvider = if ($config.root.ContainsKey("model_provider")) { [string]$config.root["model_provider"] } else { $null }
        $Script:Summary["model"] = if ($config.root.ContainsKey("model")) { $config.root["model"] } else { $null }
        $Script:Summary["model_provider"] = $selectedProvider
        $Script:Summary["openai_base_url"] = if ($baseUrlOverride) { $baseUrlOverride.value } else { $null }
        if ($baseUrlOverride) {
            $sev = if ($baseUrlOverride.is_public_openai_api) { "High" } else { "Medium" }
            $title = if ($baseUrlOverride.is_public_openai_api) { "openai_base_url routes to the public OpenAI API" } else { "Custom root openai_base_url is configured" }
            Add-Finding "CONFIG_OPENAI_BASE_URL_OVERRIDE" $sev $title "$($baseUrlOverride.key)=$($baseUrlOverride.value)" "If using ChatGPT sign-in auth, remove openai_base_url or use the matching API-key auth mode." $baseUrlOverride.is_public_openai_api
        }
        if ($dangerProviders.Count -eq 0 -and -not ($baseUrlOverride -and $baseUrlOverride.is_public_openai_api)) {
            Add-Finding "CONFIG_NO_OPENAI_RESPONSES_PROVIDER_MISMATCH" "Info" "No selected OpenAI Responses custom provider mismatch detected" "" ""
        } else {
            foreach ($p in $dangerProviders) {
                $sev = if ($p.selected) { "High" } else { "Medium" }
                $title = if ($p.selected) { "Selected provider routes to public OpenAI Responses API" } else { "Dormant provider routes to public OpenAI Responses API" }
                Add-Finding "CONFIG_OPENAI_RESPONSES_PROVIDER" $sev $title "provider=$($p.name); base_url=$($p.base_url); wire_api=$($p.wire_api); requires_openai_auth=$($p.requires_openai_auth)" "If using ChatGPT sign-in auth, this can trigger Missing scopes: api.responses.write. Remove the provider or use correct API-key auth." $p.selected
            }
        }
    }

    Test-EnvOverrides
    $authInfo = Read-AuthScopes $authPath
    if ($authInfo) {
        $Script:Summary["auth_token_expires_local"] = $authInfo.expires_local
        $Script:Summary["auth_has_api_responses_write"] = $authInfo.has_api_responses_write
        $scopeEvidence = "Scopes found: " + (($authInfo.scopes | Sort-Object) -join ", ")
        if ($scopeEvidence.Length -gt 300) { $scopeEvidence = $scopeEvidence.Substring(0, 300) + "..." }
        if ($authInfo.has_api_responses_write) {
            Add-Finding "AUTH_SCOPE_HAS_RESPONSES_WRITE" "Info" "Auth payload includes api.responses.write" $scopeEvidence ""
        } else {
            Add-Finding "AUTH_SCOPE_MISSING_RESPONSES_WRITE" "Medium" "Auth payload does not include api.responses.write" $scopeEvidence "This is expected for many ChatGPT OAuth tokens, but conflicts with a provider that calls https://api.openai.com/v1/responses."
        }
        $selectedDanger = @($dangerProviders | Where-Object { $_.selected }) | Select-Object -First 1
        if ($selectedDanger -and -not $authInfo.has_api_responses_write) {
            Add-Finding "LIKELY_ROOT_CAUSE_SCOPE_MISMATCH" "Critical" "Likely root cause: ChatGPT OAuth routed to public Responses API without api.responses.write" "Selected provider '$($selectedDanger.name)' uses https://api.openai.com/v1 + responses; auth payload lacks api.responses.write." "Run with -FixConfig after reviewing the prompt, or remove the provider manually." $true
        }
        if ($baseUrlOverride -and $baseUrlOverride.is_public_openai_api -and -not $authInfo.has_api_responses_write) {
            Add-Finding "LIKELY_ROOT_CAUSE_OPENAI_BASE_URL_SCOPE_MISMATCH" "Critical" "Likely root cause: root openai_base_url sends ChatGPT OAuth to the public OpenAI API" "openai_base_url=$($baseUrlOverride.value); auth payload lacks api.responses.write." "Run with -FixConfig after reviewing the prompt, or remove openai_base_url manually." $true
        }
    }

    $logResult = Invoke-LogScan $logsPath $LogHours
    Add-LogFindings $logResult
    Test-SessionIndex $CodexHome

    $shouldFixConfig = $FixConfig -or $Fix
    if ($shouldFixConfig) {
        $fixedAnyConfig = $false
        $selectedDanger = @($dangerProviders | Where-Object { $_.selected }) | Select-Object -First 1
        if ($selectedDanger) {
            Remove-DangerousProviderFromConfig $config $selectedDanger.name
            $fixedAnyConfig = $true
            $config = Read-CodexConfig $configPath
            $baseUrlOverride = Test-OpenAIBaseUrlOverride $config
        }
        if ($baseUrlOverride -and $baseUrlOverride.is_public_openai_api) {
            Remove-OpenAIBaseUrlOverrideFromConfig $config
            $fixedAnyConfig = $true
        }
        if (-not $fixedAnyConfig) {
            Add-Finding "FIX_CONFIG_NOT_APPLICABLE" "Info" "No selected dangerous provider or public openai_base_url found for config repair" "" ""
        }
    }

    if ($RebuildIndex -or $Fix) {
        Rebuild-SessionIndex $CodexHome
    }

    if ($Json) {
        [pscustomobject]@{
            summary = $Script:Summary
            findings = $Script:Findings.ToArray()
            actions_taken = $Script:ActionsTaken.ToArray()
        } | ConvertTo-Json -Depth 8
    } else {
        Write-HumanReport
    }
}

Main
