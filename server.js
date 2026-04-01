const express = require("express")
const fs = require("node:fs")
const path = require("node:path")
const http = require("node:http")
const https = require("node:https")
const crypto = require("node:crypto")
const { URL } = require("node:url")
const { loadAdminKey } = require("./passwordManager")

const app = express()

app.disable("x-powered-by")
app.set("trust proxy", true)
app.use(express.urlencoded({ extended: false }))
app.use(express.json({ limit: "256kb" }))

const CONFIG_DIR = path.join(process.cwd(), "data")
const CONFIG_FILE = path.join(CONFIG_DIR, "clash-subscription.json")

const PORT = Number(process.env.PORT || 3000)
const adminKeyInfo = loadAdminKey()
const ADMIN_KEY = adminKeyInfo.adminKey
const CACHE_TTL_MS = Number(process.env.CACHE_TTL_MS || 30_000)
const ADMIN_SESSION_TTL_MS = Number(process.env.ADMIN_SESSION_TTL_MS || 7 * 24 * 60 * 60 * 1000)
const ADMIN_COOKIE_NAME = "sevens_admin_session"
const ADMIN_COOKIE_PATH = "/"

const subscriptionCache = {
  updatedAtMs: 0,
  body: null,
  contentType: "",
  etag: "",
  lastModified: "",
  upstreamUrl: "",
}

function nowIso() {
  return new Date().toISOString()
}

function logWithTime(message, extra = {}) {
  const payload = { time: nowIso(), ...extra }
  console.log(`${message} ${JSON.stringify(payload)}`)
}

function ensureConfigDir() {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true })
    logWithTime("Created config directory", { path: CONFIG_DIR })
  }
}

function loadConfig() {
  ensureConfigDir()
  if (!fs.existsSync(CONFIG_FILE)) {
    logWithTime("Config file not found, using defaults", { path: CONFIG_FILE })
    return { upstreamUrl: "", updatedAt: "" }
  }

  try {
    const raw = fs.readFileSync(CONFIG_FILE, "utf8")
    const parsed = JSON.parse(raw)
    return {
      upstreamUrl: typeof parsed.upstreamUrl === "string" ? parsed.upstreamUrl : "",
      updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : "",
    }
  } catch (error) {
    logWithTime("Failed to read config file, using defaults", {
      path: CONFIG_FILE,
      error: String(error && error.message ? error.message : error),
    })
    return { upstreamUrl: "", updatedAt: "" }
  }
}

function saveConfig(nextConfig) {
  ensureConfigDir()
  const data = JSON.stringify(nextConfig, null, 2)
  fs.writeFileSync(CONFIG_FILE, data, "utf8")
  logWithTime("Saved config file", { path: CONFIG_FILE })
}

function readAdminKeyFromRequest(req) {
  const headerKey = req.headers["x-admin-key"]
  if (typeof headerKey === "string" && headerKey.trim()) return headerKey.trim()

  const auth = req.headers.authorization
  if (typeof auth === "string" && auth.toLowerCase().startsWith("bearer ")) {
    const token = auth.slice("bearer ".length).trim()
    if (token) return token
  }

  const queryKey = req.query && req.query.key
  if (typeof queryKey === "string" && queryKey.trim()) return queryKey.trim()

  return ""
}

function parseCookies(cookieHeader) {
  const header = typeof cookieHeader === "string" ? cookieHeader : ""
  if (!header) return {}

  const pairs = header.split(";")
  const cookies = {}
  for (const part of pairs) {
    const index = part.indexOf("=")
    if (index === -1) continue
    const key = part.slice(0, index).trim()
    const value = part.slice(index + 1).trim()
    if (!key) continue
    cookies[key] = decodeURIComponent(value)
  }
  return cookies
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false
  const bufA = Buffer.from(a)
  const bufB = Buffer.from(b)
  if (bufA.length !== bufB.length) return false
  return crypto.timingSafeEqual(bufA, bufB)
}

function makeSessionSignature(timestampMs) {
  return crypto.createHmac("sha256", ADMIN_KEY).update(String(timestampMs)).digest("hex")
}

function createAdminSessionToken() {
  const ts = Date.now()
  const sig = makeSessionSignature(ts)
  return `${ts}.${sig}`
}

function verifyAdminSessionToken(token) {
  if (!ADMIN_KEY) return { ok: false, reason: "missing_admin_key" }
  if (typeof token !== "string" || !token) return { ok: false, reason: "missing_token" }
  const parts = token.split(".")
  if (parts.length !== 2) return { ok: false, reason: "bad_format" }

  const ts = Number(parts[0])
  if (!Number.isFinite(ts) || ts <= 0) return { ok: false, reason: "bad_timestamp" }

  if (Date.now() - ts > ADMIN_SESSION_TTL_MS) return { ok: false, reason: "expired" }

  const expected = makeSessionSignature(ts)
  const provided = parts[1]
  if (!safeEqual(expected, provided)) return { ok: false, reason: "bad_signature" }
  return { ok: true, reason: "" }
}

function isAdminAuthed(req) {
  if (!ADMIN_KEY) return false

  const providedKey = readAdminKeyFromRequest(req)
  if (providedKey && providedKey === ADMIN_KEY) return true

  const cookies = parseCookies(req.headers.cookie)
  const token = cookies[ADMIN_COOKIE_NAME]
  return verifyAdminSessionToken(token).ok
}

function setAdminSessionCookie(res) {
  const token = createAdminSessionToken()
  const maxAgeSeconds = Math.floor(ADMIN_SESSION_TTL_MS / 1000)
  const cookie = [
    `${ADMIN_COOKIE_NAME}=${encodeURIComponent(token)}`,
    `Path=${ADMIN_COOKIE_PATH}`,
    `Max-Age=${maxAgeSeconds}`,
    "HttpOnly",
    "SameSite=Lax",
  ].join("; ")
  res.setHeader("set-cookie", cookie)
}

function clearAdminSessionCookie(res) {
  const cookie = [
    `${ADMIN_COOKIE_NAME}=`,
    `Path=${ADMIN_COOKIE_PATH}`,
    "Max-Age=0",
    "HttpOnly",
    "SameSite=Lax",
  ].join("; ")
  res.setHeader("set-cookie", cookie)
}

function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) {
    res.status(500).send("服务端未配置 ADMIN_KEY（环境变量或 data/admin-key.json），无法进入管理页面。")
    return
  }

  if (!isAdminAuthed(req)) {
    res.status(401).send("未授权：请先在主页面输入密码登录。")
    return
  }

  next()
}

app.use((req, res, next) => {
  const startMs = Date.now()
  res.on("finish", () => {
    logWithTime("HTTP", {
      method: req.method,
      path: req.originalUrl || req.url,
      status: res.statusCode,
      durationMs: Date.now() - startMs,
      ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress || "",
      ua: req.headers["user-agent"] || "",
    })
  })
  next()
})

function validateHttpUrl(urlString) {
  try {
    const u = new URL(urlString)
    if (u.protocol !== "http:" && u.protocol !== "https:") return { ok: false, reason: "仅支持 http/https" }
    return { ok: true, reason: "" }
  } catch {
    return { ok: false, reason: "URL 格式不正确" }
  }
}

function requestOnce(targetUrl, headers = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(targetUrl)
    const isHttps = urlObj.protocol === "https:"
    const lib = isHttps ? https : http

    const options = {
      protocol: urlObj.protocol,
      hostname: urlObj.hostname,
      port: urlObj.port ? Number(urlObj.port) : isHttps ? 443 : 80,
      path: `${urlObj.pathname}${urlObj.search}`,
      method: "GET",
      headers,
      timeout: 20_000,
    }

    const req = lib.request(options, (resp) => {
      const chunks = []
      resp.on("data", (c) => chunks.push(c))
      resp.on("end", () => {
        const body = Buffer.concat(chunks)
        resolve({
          statusCode: resp.statusCode || 0,
          headers: resp.headers || {},
          body,
        })
      })
    })

    req.on("timeout", () => {
      req.destroy(new Error("upstream request timeout"))
    })
    req.on("error", (err) => reject(err))
    req.end()
  })
}

async function fetchWithRedirects(targetUrl, headers = {}, redirectLimit = 5) {
  let currentUrl = targetUrl
  for (let i = 0; i <= redirectLimit; i += 1) {
    const resp = await requestOnce(currentUrl, headers)
    const isRedirect = resp.statusCode >= 300 && resp.statusCode < 400
    const location = resp.headers.location
    if (isRedirect && typeof location === "string" && location) {
      const nextUrl = new URL(location, currentUrl).toString()
      logWithTime("Upstream redirect", { from: currentUrl, to: nextUrl, status: resp.statusCode })
      currentUrl = nextUrl
      continue
    }
    return { ...resp, finalUrl: currentUrl }
  }

  throw new Error("too many redirects")
}

function toHeaderString(value) {
  if (typeof value === "string") return value
  if (Array.isArray(value)) return value.join(", ")
  return ""
}

async function getSubscriptionFromUpstream(upstreamUrl) {
  const cacheValid =
    subscriptionCache.upstreamUrl === upstreamUrl &&
    subscriptionCache.body &&
    Date.now() - subscriptionCache.updatedAtMs < CACHE_TTL_MS

  if (cacheValid) {
    return { source: "memory-cache", body: subscriptionCache.body, contentType: subscriptionCache.contentType }
  }

  const headers = {
    "user-agent": "sevens-service-project/1.0",
    accept: "*/*",
    "accept-encoding": "identity",
  }

  if (subscriptionCache.upstreamUrl === upstreamUrl) {
    if (subscriptionCache.etag) headers["if-none-match"] = subscriptionCache.etag
    if (subscriptionCache.lastModified) headers["if-modified-since"] = subscriptionCache.lastModified
  }

  const resp = await fetchWithRedirects(upstreamUrl, headers)

  if (resp.statusCode === 304 && subscriptionCache.upstreamUrl === upstreamUrl && subscriptionCache.body) {
    subscriptionCache.updatedAtMs = Date.now()
    return { source: "upstream-304", body: subscriptionCache.body, contentType: subscriptionCache.contentType }
  }

  if (resp.statusCode < 200 || resp.statusCode >= 300) {
    const fallbackAvailable = subscriptionCache.upstreamUrl === upstreamUrl && subscriptionCache.body
    const error = new Error(`upstream status ${resp.statusCode}`)
    error.fallbackAvailable = fallbackAvailable
    throw error
  }

  const contentType = toHeaderString(resp.headers["content-type"]) || "text/plain; charset=utf-8"
  const etag = toHeaderString(resp.headers.etag)
  const lastModified = toHeaderString(resp.headers["last-modified"])

  subscriptionCache.upstreamUrl = upstreamUrl
  subscriptionCache.updatedAtMs = Date.now()
  subscriptionCache.body = resp.body
  subscriptionCache.contentType = contentType
  subscriptionCache.etag = etag
  subscriptionCache.lastModified = lastModified

  return { source: "upstream-200", body: resp.body, contentType }
}

function getBaseUrl(req) {
  const proto = req.protocol || "http"
  const host = req.get("host") || "localhost"
  return `${proto}://${host}`
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
}

app.get("/logout", (req, res) => {
  clearAdminSessionCookie(res)
  logWithTime("Admin logout", { ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress || "" })
  res.redirect("/")
})

app.post("/login", (req, res) => {
  if (!ADMIN_KEY) {
    res.status(500).type("text/plain; charset=utf-8").send("服务端未配置 ADMIN_KEY（环境变量或 data/admin-key.json），无法登录。")
    return
  }

  const password = typeof req.body.password === "string" ? req.body.password : ""
  if (password !== ADMIN_KEY) {
    logWithTime("Admin login failed", { ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress || "" })
    res.status(401).type("text/plain; charset=utf-8").send("密码错误")
    return
  }

  setAdminSessionCookie(res)
  logWithTime("Admin login success", { ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress || "" })
  res.redirect("/")
})

app.get("/", (req, res) => {
  if (ADMIN_KEY) {
    const key = readAdminKeyFromRequest(req)
    if (key && key === ADMIN_KEY) {
      setAdminSessionCookie(res)
      res.redirect("/")
      return
    }
  }

  const authed = isAdminAuthed(req)
  const baseUrl = getBaseUrl(req)
  const proxyUrl = `${baseUrl}/sub`

  if (!authed) {
    const html = `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Clash 订阅中转 - 登录</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, "PingFang SC", "Microsoft YaHei", sans-serif; padding: 24px; max-width: 900px; margin: 0 auto; background: #f9fafb; }
      .card { background: white; border: 1px solid #e5e7eb; border-radius: 12px; padding: 18px; }
      .title { margin: 0 0 12px; }
      label { display: block; font-weight: 600; margin-bottom: 8px; }
      input { width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 14px; }
      button { margin-top: 12px; padding: 10px 14px; border: none; border-radius: 8px; background: #111827; color: white; cursor: pointer; }
      .hint { color: #374151; line-height: 1.6; }
      code { background: #f3f4f6; padding: 2px 6px; border-radius: 6px; }
    </style>
  </head>
  <body>
    <h1 class="title">Clash 订阅中转</h1>
    <div class="card">
      <form method="post" action="/login">
        <label for="password">进入页面密码</label>
        <input id="password" name="password" type="password" placeholder="请输入密码" required autofocus />
        <button type="submit">登录</button>
      </form>
      <p class="hint">客户端订阅地址固定为：<code>${escapeHtml(proxyUrl)}</code></p>
    </div>
  </body>
</html>`
    res.type("text/html; charset=utf-8").send(html)
    return
  }

  const config = loadConfig()
  const html = `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Clash 订阅中转 - 主页面</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, "PingFang SC", "Microsoft YaHei", sans-serif; padding: 24px; max-width: 980px; margin: 0 auto; background: #f9fafb; }
      .topbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
      .title { margin: 0; }
      .card { background: white; border: 1px solid #e5e7eb; border-radius: 12px; padding: 18px; margin-top: 12px; }
      .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
      .grow { flex: 1 1 380px; }
      .label { display: block; font-weight: 600; margin-bottom: 8px; }
      input[type="url"], input[type="text"] { width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 14px; }
      button { padding: 10px 14px; border: none; border-radius: 8px; background: #111827; color: white; cursor: pointer; }
      button.secondary { background: #374151; }
      button.ghost { background: transparent; color: #111827; border: 1px solid #d1d5db; }
      button:disabled { opacity: 0.6; cursor: not-allowed; }
      code { background: #f3f4f6; padding: 2px 6px; border-radius: 6px; }
      .hint { color: #374151; line-height: 1.6; }
      .muted { color: #6b7280; }
      .hidden { display: none; }
      .status { margin-top: 10px; font-size: 13px; }
    </style>
  </head>
  <body>
    <div class="topbar">
      <h1 class="title">Clash 订阅中转</h1>
      <a class="muted" href="/logout">退出登录</a>
    </div>
    <div class="card">
      <div class="row">
        <div class="grow">
          <div class="label">Clash 客户端订阅地址（固定）</div>
          <input id="proxyUrl" type="text" readonly value="${escapeHtml(proxyUrl)}" />
        </div>
        <div>
          <div class="label">&nbsp;</div>
          <button id="copyProxyBtn" class="ghost" type="button">复制</button>
        </div>
      </div>
      <p class="hint">所有客户端都填上面这个地址。以后订阅源变化，只改下面的订阅源地址即可全体生效。</p>
    </div>

    <div class="card">
      <div class="row" style="justify-content: space-between;">
        <div>
          <div class="label">订阅源地址（会被中转）</div>
          <div class="muted">当前：<code id="currentUpstream">${escapeHtml(config.upstreamUrl || "未设置")}</code></div>
          <div class="muted">更新时间：<code id="currentUpdatedAt">${escapeHtml(config.updatedAt || "未设置")}</code></div>
        </div>
        <div>
          <button id="toggleConfigBtn" class="secondary" type="button">配置 Clash 地址</button>
        </div>
      </div>

      <div id="configPanel" class="hidden" style="margin-top: 14px;">
        <div class="row">
          <div class="grow">
            <div class="label">输入新的订阅源地址</div>
            <input id="upstreamInput" type="url" placeholder="https://example.com/xxx?token=..." value="${escapeHtml(
              config.upstreamUrl || ""
            )}" />
          </div>
          <div>
            <div class="label">&nbsp;</div>
            <button id="applyBtn" type="button">应用</button>
          </div>
        </div>
        <div id="status" class="status muted"></div>
      </div>
    </div>

    <div class="card">
      <div class="hint">
        <div>配置文件路径：<code>${escapeHtml(CONFIG_FILE)}</code></div>
        <div>缓存 TTL：<code>${escapeHtml(String(CACHE_TTL_MS))} ms</code></div>
      </div>
    </div>

    <script>
      const proxyUrlEl = document.getElementById("proxyUrl")
      const copyProxyBtn = document.getElementById("copyProxyBtn")
      const toggleConfigBtn = document.getElementById("toggleConfigBtn")
      const configPanel = document.getElementById("configPanel")
      const upstreamInput = document.getElementById("upstreamInput")
      const applyBtn = document.getElementById("applyBtn")
      const statusEl = document.getElementById("status")
      const currentUpstreamEl = document.getElementById("currentUpstream")
      const currentUpdatedAtEl = document.getElementById("currentUpdatedAt")

      function setStatus(text, isError) {
        statusEl.textContent = text || ""
        statusEl.className = "status " + (isError ? "" : "muted")
        if (isError) statusEl.style.color = "#b91c1c"
        else statusEl.style.color = ""
      }

      async function copyText(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text)
          return
        }
        const temp = document.createElement("textarea")
        temp.value = text
        temp.style.position = "fixed"
        temp.style.left = "-9999px"
        document.body.appendChild(temp)
        temp.focus()
        temp.select()
        document.execCommand("copy")
        document.body.removeChild(temp)
      }

      copyProxyBtn.addEventListener("click", async () => {
        try {
          await copyText(proxyUrlEl.value)
          setStatus("已复制订阅地址")
        } catch (e) {
          setStatus("复制失败：" + (e && e.message ? e.message : String(e)), true)
        }
      })

      toggleConfigBtn.addEventListener("click", () => {
        const visible = !configPanel.classList.contains("hidden")
        if (visible) {
          configPanel.classList.add("hidden")
        } else {
          configPanel.classList.remove("hidden")
          upstreamInput.focus()
        }
      })

      applyBtn.addEventListener("click", async () => {
        const upstreamUrl = (upstreamInput.value || "").trim()
        if (!upstreamUrl) {
          setStatus("请输入订阅源地址", true)
          return
        }

        applyBtn.disabled = true
        setStatus("正在应用...")
        try {
          const resp = await fetch("/api/config", {
            method: "POST",
            headers: { "content-type": "application/json", accept: "application/json" },
            body: JSON.stringify({ upstreamUrl }),
            credentials: "same-origin"
          })
          if (!resp.ok) {
            const text = await resp.text()
            throw new Error(text || ("HTTP " + resp.status))
          }
          const data = await resp.json()
          currentUpstreamEl.textContent = data.upstreamUrl || "未设置"
          currentUpdatedAtEl.textContent = data.updatedAt || "未设置"
          setStatus("已应用，所有客户端立即生效")
        } catch (e) {
          setStatus("应用失败：" + (e && e.message ? e.message : String(e)), true)
        } finally {
          applyBtn.disabled = false
        }
      })
    </script>
  </body>
</html>`
  res.type("text/html; charset=utf-8").send(html)
})

app.get("/admin", (req, res) => {
  res.redirect("/")
})

app.get("/api/config", requireAdmin, (req, res) => {
  const config = loadConfig()
  res.json({
    upstreamUrl: config.upstreamUrl,
    updatedAt: config.updatedAt,
    configFile: CONFIG_FILE,
    cacheTtlMs: CACHE_TTL_MS,
  })
})

app.post("/api/config", requireAdmin, (req, res) => {
  const upstreamUrl = typeof req.body.upstreamUrl === "string" ? req.body.upstreamUrl.trim() : ""
  const validation = validateHttpUrl(upstreamUrl)
  if (!upstreamUrl || !validation.ok) {
    res.status(400).type("text/plain; charset=utf-8").send(`upstreamUrl 无效：${validation.reason || "unknown"}`)
    return
  }

  const nextConfig = { upstreamUrl, updatedAt: nowIso() }
  saveConfig(nextConfig)
  logWithTime("Config updated", { upstreamUrl })

  if (subscriptionCache.upstreamUrl !== upstreamUrl) {
    subscriptionCache.upstreamUrl = upstreamUrl
    subscriptionCache.updatedAtMs = 0
    subscriptionCache.body = null
    subscriptionCache.contentType = ""
    subscriptionCache.etag = ""
    subscriptionCache.lastModified = ""
    logWithTime("Cache cleared due to upstream change", { upstreamUrl })
  }

  const accept = typeof req.headers.accept === "string" ? req.headers.accept : ""
  const contentType = typeof req.headers["content-type"] === "string" ? req.headers["content-type"] : ""
  const prefersJson = accept.includes("application/json") || contentType.includes("application/json")
  if (prefersJson) {
    res.json(nextConfig)
    return
  }

  res.redirect("/")
})

app.get("/sub", async (req, res) => {
  const config = loadConfig()
  if (!config.upstreamUrl) {
    res.status(404).type("text/plain; charset=utf-8").send("未配置订阅源地址，请先访问主页面 / 登录后设置订阅源地址。")
    return
  }

  try {
    const { source, body, contentType } = await getSubscriptionFromUpstream(config.upstreamUrl)
    res.setHeader("content-type", contentType)
    res.setHeader("cache-control", "no-store")
    res.setHeader("x-subscription-source", source)
    res.status(200).send(body)
  } catch (error) {
    const fallbackAvailable = Boolean(error && error.fallbackAvailable)
    if (fallbackAvailable && subscriptionCache.body) {
      res.setHeader("content-type", subscriptionCache.contentType || "text/plain; charset=utf-8")
      res.setHeader("cache-control", "no-store")
      res.setHeader("x-subscription-source", "cache-fallback")
      res.status(200).send(subscriptionCache.body)
      return
    }

    res
      .status(502)
      .type("text/plain; charset=utf-8")
      .send(`上游订阅拉取失败：${String(error && error.message ? error.message : error)}`)
  }
})

app.listen(PORT, () => {
  logWithTime("Server started", {
    url: `http://localhost:${PORT}`,
    port: PORT,
    configFile: CONFIG_FILE,
    cacheTtlMs: CACHE_TTL_MS,
    adminKeyConfigured: Boolean(ADMIN_KEY),
    adminKeySource: adminKeyInfo.source,
    adminKeyFile: adminKeyInfo.filePath,
  })
})
