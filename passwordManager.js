const fs = require("node:fs")
const path = require("node:path")

const PASSWORD_DIR = path.join(process.cwd(), "data")
const ADMIN_KEY_FILE = path.join(PASSWORD_DIR, "admin-key.json")

function ensurePasswordDir() {
  if (!fs.existsSync(PASSWORD_DIR)) {
    fs.mkdirSync(PASSWORD_DIR, { recursive: true })
  }
}

function loadAdminKeyFromFile() {
  ensurePasswordDir()
  if (!fs.existsSync(ADMIN_KEY_FILE)) return ""

  const raw = fs.readFileSync(ADMIN_KEY_FILE, "utf8").trim()
  if (!raw) return ""

  if (raw.startsWith("{")) {
    const parsed = JSON.parse(raw)
    const key = typeof parsed.adminKey === "string" ? parsed.adminKey.trim() : ""
    return key
  }

  return raw
}

function loadAdminKey() {
  const envKey = typeof process.env.ADMIN_KEY === "string" ? process.env.ADMIN_KEY.trim() : ""
  if (envKey) {
    return { adminKey: envKey, source: "env", filePath: ADMIN_KEY_FILE }
  }

  try {
    const fileKey = loadAdminKeyFromFile()
    if (fileKey) return { adminKey: fileKey, source: "file", filePath: ADMIN_KEY_FILE }
  } catch {
    return { adminKey: "", source: "error", filePath: ADMIN_KEY_FILE }
  }

  return { adminKey: "", source: "none", filePath: ADMIN_KEY_FILE }
}

function saveAdminKey(adminKey) {
  ensurePasswordDir()
  const key = typeof adminKey === "string" ? adminKey.trim() : ""
  const data = JSON.stringify({ adminKey: key, updatedAt: new Date().toISOString() }, null, 2)
  fs.writeFileSync(ADMIN_KEY_FILE, data, "utf8")
  return { filePath: ADMIN_KEY_FILE }
}

module.exports = {
  ADMIN_KEY_FILE,
  loadAdminKey,
  saveAdminKey,
}
