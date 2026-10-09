const crypto = require("crypto");

const ACCOUNT_PATH = process.env.ACCOUNT_PATH || "account.json";
const SESSION_COOKIE = "vk_session";
const SESSION_DURATION = 8 * 60 * 60 * 1000;

function sign(value) {
  return crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(value)
    .digest("base64url");
}

function makeCookie(value, maxAge) {
  return [
    `${SESSION_COOKIE}=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    `Max-Age=${maxAge}`
  ].join("; ");
}

async function githubFile(path) {
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.ACCOUNT_REPO || "databaseaccount";
  const branch = process.env.GITHUB_BRANCH || "main";

  const encodedPath = path
    .split("/")
    .map(encodeURIComponent)
    .join("/");

  const url =
    `https://api.github.com/repos/${owner}/${repo}/contents/` +
    `${encodedPath}?ref=${encodeURIComponent(branch)}`;

  const response = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "VeronixKyzooxd"
    }
  });

  if (!response.ok) {
    const errorText = await response.text();

    console.error(
      "[LOGIN GITHUB]",
      response.status,
      errorText.slice(0, 500)
    );

    throw new Error("Gagal membaca database akun GitHub.");
  }

  const file = await response.json();

  if (!file.content || file.encoding !== "base64") {
    throw new Error("Format file database GitHub tidak valid.");
  }

  const content = Buffer.from(file.content, "base64").toString("utf8");

  return JSON.parse(content);
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  // Periksa environment variables yang wajib tersedia.
  const required = [
    "SESSION_SECRET",
    "GITHUB_TOKEN",
    "GITHUB_OWNER"
  ];

  const missing = required.filter((key) => {
    const value = process.env[key];
    return typeof value !== "string" || value.trim() === "";
  });

  if (missing.length > 0) {
    console.error(
      "[LOGIN CONFIG] Environment variables belum tersedia:",
      missing.join(", ")
    );

    return res.status(500).json({
      error: "Konfigurasi backend belum lengkap.",
      missing
    });
  }

  // Logout.
  if (req.method === "DELETE") {
    res.setHeader("Set-Cookie", makeCookie("", 0));

    return res.status(200).json({
      ok: true,
      message: "Logout berhasil."
    });
  }

  // Login hanya menerima POST.
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, DELETE");

    return res.status(405).json({
      error: "Method tidak diizinkan."
    });
  }

  try {
    const body =
      typeof req.body === "string"
        ? JSON.parse(req.body)
        : req.body || {};

    const username = String(body.username || "").trim();
    const accountKey = String(body.accountKey || "");

    if (
      !username ||
      !accountKey ||
      username.length > 100 ||
      accountKey.length > 500
    ) {
      return res.status(400).json({
        error: "Username dan Account Key wajib diisi."
      });
    }

    // Ambil database akun dari GitHub.
    const database = await githubFile(ACCOUNT_PATH);

    if (
      !database ||
      typeof database !== "object" ||
      !Array.isArray(database.accounts)
    ) {
      console.error("[LOGIN] Struktur database akun tidak valid.");

      return res.status(500).json({
        error: "Format database akun tidak valid."
      });
    }

    // Cari akun berdasarkan username dan Account Key.
    const account = database.accounts.find((item) => {
      return (
        String(item.username || "").toLowerCase() ===
          username.toLowerCase() &&
        String(item.accountKey || "") === accountKey
      );
    });

    if (!account || !account.id) {
      return res.status(401).json({
        error: "Username atau Account Key salah."
      });
    }

    // Periksa apakah akun dinonaktifkan.
    const bannedUsers = database.bannedUsers || {};

    if (bannedUsers[String(account.id)]) {
      return res.status(403).json({
        error: "Akun ini sedang dinonaktifkan."
      });
    }

    // Buat data session.
    const now = Date.now();

    const session = {
      id: String(account.id),
      username: String(account.username),
      iat: now,
      exp: now + SESSION_DURATION
    };

    const payload = Buffer
      .from(JSON.stringify(session))
      .toString("base64url");

    const signature = sign(payload);
    const sessionToken = `${payload}.${signature}`;

    // Simpan session melalui cookie HttpOnly.
    res.setHeader(
      "Set-Cookie",
      makeCookie(sessionToken, SESSION_DURATION / 1000)
    );

    return res.status(200).json({
      ok: true,
      message: "Login berhasil.",
      account: {
        id: session.id,
        username: session.username
      },
      redirect: "kyzo.html"
    });
  } catch (error) {
    console.error("[LOGIN ERROR]", error.message);

    return res.status(500).json({
      error: "Login gagal karena database tidak dapat diverifikasi."
    });
  }
};
