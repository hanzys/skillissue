```javascript
const crypto = require("crypto");

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, private");
  res.setHeader("Vary", "Cookie");

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method tidak diizinkan." });
  }

  try {
    const secret = process.env.SESSION_SECRET;
    const cookieHeader = String(req.headers.cookie || "");
    const cookie = cookieHeader.split(";")
      .map(value => value.trim())
      .find(value => value.startsWith("vk_session="));

    if (!secret || !process.env.GITHUB_TOKEN ||
        !process.env.GITHUB_OWNER || !cookie) {
      return res.status(401).json({ error: "Silakan login kembali." });
    }

    const token = cookie.slice("vk_session=".length);
    const parts = token.split(".");
    if (parts.length !== 2) {
      return res.status(401).json({ error: "Sesi tidak valid." });
    }

    const [payload, signature] = parts;
    const expected = crypto.createHmac("sha256", secret)
      .update(payload).digest();

    const actual = Buffer.from(signature, "base64url");

    if (actual.length !== expected.length ||
        !crypto.timingSafeEqual(actual, expected)) {
      return res.status(401).json({ error: "Sesi tidak valid." });
    }

    const session = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (!session.id || !session.username ||
        !session.exp || Date.now() >= session.exp) {
      return res.status(401).json({ error: "Sesi telah berakhir." });
    }

    const owner = process.env.GITHUB_OWNER;
    const repo = process.env.ACCOUNT_REPO || "databaseaccount";
    const path = (process.env.ACCOUNT_PATH || "account.json")
      .split("/").map(encodeURIComponent).join("/");
    const branch = process.env.ACCOUNT_BRANCH || "main";

    const url =
      `https://api.github.com/repos/${owner}/${repo}/contents/${path}` +
      `?ref=${encodeURIComponent(branch)}`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
      }
    });

    if (!response.ok) {
      throw new Error("Database akun tidak dapat diverifikasi.");
    }

    const file = await response.json();
    const database = JSON.parse(
      Buffer.from(file.content, "base64").toString("utf8")
    );

    const accounts = Array.isArray(database.accounts)
      ? database.accounts : [];

    const account = accounts.find(item =>
      String(item.id || "") === String(session.id) &&
      String(item.username || "").toLowerCase() ===
        String(session.username).toLowerCase()
    );

    if (!account || database.bannedUsers?.[String(session.id)]) {
      res.setHeader("Set-Cookie",
        "vk_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
      return res.status(401).json({
        error: "Akun tidak ditemukan atau telah dinonaktifkan."
      });
    }

    return res.status(200).json({
      account: {
        id: String(account.id),
        username: String(account.username),
        role: String(account.role || "reseller")
      }
    });
  } catch (error) {
    console.error("Session verification error:", error.message);
    return res.status(500).json({
      error: "Gagal memverifikasi sesi."
    });
  }
};
```
