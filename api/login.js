const crypto = require("crypto");

const ACCOUNT_PATH = process.env.ACCOUNT_PATH || "account.json";

function sign(value) {
  return crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(value)
    .digest("base64url");
}

function makeCookie(value, maxAge) {
  return [
    `vk_session=${value}`,
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

  const url =
    `https://api.github.com/repos/${owner}/${repo}/contents/` +
    `${path.split("/").map(encodeURIComponent).join("/")}` +
    `?ref=${encodeURIComponent(branch)}`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28"
    }
  });

  if (!response.ok) {
    throw new Error("Gagal membaca database akun GitHub.");
  }

  const file = await response.json();
  return JSON.parse(
    Buffer.from(file.content, "base64").toString("utf8")
  );
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (!process.env.SESSION_SECRET ||
      !process.env.GITHUB_TOKEN ||
      !process.env.GITHUB_OWNER) {
    return res.status(500).json({
      error: "Konfigurasi backend belum lengkap."
    });
  }

  if (req.method === "DELETE") {
    res.setHeader("Set-Cookie", makeCookie("", 0));
    return res.status(200).json({ ok: true });
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, DELETE");
    return res.status(405).json({ error: "Method tidak diizinkan." });
  }

  try {
    const username = String(req.body?.username || "").trim();
    const accountKey = String(req.body?.accountKey || "");

    if (!username || !accountKey ||
        username.length > 100 || accountKey.length > 500) {
      return res.status(400).json({
        error: "Username dan Account Key wajib diisi."
      });
    }

    const database = await githubFile(ACCOUNT_PATH);
    const accounts = Array.isArray(database.accounts)
      ? database.accounts
      : [];

    const account = accounts.find(item =>
      String(item.username || "").toLowerCase() ===
        username.toLowerCase() &&
      String(item.accountKey || "") === accountKey
    );

    if (!account || !account.id) {
      return res.status(401).json({
        error: "Username atau Account Key salah."
      });
    }

    if (database.bannedUsers &&
        database.bannedUsers[String(account.id)]) {
      return res.status(403).json({
        error: "Akun ini sedang dinonaktifkan."
      });
    }

    const session = {
      id: String(account.id),
      username: String(account.username),
      iat: Date.now(),
      exp: Date.now() + 8 * 60 * 60 * 1000
    };

    const payload = Buffer.from(JSON.stringify(session))
      .toString("base64url");

    const token = `${payload}.${sign(payload)}`;

    res.setHeader("Set-Cookie", makeCookie(token, 8 * 60 * 60));

    return res.status(200).json({
      ok: true,
      account: {
        id: session.id,
        username: session.username
      },
      redirect: "kyzo.html"
    });
  } catch (error) {
    console.error("Login error:", error.message);
    return res.status(500).json({
      error: "Login gagal karena database tidak dapat diverifikasi."
    });
  }
};
