const crypto = require("crypto");
const OWNER = process.env.GITHUB_OWNER;
const REPO = process.env.TOKEN_REPO || "ttken";
const BRANCH = process.env.TOKEN_BRANCH || "main";
const TOKEN_PATH = process.env.TOKEN_PATH || "token.json";

const ACCOUNT_REPO = process.env.ACCOUNT_REPO || "databaseaccount";
const ACCOUNT_PATH = process.env.ACCOUNT_PATH || "account.json";

function verifySignature(payload, signature) {
  const expected = crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(payload)
    .digest();

  let actual;

  try {
    actual = Buffer.from(signature, "base64url");
  } catch {
    return false;
  }

  return actual.length === expected.length &&
    crypto.timingSafeEqual(actual, expected);
}

function getCookie(req, name) {
  const cookies = String(req.headers.cookie || "").split(";");

  for (const cookie of cookies) {
    const index = cookie.indexOf("=");
    if (index < 0) continue;

    if (cookie.slice(0, index).trim() === name) {
      return cookie.slice(index + 1).trim();
    }
  }

  return "";
}

function decodeSession(req) {
  const parts = getCookie(req, "vk_session").split(".");
  if (parts.length !== 2) return null;

  const [payload, signature] = parts;

  if (!verifySignature(payload, signature)) return null;

  try {
    const session = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (!session.id ||
        !session.username ||
        !session.exp ||
        Date.now() >= session.exp) {
      return null;
    }

    return session;
  } catch {
    return null;
  }
}

function githubUrl(repo, path, branch) {
  const encodedPath = path
    .split("/")
    .map(encodeURIComponent)
    .join("/");

  return `https://api.github.com/repos/${OWNER}/${repo}/contents/` +
    `${encodedPath}?ref=${encodeURIComponent(branch)}`;
}

async function readGitHubFile(repo, path, branch) {
  const response = await fetch(githubUrl(repo, path, branch), {
    headers: {
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28"
    }
  });

  if (!response.ok) {
    throw new Error(`GitHub read failed: ${response.status}`);
  }

  const file = await response.json();

  return {
    sha: file.sha,
    data: JSON.parse(
      Buffer.from(file.content, "base64").toString("utf8")
    )
  };
}

async function verifyDeveloper(req) {
  const session = decodeSession(req);
  if (!session) return null;

  const result = await readGitHubFile(
    ACCOUNT_REPO,
    ACCOUNT_PATH,
    process.env.ACCOUNT_BRANCH || "main"
  );

  const database = result.data;
  const accounts = Array.isArray(database.accounts)
    ? database.accounts
    : [];

  const account = accounts.find(item =>
    String(item.id || "") === session.id &&
    String(item.username || "").toLowerCase() ===
      session.username.toLowerCase()
  );

  if (!account) return null;

  if (database.bannedUsers?.[session.id]) return null;

  if (String(account.role || "").toLowerCase() !== "developer") {
    return null;
  }

  return account;
}

async function writeTokenFile(data, sha) {
  const url =
    `https://api.github.com/repos/${OWNER}/${REPO}/contents/` +
    TOKEN_PATH.split("/").map(encodeURIComponent).join("/");

  const body = {
    message: "Update token database via VeronixKyzooxd",
    content: Buffer.from(
      JSON.stringify(data, null, 2) + "\n"
    ).toString("base64"),
    branch: BRANCH,
    sha
  };

  const response = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2022-11-28"
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    const details = await response.text();
    console.error("GitHub write error:", response.status, details);

    if (response.status === 409 || response.status === 422) {
      throw new Error(
        "Database berubah atau GitHub menolak pembaruan. Muat ulang lalu coba lagi."
      );
    }

    throw new Error("Gagal menyimpan perubahan ke GitHub.");
  }
}

function normalizeEntry(entry) {
  if (typeof entry === "string") return entry;
  if (entry && typeof entry === "object") {
    return String(entry.token || "");
  }
  return "";
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, private");
  res.setHeader("Vary", "Cookie");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");

  if (!["GET", "POST", "DELETE"].includes(req.method)) {
    res.setHeader("Allow", "GET, POST, DELETE");
    return res.status(405).json({ error: "Method tidak diizinkan." });
  }

  if (!OWNER || !process.env.GITHUB_TOKEN ||
      !process.env.SESSION_SECRET) {
    return res.status(500).json({
      error: "Konfigurasi backend belum lengkap."
    });
  }

  try {
    const account = await verifyDeveloper(req);

    if (!account) {
      return res.status(403).json({
        error: "Akses ditolak. Hanya akun developer aktif yang diizinkan."
      });
    }

    const file = await readGitHubFile(REPO, TOKEN_PATH, BRANCH);
    const database = file.data;

    if (!database || typeof database !== "object" ||
        Array.isArray(database)) {
      return res.status(500).json({
        error: "Format token.json tidak valid."
      });
    }

    if (!Array.isArray(database.tokens)) {
      database.tokens = [];
    }

    if (req.method === "GET") {
      return res.status(200).json({
        tokens: database.tokens,
        updatedAt: database.updatedAt || null
      });
    }

    if (req.method === "POST") {
      const value = String(req.body?.token || "").trim();

      if (!value || value.length > 2000) {
        return res.status(400).json({
          error: "Token wajib diisi dan maksimal 2000 karakter."
        });
      }

      const exists = database.tokens.some(
        entry => normalizeEntry(entry) === value
      );

      if (exists) {
        return res.status(409).json({
          error: "Token tersebut sudah ada."
        });
      }

      database.tokens.push(value);
      database.updatedAt = new Date().toISOString();

      await writeTokenFile(database, file.sha);

      return res.status(200).json({
        ok: true,
        message: "Token berhasil disimpan ke GitHub.",
        count: database.tokens.length
      });
    }

    const index = Number(req.body?.index);

    if (!Number.isInteger(index) ||
        index < 0 ||
        index >= database.tokens.length) {
      return res.status(400).json({
        error: "Indeks token tidak valid."
      });
    }

    database.tokens.splice(index, 1);
    database.updatedAt = new Date().toISOString();

    await writeTokenFile(database, file.sha);

    return res.status(200).json({
      ok: true,
      message: "Token berhasil dihapus dari GitHub.",
      count: database.tokens.length
    });
  } catch (error) {
    console.error("Token API error:", error.message);

    return res.status(500).json({
      error: error.message || "Terjadi kesalahan pada server."
    });
  }
};
