const { neon } = require("@neondatabase/serverless");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

function getSql() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is not configured");
  }
  return neon(process.env.DATABASE_URL);
}

function prepare(req, res) {
  const origin = req.headers.origin;
  
const allowed = [
  "https://ano18391.github.io",
  "https://solid-pancake-xrp7g9gvw6p6cpxw7-8000.app.github.dev",
  "http://localhost:8000",
  "http://127.0.0.1:8000"
];

  if (origin && allowed.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }

  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return true;
  }

  return false;
}

function send(res, status, body) {
  return res.status(status).json(body);
}

function validateUsername(username) {
  return typeof username === "string"
    && /^[A-Za-z0-9_.-]{3,24}$/.test(username);
}

function validatePassword(password) {
  return typeof password === "string"
    && password.length >= 10
    && password.length <= 128;
}

function makeRecoveryCode() {
  const value = crypto.randomBytes(10).toString("hex").toUpperCase();
  return `PF-${value.match(/.{1,5}/g).join("-")}`;
}

function signToken(payload) {
  const secret = process.env.SESSION_SECRET;

  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new Error("SESSION_SECRET must contain at least 32 bytes");
  }

  const encoded = Buffer.from(JSON.stringify({
    ...payload,
    exp: Math.floor(Date.now() / 1000) + payload.duration
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", secret)
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${signature}`;
}

function verifyToken(token, purpose) {
  try {
    const secret = process.env.SESSION_SECRET;
    if (!secret || typeof token !== "string") return null;

    const parts = token.split(".");
    if (parts.length !== 2) return null;

    const expected = crypto.createHmac("sha256", secret)
      .update(parts[0]).digest();

    const actual = Buffer.from(parts[1], "base64url");

    if (actual.length !== expected.length
      || !crypto.timingSafeEqual(actual, expected)) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(parts[0], "base64url").toString("utf8")
    );

    if (payload.exp <= Math.floor(Date.now() / 1000)) return null;
    if (payload.purpose !== purpose) return null;

    return payload;
  } catch {
    return null;
  }
}

function setSessionCookie(res, user) {
  const token = signToken({
    purpose: "session",
    userId: user.id,
    username: user.username,
    duration: 7 * 24 * 60 * 60
  });

  res.setHeader(
    "Set-Cookie",
    `pf_session=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=604800`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    "pf_session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0"
  );
}

function getCookie(req, name) {
  const header = req.headers.cookie || "";
  const entry = header.split("; ").find(part => part.startsWith(`${name}=`));
  return entry ? decodeURIComponent(entry.slice(name.length + 1)) : null;
}

function getSession(req) {
  return verifyToken(getCookie(req, "pf_session"), "session");
}

module.exports = {
  getSql,
  bcrypt,
  crypto,
  prepare,
  send,
  validateUsername,
  validatePassword,
  makeRecoveryCode,
  signToken,
  verifyToken,
  setSessionCookie,
  clearSessionCookie,
  getSession
};
