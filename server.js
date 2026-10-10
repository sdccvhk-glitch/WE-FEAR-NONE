const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "delta.db");
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  name: "delta.sid",
  secret: process.env.SESSION_SECRET || "DEVELOPMENT_ONLY_change_SESSION_SECRET",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 1000 * 60 * 60 * 8 }
}));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/", rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0),
 role TEXT NOT NULL DEFAULT 'user',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS referrals (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 code TEXT NOT NULL UNIQUE,
 balance INTEGER NOT NULL CHECK(balance >= 0),
 max_uses INTEGER NOT NULL DEFAULT 1,
 uses INTEGER NOT NULL DEFAULT 0,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '',
 price INTEGER NOT NULL CHECK(price >= 0),
 duration TEXT NOT NULL DEFAULT '1 Hour',
 devices INTEGER NOT NULL DEFAULT 1 CHECK(devices > 0),
 active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 product_id INTEGER NOT NULL REFERENCES products(id),
 price INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 license_key TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const count = db.prepare("SELECT COUNT(*) n FROM users").get().n;
if (!count) {
  const username = process.env.ADMIN_USERNAME || "admin";
  const password = process.env.ADMIN_PASSWORD || "change-me-now";
  db.prepare("INSERT INTO users(username,password_hash,balance,role) VALUES(?,?,0,'admin')")
    .run(username, bcrypt.hashSync(password, 12));
  db.prepare("INSERT INTO products(name,description,price,duration,devices) VALUES(?,?,?,?,?)")
    .run("PUBG Example", "Demo product — configure only products you are authorized to sell.", 1000, "1 Hour", 1);
}

const safeUser = u => ({ id: u.id, username: u.username, balance: u.balance, role: u.role });
const currentUser = req => req.session.userId ? db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId) : null;
const requireLogin = (req,res,next) => currentUser(req) ? next() : res.status(401).json({ error: "Please log in." });
const requireAdmin = (req,res,next) => {
  const u = currentUser(req);
  if (!u || u.role !== "admin") return res.status(403).json({ error: "Admin access required." });
  next();
};
const cleanCode = s => String(s || "").trim().toUpperCase();
const transaction = db.transaction(fn => fn());

app.get("/api/me", (req,res) => {
  const u = currentUser(req);
  res.json({ user: u ? safeUser(u) : null });
});

app.post("/api/register", rateLimit({ windowMs: 15 * 60_000, limit: 10 }), (req,res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const code = cleanCode(req.body.referralCode);
  if (!/^[a-zA-Z0-9_]{3,24}$/.test(username) || password.length < 10 || password.length > 200 || !code)
    return res.status(400).json({ error: "Use a 3–24 character username, a password of at least 10 characters, and a referral code." });
  const ref = db.prepare("SELECT * FROM referrals WHERE code=? AND active=1 AND uses<max_uses").get(code);
  if (!ref) return res.status(400).json({ error: "Referral code is invalid, inactive, or used up." });
  try {
    const result = transaction(() => {
      const user = db.prepare("INSERT INTO users(username,password_hash,balance,role) VALUES(?,?,?,'user')")
        .run(username, bcrypt.hashSync(password, 12), ref.balance);
      db.prepare("UPDATE referrals SET uses=uses+1 WHERE id=?").run(ref.id);
      return db.prepare("SELECT * FROM users WHERE id=?").get(user.lastInsertRowid);
    })();
    req.session.userId = result.id;
    res.json({ user: safeUser(result) });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) return res.status(409).json({ error: "Username already exists." });
    res.status(500).json({ error: "Registration failed." });
  }
});

app.post("/api/login", rateLimit({ windowMs: 15 * 60_000, limit: 20 }), (req,res) => {
  const u = db.prepare("SELECT * FROM users WHERE username=?").get(String(req.body.username || "").trim());
  if (!u || !bcrypt.compareSync(String(req.body.password || ""), u.password_hash))
    return res.status(401).json({ error: "Incorrect username or password." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start session." });
    req.session.userId = u.id;
    res.json({ user: safeUser(u) });
  });
});

app.post("/api/logout", (req,res) => req.session.destroy(() => res.json({ ok: true })));
app.get("/api/products", (req,res) => res.json({ products: db.prepare("SELECT id,name,description,price,duration,devices FROM products WHERE active=1 ORDER BY id DESC").all() }));
app.get("/api/orders", requireLogin, (req,res) => {
  const u = currentUser(req);
  const orders = u.role === "admin"
    ? db.prepare("SELECT o.*,u.username,p.name product_name FROM orders o JOIN users u ON u.id=o.user_id JOIN products p ON p.id=o.product_id ORDER BY o.id DESC LIMIT 100").all()
    : db.prepare("SELECT o.*,p.name product_name FROM orders o JOIN products p ON p.id=o.product_id WHERE o.user_id=? ORDER BY o.id DESC").all(u.id);
  res.json({ orders });
});

/* Key issuance is intentionally not faked. A purchase is recorded as pending
   until a provider-authorized integration is implemented and tested. */
app.post("/api/purchase", requireLogin, (req,res) => {
  const u = currentUser(req);
  if (u.role === "admin") return res.status(400).json({ error: "Use a customer account to test purchases." });
  const productId = Number(req.body.productId);
  const p = db.prepare("SELECT * FROM products WHERE id=? AND active=1").get(productId);
  if (!p) return res.status(404).json({ error: "Product not found." });
  if (u.balance < p.price) return res.status(400).json({ error: "Insufficient balance." });
  const orderId = transaction(() => {
    const changed = db.prepare("UPDATE users SET balance=balance-? WHERE id=? AND balance>=?").run(p.price,u.id,p.price);
    if (!changed.changes) throw new Error("INSUFFICIENT");
    const result = db.prepare("INSERT INTO orders(user_id,product_id,price,status) VALUES(?,?,?,'pending')").run(u.id,p.id,p.price);
    return result.lastInsertRowid;
  })();
  res.status(202).json({ orderId, status: "pending", message: "Order recorded. Key issuance is not connected yet; an admin must complete delivery." });
});

app.get("/api/admin/summary", requireAdmin, (req,res) => {
  res.json({
    users: db.prepare("SELECT id,username,balance,role,created_at FROM users ORDER BY id DESC").all(),
    products: db.prepare("SELECT * FROM products ORDER BY id DESC").all(),
    referrals: db.prepare("SELECT * FROM referrals ORDER BY id DESC").all(),
    orders: db.prepare("SELECT o.*,u.username,p.name product_name FROM orders o JOIN users u ON u.id=o.user_id JOIN products p ON p.id=o.product_id ORDER BY o.id DESC LIMIT 200").all()
  });
});
app.post("/api/admin/products", requireAdmin, (req,res) => {
  const name = String(req.body.name || "").trim();
  const description = String(req.body.description || "").trim();
  const price = Number(req.body.price);
  const duration = String(req.body.duration || "1 Hour").trim();
  const devices = Number(req.body.devices || 1);
  if (!name || name.length > 100 || !Number.isSafeInteger(price) || price < 0 || !Number.isInteger(devices) || devices < 1 || devices > 20)
    return res.status(400).json({ error: "Enter a product name, price in paise, and device count 1–20." });
  const result = db.prepare("INSERT INTO products(name,description,price,duration,devices) VALUES(?,?,?,?,?)").run(name,description,price,duration,devices);
  res.json({ id: result.lastInsertRowid });
});
app.patch("/api/admin/products/:id", requireAdmin, (req,res) => {
  const id = Number(req.params.id);
  const p = db.prepare("SELECT * FROM products WHERE id=?").get(id);
  if (!p) return res.status(404).json({ error: "Product not found." });
  const name = String(req.body.name ?? p.name).trim();
  const description = String(req.body.description ?? p.description).trim();
  const price = Number(req.body.price ?? p.price);
  const duration = String(req.body.duration ?? p.duration).trim();
  const devices = Number(req.body.devices ?? p.devices);
  const active = req.body.active === undefined ? p.active : (req.body.active ? 1 : 0);
  if (!name || !Number.isSafeInteger(price) || price < 0 || !Number.isInteger(devices) || devices < 1 || devices > 20)
    return res.status(400).json({ error: "Invalid product values." });
  db.prepare("UPDATE products SET name=?,description=?,price=?,duration=?,devices=?,active=? WHERE id=?").run(name,description,price,duration,devices,active,id);
  res.json({ ok: true });
});
app.post("/api/admin/referrals", requireAdmin, (req,res) => {
  const code = cleanCode(req.body.code);
  const balance = Number(req.body.balance);
  const maxUses = Number(req.body.maxUses || 1);
  if (!/^[A-Z0-9_-]{4,32}$/.test(code) || !Number.isSafeInteger(balance) || balance < 0 || !Number.isInteger(maxUses) || maxUses < 1 || maxUses > 10000)
    return res.status(400).json({ error: "Use a 4–32 character code, non-negative balance in paise, and max uses 1–10000." });
  try {
    const r = db.prepare("INSERT INTO referrals(code,balance,max_uses) VALUES(?,?,?)").run(code,balance,maxUses);
    res.json({ id: r.lastInsertRowid });
  } catch {
    res.status(409).json({ error: "Referral code already exists." });
  }
});
app.post("/api/admin/users/:id/balance", requireAdmin, (req,res) => {
  const amount = Number(req.body.balance);
  if (!Number.isSafeInteger(amount) || amount < 0) return res.status(400).json({ error: "Balance must be a non-negative integer in paise." });
  const r = db.prepare("UPDATE users SET balance=? WHERE id=?").run(amount,Number(req.params.id));
  if (!r.changes) return res.status(404).json({ error: "User not found." });
  res.json({ ok: true });
});
app.post("/api/admin/orders/:id/deliver", requireAdmin, (req,res) => {
  const key = String(req.body.key || "").trim();
  if (!key || key.length > 500) return res.status(400).json({ error: "Enter the issued key." });
  const r = db.prepare("UPDATE orders SET license_key=?,status='delivered' WHERE id=? AND status='pending'").run(key,Number(req.params.id));
  if (!r.changes) return res.status(409).json({ error: "Order not found or already processed." });
  res.json({ ok: true });
});
app.get("*", (req,res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.listen(PORT, "0.0.0.0", () => console.log(`DELTA.KEYS listening on ${PORT}`));
