const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// ===== DATABASE =====
const db = new Pool({
  user: "postgres",
  host: "localhost",
  database: "sports_db",
  password: "1234",
  port: 5432,
});

// ===== INIT DATABASE TABLES =====
async function initDB() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        phone VARCHAR(20) UNIQUE,
        password TEXT
      );

      CREATE TABLE IF NOT EXISTS judges (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        username VARCHAR(50) UNIQUE,
        password TEXT
      );

      CREATE TABLE IF NOT EXISTS sports (
        id SERIAL PRIMARY KEY,
        title VARCHAR(50) UNIQUE
      );

      CREATE TABLE IF NOT EXISTS registrations (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        sport_id INT REFERENCES sports(id) ON DELETE CASCADE,
        UNIQUE (user_id, sport_id)
      );
    `);

    // Initial sports (давхцахгүй)
    await db.query(`
      INSERT INTO sports (title)
      VALUES ('Basketball'), ('Volleyball')
      ON CONFLICT (title) DO NOTHING
    `);

    console.log("Tables checked/created successfully");
  } catch (err) {
    console.error("DB init error:", err.message);
  }
}

// Server асахад table шалгана
initDB();


// ===== SECRETS =====
const USER_SECRET = "USER_SECRET";
const JUDGE_SECRET = "JUDGE_SECRET";

// ================= USERS =================
app.post("/register", async (req, res) => {
  const { name, phone, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await db.query(
      "INSERT INTO users (name, phone, password) VALUES ($1,$2,$3)",
      [name, phone, hash]
    );
    res.json({ success: true });
  } catch {
    res.status(400).json({ error: "User exists" });
  }
});

app.post("/login", async (req, res) => {
  const { phone, password } = req.body;
  const result = await db.query(
    "SELECT * FROM users WHERE phone=$1",
    [phone]
  );
  if (result.rows.length === 0)
    return res.status(401).json({ error: "User not found" });

  const valid = await bcrypt.compare(password, result.rows[0].password);
  if (!valid)
    return res.status(401).json({ error: "Wrong password" });

  const token = jwt.sign(
    { id: result.rows[0].id, role: "user" },
    USER_SECRET
  );
  res.json({ token });
});

// ================= JUDGES =================
app.post("/judge/register", async (req, res) => {
  const { name, username, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await db.query(
      "INSERT INTO judges (name, username, password) VALUES ($1,$2,$3)",
      [name, username, hash]
    );
    res.json({ success: true });
  } catch {
    res.status(400).json({ error: "Judge exists" });
  }
});

app.post("/judge/login", async (req, res) => {
  const { username, password } = req.body;
  const result = await db.query(
    "SELECT * FROM judges WHERE username=$1",
    [username]
  );
  if (result.rows.length === 0)
    return res.status(401).json({ error: "Judge not found" });

  const valid = await bcrypt.compare(password, result.rows[0].password);
  if (!valid)
    return res.status(401).json({ error: "Wrong password" });

  const token = jwt.sign(
    { id: result.rows[0].id, role: "judge" },
    JUDGE_SECRET
  );
  res.json({ token });
});

// ================= AUTH =================
function userAuth(req, res, next) {
  try {
    req.user = jwt.verify(req.headers.authorization, USER_SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
}

function judgeAuth(req, res, next) {
  try {
    req.judge = jwt.verify(req.headers.authorization, JUDGE_SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
}

// ================= SPORTS =================
app.get("/sports", async (req, res) => {
  const result = await db.query("SELECT * FROM sports");
  res.json(result.rows);
});

app.post("/join", userAuth, async (req, res) => {
  const { sport_id } = req.body;
  try {
    await db.query(
      "INSERT INTO registrations (user_id, sport_id) VALUES ($1,$2)",
      [req.user.id, sport_id]
    );
    res.json({ success: true });
  } catch {
    res.status(400).json({ error: "Already joined" });
  }
});

// ================= JUDGE VIEW =================
app.get("/judge/registrations", judgeAuth, async (req, res) => {
  const result = await db.query(`
    SELECT u.name, u.phone, s.title
    FROM registrations r
    JOIN users u ON r.user_id=u.id
    JOIN sports s ON r.sport_id=s.id
  `);
  res.json(result.rows);
});

// ================= SERVER =================
app.listen(3000, () =>
  console.log("🚀 Server running on http://localhost:3000")
);