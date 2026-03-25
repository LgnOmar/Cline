const express = require("express");
const sqlite3 = require("better-sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = "supersecretkey"; // Replace with a strong, environment-specific key

app.use(express.json());

// Database setup
const db = new sqlite3("database.db");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    completed BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS user_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    activity_type TEXT NOT NULL, /* e.g., 'login', 'registration' */
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Middleware for authenticating JWT tokens
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401); // No token

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403); // Invalid token
    req.user = user;
    next();
  });
};

// User Registration
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const stmt = db.prepare(
      "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"
    );
    const info = stmt.run(username, email, hashedPassword);
    const userId = info.lastInsertRowid;

    db.prepare(
      "INSERT INTO user_activity (user_id, activity_type) VALUES (?, ?)"
    ).run(userId, "registration");

    res.status(201).send("User registered successfully");
  } catch (error) {
    if (error.message.includes("UNIQUE constraint failed")) {
      return res.status(409).send("Username or email already exists");
    }
    res.status(500).send("Server error");
  }
});

// User Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const stmt = db.prepare("SELECT * FROM users WHERE username = ?");
    const user = stmt.get(username);

    if (!user) {
      return res.status(400).send("Invalid credentials");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).send("Invalid credentials");
    }

    const accessToken = jwt.sign(
      { id: user.id, username: user.username },
      SECRET_KEY
    );

    db.prepare(
      "INSERT INTO user_activity (user_id, activity_type) VALUES (?, ?)"
    ).run(user.id, "login");

    res.json({ accessToken });
  } catch (error) {
    res.status(500).send("Server error");
  }
});

// Get User Activity (for dashboard)
app.get("/dashboard/activity", authenticateToken, (req, res) => {
  try {
    const activities = db
      .prepare(
        "SELECT * FROM user_activity WHERE user_id = ? ORDER BY timestamp DESC"
      )
      .all(req.user.id);
    res.json(activities);
  } catch (error) {
    res.status(500).send("Server error");
  }
});

// Get All Users (for dashboard, requires admin-like privileges in a real app)
app.get("/dashboard/users", authenticateToken, (req, res) => {
  // In a real application, you'd add authorization logic here to ensure only admins can view all users
  try {
    const users = db.prepare("SELECT id, username, email FROM users").all();
    res.json(users);
  } catch (error) {
    res.status(500).send("Server error");
  }
});

// To-Do Endpoints
app.post("/todos", authenticateToken, (req, res) => {
  const { title } = req.body;
  try {
    const stmt = db.prepare(
      "INSERT INTO todos (user_id, title) VALUES (?, ?)"
    );
    const info = stmt.run(req.user.id, title);
    res.status(201).json({ id: info.lastInsertRowid, title, completed: 0 });
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.get("/todos", authenticateToken, (req, res) => {
  try {
    const todos = db
      .prepare("SELECT * FROM todos WHERE user_id = ? ORDER BY created_at DESC")
      .all(req.user.id);
    res.json(todos);
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.put("/todos/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  const { title, completed } = req.body;
  try {
    const stmt = db.prepare(
      "UPDATE todos SET title = ?, completed = ? WHERE id = ? AND user_id = ?"
    );
    const info = stmt.run(title, completed ? 1 : 0, id, req.user.id);
    if (info.changes === 0) {
      return res.status(404).send("Todo not found or not authorized");
    }
    res.send("Todo updated successfully");
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.delete("/todos/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  try {
    const stmt = db.prepare("DELETE FROM todos WHERE id = ? AND user_id = ?");
    const info = stmt.run(id, req.user.id);
    if (info.changes === 0) {
      return res.status(404).send("Todo not found or not authorized");
    }
    res.send("Todo deleted successfully");
  } catch (error) {
    res.status(500).send("Server error");
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});