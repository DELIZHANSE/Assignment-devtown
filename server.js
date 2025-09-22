// server.js
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(bodyParser.json());

const users = []; // In-memory storage (no DB)

// Secret key for JWT
const JWT_SECRET = "mysecretkey"; // In real projects, keep it in .env

// ================== TASK 1: Password Hashing ==================

// Register route
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  // Check if user exists
  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Store user
  users.push({ username, password: hashedPassword });
  res.json({ message: "User registered successfully" });
});

// Login route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(400).json({ message: "Invalid credentials" });
  }

  // Compare password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ message: "Invalid credentials" });
  }

  // ================== TASK 2: JWT Auth ==================
  // Generate JWT token
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });

  res.json({ message: "Login successful", token });
});

// Protected route
app.get("/profile", (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1]; // Format: Bearer <token>

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Unauthorized or expired token" });
    }
    res.json({ message: `Welcome ${decoded.username}` });
  });
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
