const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// MySQL database connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "news_blog"
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connected to MySQL database.");
});

// Register a new user
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashedPassword],
    (err, result) => {
      if (err) return res.status(500).send(err);
      res.json({ message: "User registered successfully!" });
    }
  );
});

// Login a user and return JWT token
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, users) => {
      if (err) return res.status(500).send(err);
      if (users.length === 0) return res.status(400).send("User not found!");

      const user = users[0];
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) return res.status(400).send("Invalid credentials!");

      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
        expiresIn: "1h"
      });

      res.json({ token });
    }
  );
});

// Create a new blog post
app.post("/api/posts", (req, res) => {
  const { title, body, author } = req.body;

  db.query(
    "INSERT INTO posts (title, body, author) VALUES (?, ?, ?)",
    [title, body, author],
    (err, result) => {
      if (err) return res.status(500).send(err);
      res.json({ message: "Post created successfully!" });
    }
  );
});

// Fetch all blog posts
app.get("/api/posts", (req, res) => {
  db.query("SELECT * FROM posts", (err, posts) => {
    if (err) return res.status(500).send(err);
    res.json(posts);
  });
});

// Fetch a single post by ID
app.get("/api/posts/:id", (req, res) => {
  const { id } = req.params;

  db.query("SELECT * FROM posts WHERE id = ?", [id], (err, post) => {
    if (err) return res.status(500).send(err);
    if (post.length === 0) return res.status(404).send("Post not found!");

    res.json(post[0]);
  });
});

// Delete a post
app.delete("/api/posts/:id", (req, res) => {
  const { id } = req.params;

  db.query("DELETE FROM posts WHERE id = ?", [id], (err, result) => {
    if (err) return res.status(500).send(err);
    res.json({ message: "Post deleted successfully!" });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
