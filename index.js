const express = require("express");
const app = express();
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const JWT_SECRET = "jwt_secret_key";

// Middleware: Token authentication
function authenticateToken(req, res, next) {
  const token = req.query.token;
  if (!token) {
    return res.status(401).send("Access denied. No token provided.");
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).send("Invalid token.");
  }
}

// MySQL connection setup
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Raj@12345678", // your MySQL password
  database: "blogplatform",
});

connection.connect((err) => {
  if (err) {
    console.log("Database connection error");
    return;
  }
  console.log("Connected to database");
});

// Redirect root to login
app.get("/", (req, res) => {
  res.redirect("/login");
});

// Signup page
app.get("/signup", (req, res) => {
  res.render("signup");
});

// Signup handler
app.post("/signup", (req, res) => {
  const { username, password } = req.body;

  connection.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, results) => {
      if (err) return res.send("Database error");
      if (results.length > 0)
        return res.send("User already exists. <a href='/signup'>Try again</a>");

      const hashedPassword = await bcrypt.hash(password, 10);
      connection.query(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashedPassword],
        (err) => {
          if (err) return res.send("Error inserting user");
          res.redirect("/login");
        }
      );
    }
  );
});

// Login page
app.get("/login", (req, res) => {
  res.render("login");
});

// Login handler
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  connection.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, results) => {
      if (err) return res.send("Database error");
      if (results.length === 0)
        return res.send("Invalid username or password. <a href='/login'>Try again</a>");

      const user = results[0];
      const match = await bcrypt.compare(password, user.password);
      if (!match)
        return res.send("Invalid username or password. <a href='/login'>Try again</a>");

      const token = jwt.sign({ username: user.username, id: user.id }, JWT_SECRET, {
        expiresIn: "1h",
      });

      res.redirect(`/home?token=${token}`);
    }
  );
});

// Logout
app.get("/logout", (req, res) => {
  res.send(`<h2>You have been logged out. <a href="/login">Login again</a></h2>`);
});

// Home dashboard
app.get("/home", authenticateToken, (req, res) => {
  connection.query(
    "SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC",
    [req.user.id],
    (err, posts) => {
      if (err) return res.send("Database error");
      // Pass token along to include it in links
      res.render("home", { username: req.user.username, posts, token: req.query.token });
    }
  );
});


// New post form
app.get("/posts/new", authenticateToken, (req, res) => {
  res.render("new-post", { username: req.user.username,   token: req.query.token });
});

// Handle new post submission
app.post("/posts/new", authenticateToken, (req, res) => {
  const { title, content } = req.body;
  connection.query(
    "INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)",
    [req.user.id, title, content],
    (err) => {
      if (err) return res.send("Database error");
      res.redirect(`/home?token=${req.query.token}`);
    }
  );
});

// View all posts (public)
app.get("/posts", (req, res) => {
  connection.query(
    "SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY created_at DESC",
    (err, posts) => {
      if (err) return res.send("Database error");
      res.render("posts", { posts });
    }
  );
});

// Delete post
app.get("/posts/delete/:id", authenticateToken, (req, res) => {
  const postId = req.params.id;
  connection.query(
    "DELETE FROM posts WHERE id = ? AND user_id = ?",
    [postId, req.user.id],
    (err) => {
      if (err) return res.send("Database error");
      res.redirect(`/home?token=${req.query.token}`);
    }
  );
});

// Server
const port = 3000;
app.listen(port, () => {
  console.log("Server running at http://localhost:" + port);
});
