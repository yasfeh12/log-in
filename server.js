require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const db = require("better-sqlite3")("ourapp.db");
db.pragma("journal_mode = WAL");

const app = express();

// DATABASE SETUP
const createTables = db.transaction(() => {
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    )
  `
  ).run();
});
createTables(); // Execute the transaction to create tables
// END OF DB SETUP

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser()); // Use cookie-parser middleware

app.use(function (req, res, next) {
  res.locals.errors = [];

  //try to decode incoming cookie
  try {
    const decode = jwt.verify(req.cookies.oursimpleapp, process.env.JWTSECRET);
    req.user = decode;
  } catch {
    req.user = false;
  }
  res.locals.user = req.user;
  console.log(req.user);

  next();
});

app.get("/", (req, res) => {
  res.render("homepage", { error: [] });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/register", (req, res) => {
  const error = [];
  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  req.body.username = req.body.username.trim();

  // Username validation
  if (!req.body.username) error.push("You must enter a username.");
  if (req.body.username.length < 3)
    error.push("Username must be longer than 2 characters.");
  if (req.body.username.length > 10)
    error.push("Username must be shorter than 10 characters.");
  if (!/^[a-zA-Z0-9]+$/.test(req.body.username))
    error.push("Username can only contain letters and numbers.");

  // Password validation
  if (!req.body.password) error.push("You must enter a password.");
  if (req.body.password.length < 8)
    error.push("Password must be at least 8 characters long.");
  if (req.body.password.length > 70)
    error.push("Password must be shorter than 70 characters.");

  if (error.length) {
    return res.render("homepage", { error });
  } else {
    try {
      // Check if the username already exists
      const checkUser = db
        .prepare(`SELECT COUNT(*) AS count FROM users WHERE username = ?`)
        .get(req.body.username);
      if (checkUser.count > 0) {
        error.push("Username already exists.");
        return res.render("homepage", { error });
      }

      // Hash password
      const salt = bcrypt.genSaltSync(10); // Generate salt synchronously
      const hashedPassword = bcrypt.hashSync(req.body.password, salt); // Hash the password

      // Insert user into database
      const ourstatement = db.prepare(
        `INSERT INTO users (username, password) VALUES (?, ?)`
      );
      const result = ourstatement.run(req.body.username, hashedPassword);

      // Generate JWT token
      const ourTokenValue = jwt.sign(
        {
          id: result.lastInsertRowid,
          username: req.body.username,
        },
        process.env.JWTSECRET,
        { expiresIn: "1d" } // Token expires in 1 day
      );

      // Set the JWT as a cookie
      res.cookie("oursimpleapp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24, // 1 day
      });

      return res.send("User registered successfully!");
    } catch (err) {
      console.error("Database Error: ", err.message); // Log the actual error
      if (err.message.includes("UNIQUE constraint failed")) {
        error.push("Username already exists.");
      } else {
        error.push("Database error. Please try again later.");
      }
      return res.render("homepage", { error });
    }
  }
});

// Start the server
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
