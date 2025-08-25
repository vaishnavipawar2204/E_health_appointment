require("dotenv").config();
const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2");

const app = express();
const PORT = process.env.PORT || 3000;

// MySQL Database connection pool
const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "ehealth_db",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Middleware
app.use(express.static(path.join(__dirname, "public"))); // serve Tailwind CSS, images
app.use(express.urlencoded({ extended: false })); // parse form data

// Session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || "thisisasecret",
    resave: false,
    saveUninitialized: false,
  })
);

// Middleware to protect routes requiring login
function checkAuth(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.redirect("/login");
  }
}

// Routes serving HTML pages
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "home.html"));
});
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "login.html"));
});
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "register.html"));
});

// Protected routes
app.get("/book", checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "book.html"));
});

app.get("/manage", checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "manage.html"));
});

// Registration POST handler
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword],
      (err, results) => {
        if (err) {
          console.error(err);
          return res.send(
            "Error registering user. Maybe email already exists."
          );
        }
        res.redirect("/login");
      }
    );
  } catch (error) {
    console.error(error);
    res.send("Server error.");
  }
});

// Login POST handler
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        console.error(err);
        return res.send("Server error");
      }
      if (results.length === 0) {
        return res.send("Invalid email or password");
      }
      const user = results[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        req.session.userId = user.id;
        res.redirect("/book");
      } else {
        res.send("Invalid email or password");
      }
    }
  );
});

// Logout route
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// Booking appointments POST handler
app.post("/book", checkAuth, (req, res) => {
  const { doctor_id, appointment_time } = req.body;
  const user_id = req.session.userId;

  db.query(
    "INSERT INTO appointments (user_id, doctor_id, appointment_time) VALUES (?, ?, ?)",
    [user_id, doctor_id, appointment_time],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.send("Error booking appointment.");
      }
      res.redirect("/manage");
    }
  );
});

// Get appointments for logged-in user (return JSON, used via AJAX on manage.html)
app.get("/api/appointments", checkAuth, (req, res) => {
  const user_id = req.session.userId;
  const query = `
    SELECT a.id, d.name AS doctor_name, d.specialty, a.appointment_time, a.status 
    FROM appointments a
    JOIN doctors d ON a.doctor_id = d.id
    WHERE a.user_id = ?
    ORDER BY a.appointment_time DESC
  `;
  db.query(query, [user_id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "DB error" });
    }
    res.json(results);
  });
});

// Cancel appointment
app.post("/manage/cancel", checkAuth, (req, res) => {
  const { appointment_id } = req.body;
  const user_id = req.session.userId;
  const query = "DELETE FROM appointments WHERE id = ? AND user_id = ?";
  db.query(query, [appointment_id, user_id], (err, result) => {
    if (err) {
      console.error(err);
      return res.send("Error cancelling appointment.");
    }
    res.redirect("/manage");
  });
});

// Serve doctors list for booking (as JSON for dynamic select in book.html if needed)
app.get("/api/doctors", (req, res) => {
  db.query("SELECT * FROM doctors", (err, results) => {
    if (err) {
      return res.status(500).json({ error: "DB error" });
    }
    res.json(results);
  });
});

app.listen(PORT, () => {
console.log(`Server running on http://localhost:${PORT}`)
});
