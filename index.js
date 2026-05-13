const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const pool = require("./db");

const app = express();
app.use(cors());
app.use(express.json());

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access only" });
  }

  next();
}

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email, role",
      [name, email, hashed],
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.log("REGISTER ERROR:", error.message);
    res.status(500).json({ message: error.message });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query("SELECT * FROM users WHERE email=$1", [
    email,
  ]);
  const user = result.rows[0];

  if (!user) return res.status(400).json({ message: "User not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "Wrong password" });

  const token = jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }, // ⏱ expires in 1 hour
  );

  res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
});

app.get("/", (req, res) => {
  res.send("Quiz API running");
});

app.get("/api/admin/results", verifyToken, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        attempts.id,
        users.name,
        users.email,
        quizzes.title AS quiz_title,
        attempts.score,
        attempts.total,
        attempts.created_at
      FROM attempts
      JOIN users ON attempts.user_id = users.id
      JOIN quizzes ON attempts.quiz_id = quizzes.id
      ORDER BY attempts.created_at DESC
    `);

    res.json(result.rows);
  } catch (err) {
    console.log("ADMIN RESULTS ERROR:", err.message);
    res.status(500).json({ message: "Error getting results" });
  }
});

app.post("/api/attempts", verifyToken, async (req, res) => {
  try {
    const { user_id, quiz_id, score, total } = req.body;

    const result = await pool.query(
      "INSERT INTO attempts (user_id, quiz_id, score, total) VALUES ($1,$2,$3,$4) RETURNING *",
      [user_id, quiz_id, score, total],
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.log("ATTEMPT ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/admin/users", verifyToken, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, email, role FROM users ORDER BY id DESC",
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: "Error getting users" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    const hashed = await bcrypt.hash(newPassword, 10);

    const result = await pool.query(
      "UPDATE users SET password=$1 WHERE email=$2 RETURNING id, email",
      [hashed, email],
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Email not found" });
    }

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.log("RESET PASSWORD ERROR:", err.message);
    res.status(500).json({ message: "Error resetting password" });
  }
});

app.post("/api/quizzes", verifyToken, adminOnly, async (req, res) => {
  try {
    const { title, description, level } = req.body;

    const result = await pool.query(
      `INSERT INTO quizzes (title, description, level)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [title, description, level],
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.log("CREATE QUIZ ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

app.put("/api/quizzes/:id", verifyToken, adminOnly, async (req, res) => {
  try {
    const { title, description, level } = req.body;

    const result = await pool.query(
      `UPDATE quizzes
       SET title=$1, description=$2, level=$3
       WHERE id=$4
       RETURNING *`,
      [title, description, level, req.params.id],
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.log("UPDATE QUIZ ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

app.delete("/api/quizzes/:id", verifyToken, adminOnly, async (req, res) => {
  try {
    await pool.query("DELETE FROM quizzes WHERE id=$1", [req.params.id]);
    res.json({ message: "Quiz deleted" });
  } catch (err) {
    console.log("DELETE QUIZ ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});



app.get("/api/quizzes", verifyToken, async (req, res) => {
  const result = await pool.query("SELECT * FROM quizzes");
  res.json(result.rows);
});



app.get("/api/questions", verifyToken, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT questions.*, quizzes.title AS quiz_title
      FROM questions
      JOIN quizzes ON questions.quiz_id = quizzes.id
      ORDER BY questions.id DESC
    `);

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/api/questions", verifyToken, adminOnly, async (req, res) => {
  try {
    const {
      quiz_id,
      question,
      option_a,
      option_b,
      option_c,
      option_d,
      correct_answer,
      explanation,
    } = req.body;

    const result = await pool.query(
      `INSERT INTO questions 
      (quiz_id, question, option_a, option_b, option_c, option_d, correct_answer, explanation)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [
        quiz_id,
        question,
        option_a,
        option_b,
        option_c,
        option_d,
        correct_answer,
        explanation,
      ],
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.log("QUESTION ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

app.put("/api/questions/:id", verifyToken, adminOnly, async (req, res) => {
  try {
    const {
      question,
      option_a,
      option_b,
      option_c,
      option_d,
      correct_answer,
      explanation,
    } = req.body;

    const result = await pool.query(
      `UPDATE questions
       SET question=$1, option_a=$2, option_b=$3, option_c=$4,
           option_d=$5, correct_answer=$6, explanation=$7
       WHERE id=$8
       RETURNING *`,
      [
        question,
        option_a,
        option_b,
        option_c,
        option_d,
        correct_answer,
        explanation,
        req.params.id,
      ],
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete("/api/questions/:id", verifyToken, adminOnly, async (req, res) => {
  try {
    await pool.query("DELETE FROM questions WHERE id=$1", [req.params.id]);
    res.json({ message: "Question deleted" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get(
  "/api/quizzes/:id/questions",
  verifyToken,
  async (req, res) => {
    const result = await pool.query(
      "SELECT * FROM questions WHERE quiz_id=$1",
      [req.params.id],
    );

    res.json(result.rows);
  },
);

app.get("/api/user/:id/attempts", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        attempts.id,
        quizzes.title AS quiz_title,
        attempts.score,
        attempts.total,
        attempts.created_at
      FROM attempts
      JOIN quizzes ON attempts.quiz_id = quizzes.id
      WHERE attempts.user_id = $1
      ORDER BY attempts.created_at DESC`,
      [req.params.id],
    );

    res.json(result.rows);
  } catch (err) {
    console.log("USER ATTEMPTS ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

app.delete("/api/admin/users/:id", verifyToken, adminOnly, async (req, res) => {
  try {
    await pool.query("DELETE FROM users WHERE id=$1", [req.params.id]);
    res.json({ message: "User deleted" });
  } catch (err) {
    console.log("DELETE USER ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

app.delete("/api/attempts/:id", verifyToken, async (req, res) => {
  try {
    await pool.query("DELETE FROM attempts WHERE id=$1", [req.params.id]);
    res.json({ message: "Attempt deleted" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.listen(process.env.PORT || 5000, () => {
  console.log("Server running");
});