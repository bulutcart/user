require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const mysql = require("mysql2/promise");

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = process.env.JWT_SECRET || "supersecretkey";

// MySQL bağlantısı
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306, // Port numarası belirleme
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});
// test
app.get("/", async (req, res) => {
    try {
        res.json({ message: "başarılı" });
    } catch (error) {
        res.status(500).json({ error: "Database error..." + process.env.DB_HOST + process.env.DB_USER});
    }
});
// Kullanıcı Kaydı
app.post("/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const connection = await pool.getConnection();
        await connection.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword]
        );
        connection.release();
        res.json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ error: "Database error..." + process.env.DB_HOST + process.env.DB_USER});
    }
});

// Kullanıcı Girişi
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const connection = await pool.getConnection();
        const [rows] = await connection.execute("SELECT * FROM users WHERE email = ?", [email]);
        connection.release();

        if (rows.length === 0 || !(await bcrypt.compare(password, rows[0].password))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ id: rows[0].id, email: rows[0].email }, SECRET_KEY, { expiresIn: "1h" });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: "Database error" });
    }
});

// Token ile Korunan Route
app.get("/profile", authenticateToken, async (req, res) => {
    try {
        const connection = await pool.getConnection();
        const [rows] = await connection.execute("SELECT id, name, email FROM users WHERE id = ?", [req.user.id]);
        connection.release();

        if (rows.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ message: "Welcome to your profile!", user: rows[0] });
    } catch (error) {
        res.status(500).json({ error: "Database error" });
    }
});

function authenticateToken(req, res, next) {
    const token = req.header("Authorization")?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Access denied" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        req.user = user;
        next();
    });
}

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
