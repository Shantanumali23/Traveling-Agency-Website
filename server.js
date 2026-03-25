require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "voyager_secret";
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || "7d";

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const pool = mysql.createPool({
    host: process.env.MYSQL_HOST || "localhost",
    port: process.env.MYSQL_PORT || 3306,
    user: process.env.MYSQL_USER || "root",
    password: process.env.MYSQL_PASSWORD || "",
    database: process.env.MYSQL_DATABASE || "voyager_travel",
    waitForConnections: true,
    connectionLimit: 10,
});

(async () => {
    try {
        const conn = await pool.getConnection();
        console.log("MySQL connected successfully");
        conn.release();
    } catch (err) {
        console.error("MySQL connection failed:", err.message);
    }
})();

mongoose
    .connect(process.env.MONGO_URI || "mongodb://localhost:27017/voyager_travel")
    .then(() => console.log("MongoDB connected successfully"))
    .catch((err) => console.error("MongoDB connection failed:", err.message));

const bookingSchema = new mongoose.Schema(
    {
        bookingId: { type: String, required: true, unique: true },
        userId: { type: Number },
        packageName: { type: String, required: true },
        location: { type: String, required: true },
        fullName: { type: String, required: true },
        email: { type: String, required: true },
        phone: { type: String, required: true },
        travelDate: { type: String, required: true },
        travellers: { type: Number, required: true },
        roomType: { type: String, default: "Standard" },
        mealPreference: { type: String, default: "All Inclusive" },
        specialRequests: { type: String, default: "" },
        totalPrice: { type: Number, required: true },
        status: { type: String, default: "Confirmed" },
    },
    { timestamps: true }
);

const Booking = mongoose.model("Booking", bookingSchema);

async function ensureTables() {
    try {
        await pool.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        full_name    VARCHAR(100) NOT NULL,
        email        VARCHAR(150) NOT NULL UNIQUE,
        password     VARCHAR(255) NOT NULL,
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
        await pool.execute(`
      CREATE TABLE IF NOT EXISTS bookings (
        id               VARCHAR(20)   PRIMARY KEY,
        user_id          INT,
        package_name     VARCHAR(100)  NOT NULL,
        location         VARCHAR(100)  NOT NULL,
        full_name        VARCHAR(100)  NOT NULL,
        email            VARCHAR(100)  NOT NULL,
        phone            VARCHAR(25)   NOT NULL,
        travel_date      DATE          NOT NULL,
        travellers       INT           NOT NULL,
        room_type        VARCHAR(50)   DEFAULT 'Standard',
        meal_preference  VARCHAR(50)   DEFAULT 'All Inclusive',
        special_requests TEXT,
        total_price      DECIMAL(12,2) NOT NULL,
        status           VARCHAR(20)   DEFAULT 'Confirmed',
        booked_on        TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      );
    `);
        console.log("MySQL tables ready (users + bookings)");
    } catch (err) {
        console.error("Table creation failed:", err.message);
    }
}
ensureTables();

function authMiddleware(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) {
        return res.status(401).json({ error: "No token provided. Please sign in." });
    }
    try {
        const token = header.split(" ")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        return res.status(401).json({ error: "Invalid or expired token. Please sign in again." });
    }
}

app.get("/api/health", (req, res) => {
    res.json({ status: "ok", time: new Date().toISOString() });
});

app.post("/api/auth/register", async (req, res) => {
    const { full_name, email, password } = req.body;
    if (!full_name || !email || !password) {
        return res.status(400).json({ error: "All fields are required." });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters." });
    }
    try {
        const [existing] = await pool.execute(
            "SELECT id FROM users WHERE email = ?", [email]
        );
        if (existing.length > 0) {
            return res.status(409).json({ error: "An account with this email already exists." });
        }
        const hashed = await bcrypt.hash(password, 12);
        const [result] = await pool.execute(
            "INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)",
            [full_name, email, hashed]
        );
        const token = jwt.sign(
            { id: result.insertId, email, full_name },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES }
        );
        console.log(`👤 New user registered: ${email}`);
        res.status(201).json({ success: true, token, user: { id: result.insertId, full_name, email } });
    } catch (err) {
        console.error("Register error:", err.message);
        res.status(500).json({ error: "Registration failed. " + err.message });
    }
});

app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
    }
    try {
        const [rows] = await pool.execute(
            "SELECT * FROM users WHERE email = ?", [email]
        );
        if (rows.length === 0) {
            return res.status(401).json({ error: "No account found with this email." });
        }
        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: "Incorrect password. Please try again." });
        }
        const token = jwt.sign(
            { id: user.id, email: user.email, full_name: user.full_name },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES }
        );
        console.log(`🔐 User logged in: ${email}`);
        res.json({ success: true, token, user: { id: user.id, full_name: user.full_name, email: user.email } });
    } catch (err) {
        console.error("Login error:", err.message);
        res.status(500).json({ error: "Login failed. " + err.message });
    }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
    try {
        const [rows] = await pool.execute(
            "SELECT id, full_name, email, created_at FROM users WHERE id = ?",
            [req.user.id]
        );
        if (!rows.length) return res.status(404).json({ error: "User not found" });
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post("/api/bookings", authMiddleware, async (req, res) => {
    const b = req.body;
    const required = ["id", "package", "location", "name", "email", "phone", "date", "travellers", "total"];
    const missing = required.filter((k) => !b[k]);
    if (missing.length) {
        return res.status(400).json({ error: `Missing fields: ${missing.join(", ")}` });
    }
    try {
        await pool.execute(
            `INSERT INTO bookings
         (id, user_id, package_name, location, full_name, email, phone,
          travel_date, travellers, room_type, meal_preference, special_requests, total_price, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                b.id, req.user.id, b.package, b.location, b.name, b.email, b.phone,
                b.date, b.travellers, b.room || "Standard",
                b.meal || "All Inclusive", b.special || "", b.total, "Confirmed",
            ]
        );
        await Booking.create({
            bookingId: b.id, userId: req.user.id,
            packageName: b.package, location: b.location,
            fullName: b.name, email: b.email, phone: b.phone,
            travelDate: b.date, travellers: b.travellers,
            roomType: b.room || "Standard",
            mealPreference: b.meal || "All Inclusive",
            specialRequests: b.special || "", totalPrice: b.total,
        });
        console.log(`Booking ${b.id} saved by user ${req.user.email}`);
        res.status(201).json({ success: true, bookingId: b.id });
    } catch (err) {
        console.error("Booking error:", err.message);
        if (err.code === "ER_DUP_ENTRY" || err.code === 11000) {
            return res.status(409).json({ error: "Booking ID already exists." });
        }
        res.status(500).json({ error: "Failed to save booking. " + err.message });
    }
});

app.get("/api/bookings", authMiddleware, async (req, res) => {
    try {
        const [rows] = await pool.execute(
            "SELECT * FROM bookings WHERE user_id = ? ORDER BY booked_on DESC",
            [req.user.id]
        );
        res.json(rows);
    } catch (err) {
        console.error("Fetch bookings error:", err.message);
        res.status(500).json({ error: "Failed to fetch bookings." });
    }
});

app.get("/api/bookings/:id", authMiddleware, async (req, res) => {
    try {
        const [rows] = await pool.execute(
            "SELECT * FROM bookings WHERE id = ? AND user_id = ?",
            [req.params.id, req.user.id]
        );
        if (!rows.length) return res.status(404).json({ error: "Booking not found." });
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete("/api/bookings/:id", authMiddleware, async (req, res) => {
    try {
        await pool.execute(
            "DELETE FROM bookings WHERE id = ? AND user_id = ?",
            [req.params.id, req.user.id]
        );
        await Booking.deleteOne({ bookingId: req.params.id });
        res.json({ success: true, message: "Booking cancelled." });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.use((req, res) => {
    res.status(404).json({ error: "Route not found." });
});

app.listen(PORT, () => {
    console.log("");
    console.log("");
});