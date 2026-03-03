const express = require("express");
const router = express.Router();
const User = require("../models/Users");
const jwt = require("jsonwebtoken");

const protect = require("../middleware/authMiddleware");
const roleMiddleware = require("../middleware/roleMiddleware");


// ================= SIGNUP =================
router.post("/signup", async (req, res) => {
  try {
    const { fullName, email, password, confirmPassword } = req.body;

    if (!fullName || !email || !password || !confirmPassword) {
      return res.status(400).json({ message: "All fields required" });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const user = await User.create({
      fullName,
      email,
      password,
      role: "student"
    });

    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    res.status(500).json({ message: "Signup failed" });
  }
});


// ================= LOGIN =================
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Email and password are required." });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ error: "Invalid credentials." });

    const isMatch = await user.comparePassword(password);
    if (!isMatch)
      return res.status(400).json({ error: "Invalid credentials." });

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,  // true in production
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      message: "Logged in successfully.",
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    res.status(500).json({ error: "Login failed." });
  }
});


// ================= LOGOUT =================
router.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out successfully." });
});


// ================= PROFILE (Any Logged In User) =================
router.get("/profile", protect, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json(user);
});


// ================= ADMIN ONLY ROUTE =================
router.get("/admin-data", protect, roleMiddleware("admin"), (req, res) => {
  res.json({ message: "Welcome Admin 👑" });
});


// ================= STUDENT ONLY ROUTE =================
router.get("/student-data", protect, roleMiddleware("student"), (req, res) => {
  res.json({ message: "Welcome Student 🎓" });
});


module.exports = router;