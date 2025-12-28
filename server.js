// server.js

require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const users = require("./models/users");
const { authenticateToken, blacklistToken } = require("./middleware/authMiddleware");

const app = express();
app.use(express.json());
app.use(cookieParser());

const SECRET_KEY = process.env.JWT_SECRET || "your_super_secret_key_here";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "your_refresh_secret_key_here";

// In-memory refresh token storage
const refreshTokens = new Set();

// Action logger middleware
function logAction(action) {
  return (req, res, next) => {
    if (req.user) {
      console.log(`[${new Date().toISOString()}] User: ${req.user.username} (ID: ${req.user.userId}, Role: ${req.user.role}) - Action: ${action}`);
    }
    next();
  };
}

// Register Route
app.post("/register", (req, res) => {
  const { username, password, role } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ 
      error: "Bad Request", 
      message: "Username and password are required" 
    });
  }
  // Check if user already exists
  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(409).json({
      error: "Conflict",
      message: "Username already exists"
    });
  }

  // Hash password
  const hashedPassword = bcrypt.hashSync(password, 10);
  
  // Create new user
  const newUser = {
    id: users.length + 1,
    username,
    password: hashedPassword,
    role: role || "student" // Default to student role
  };

  users.push(newUser);

  console.log(`[${new Date().toISOString()}] New User Registered: ${newUser.username} (ID: ${newUser.id}, Role: ${newUser.role})`);

  res.status(201).json({
    message: "User registered successfully",
    user: {
      id: newUser.id,
      username: newUser.username,
      role: newUser.role
    }
  });
});

// Login Route
app.post("/login", (req, res) => {
  // 1. Extract username and password from req.body
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ 
      error: "Bad Request", 
      message: "Username and password are required" 
    });
  }

  // 2. Find the user from the users array
  const user = users.find(u => u.username === username);

  // 3. If user not found, return 401
  if (!user) {
    return res.status(401).json({ 
      error: "Unauthorized", 
      message: "Invalid username or password" 
    });
  }

  // 4. Compare password using bcrypt.compareSync
  const isValidPassword = bcrypt.compareSync(password, user.password);

  // 5. If password invalid, return 401
  if (!isValidPassword) {
    return res.status(401).json({ 
      error: "Unauthorized", 
      message: "Invalid username or password" 
    });
  }

  // 6. Generate JWT token with userId and role
  const tokenPayload = {
    userId: user.id,
    username: user.username,
    role: user.role
  };

  // 7. Set token expiry to 1 hour
  const accessToken = jwt.sign(tokenPayload, SECRET_KEY, { expiresIn: "1h" });
  
  // Generate refresh token (expires in 7 days)
  const refreshToken = jwt.sign(tokenPayload, REFRESH_SECRET, { expiresIn: "7d" });
  refreshTokens.add(refreshToken);

  // Set JWT in HttpOnly cookie
  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 3600000 // 1 hour
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 3600000 // 7 days
  });

  console.log(`[${new Date().toISOString()}] User: ${user.username} (ID: ${user.id}) - Action: LOGIN`);

  // 8. Return token in JSON response
  res.json({ 
    message: "Login successful",
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      username: user.username,
      role: user.role
    }
  });
});

// Refresh Token Route
app.post("/refresh", (req, res) => {
  const { refreshToken } = req.body || {};
  const cookieRefreshToken = req.cookies?.refreshToken;
  const token = refreshToken || cookieRefreshToken;

  if (!token) {
    return res.status(401).json({ 
      error: "Unauthorized", 
      message: "Refresh token is required" 
    });
  }

  if (!refreshTokens.has(token)) {
    return res.status(403).json({ 
      error: "Forbidden", 
      message: "Invalid refresh token" 
    });
  }

  jwt.verify(token, REFRESH_SECRET, (err, decoded) => {
    if (err) {
      refreshTokens.delete(token);
      return res.status(403).json({ 
        error: "Forbidden", 
        message: "Refresh token expired or invalid" 
      });
    }

    const tokenPayload = {
      userId: decoded.userId,
      username: decoded.username,
      role: decoded.role
    };

    const newAccessToken = jwt.sign(tokenPayload, SECRET_KEY, { expiresIn: "1h" });

    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 3600000
    });

    console.log(`[${new Date().toISOString()}] User: ${decoded.username} (ID: ${decoded.userId}) - Action: TOKEN_REFRESH`);

    res.json({ 
      message: "Token refreshed successfully",
      accessToken: newAccessToken 
    });
  });
});

// Logout Route
app.post("/logout", authenticateToken, (req, res) => {
  // Blacklist the current access token
  if (req.token) {
    blacklistToken(req.token);
  }

  // Remove refresh token if provided
  const { refreshToken } = req.body || {};
  const cookieRefreshToken = req.cookies?.refreshToken;
  const token = refreshToken || cookieRefreshToken;
  
  if (token) {
    refreshTokens.delete(token);
  }

  // Clear cookies
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");

  console.log(`[${new Date().toISOString()}] User: ${req.user.username} (ID: ${req.user.userId}) - Action: LOGOUT`);

  res.json({ 
    message: "Logout successful. Token has been invalidated." 
  });
});

// Protected Profile Route
app.get("/profile", authenticateToken, logAction("VIEW_PROFILE"), (req, res) => {
  // 1. Access decoded token data from req.user
  // 2. Return userId and role in response
  res.json({
    message: "Profile accessed successfully",
    user: {
      userId: req.user.userId,
      username: req.user.username,
      role: req.user.role
    }
  });
});

// Admin-only Route
app.get("/admin", authenticateToken, logAction("ACCESS_ADMIN"), (req, res) => {
  // 1. Check if req.user.role is "admin"
  if (req.user.role !== "admin") {
    // 2. If not, return 403 Forbidden
    return res.status(403).json({ 
      error: "Forbidden", 
      message: "Access denied. Admin role required." 
    });
  }

  // 3. If yes, return success message
  res.json({
    message: "Welcome to the admin panel!",
    user: {
      userId: req.user.userId,
      username: req.user.username,
      role: req.user.role
    }
  });
});

// Dashboard Route (for students and admins)
app.get("/dashboard", authenticateToken, logAction("VIEW_DASHBOARD"), (req, res) => {
  res.json({
    message: `Welcome to your dashboard, ${req.user.username}!`,
    user: {
      userId: req.user.userId,
      username: req.user.username,
      role: req.user.role
    }
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] ERROR: ${err.stack}`);
  res.status(500).json({
    error: "Internal Server Error",
    message: "Something went wrong on the server."
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log("\nAvailable users for testing:");
  console.log("  - admin / admin123 (role: admin)");
  console.log("  - student1 / student123 (role: student)");
  console.log("  - student2 / student456 (role: student)");
  console.log("\nEndpoints:");
  console.log("  POST /register    - Register a new user");
  console.log("  POST /login       - Login and get JWT token");
  console.log("  POST /logout      - Logout and invalidate token");
  console.log("  POST /refresh    - Refresh access token");
  console.log("  GET  /profile    - View profile (authenticated)");
  console.log("  GET  /dashboard  - View dashboard (authenticated)");
  console.log("  GET  /admin      - Admin only route");
});
