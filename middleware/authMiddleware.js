// authMiddleware.js

const jwt = require("jsonwebtoken");

const SECRET_KEY = process.env.JWT_SECRET || "your_super_secret_key_here";

// In-memory token blacklist for logout functionality
const tokenBlacklist = new Set();

function authenticateToken(req, res, next) {
  // 1. Read Authorization header or cookie
  const authHeader = req.headers["authorization"];
  const cookieToken = req.cookies ? req.cookies.accessToken : null;
  
  // 2. Extract token from "Bearer <token>" or cookie
  const token = (authHeader && authHeader.split(" ")[1]) || cookieToken;
  
  // 3. If token missing, return 401
  if (!token) {
    return res.status(401).json({ 
      error: "Unauthorized", 
      message: "Access token is missing. Please login to get a token." 
    });
  }

  // Check if token is blacklisted (logged out)
  if (tokenBlacklist.has(token)) {
    return res.status(403).json({ 
      error: "Forbidden", 
      message: "Token has been invalidated. Please login again." 
    });
  }

  // 4. Verify token using jwt.verify
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    // 5. If invalid or expired, return 403 with custom error messages
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(403).json({ 
          error: "Forbidden", 
          message: "Token has expired. Please login again to get a new token.",
          expiredAt: err.expiredAt
        });
      }
      if (err.name === "JsonWebTokenError") {
        return res.status(403).json({ 
          error: "Forbidden", 
          message: "Invalid token. Please provide a valid token." 
        });
      }
      return res.status(403).json({ 
        error: "Forbidden", 
        message: "Token verification failed." 
      });
    }
    
    // 6. Attach decoded payload to req.user
    req.user = decoded;
    req.token = token; // Store token for potential blacklisting on logout
    
    // 7. Call next()
    next();
  });
}

// Function to blacklist a token (for logout)
function blacklistToken(token) {
  tokenBlacklist.add(token);
}

// Function to check if token is blacklisted
function isTokenBlacklisted(token) {
  return tokenBlacklist.has(token);
}

module.exports = { 
  authenticateToken, 
  blacklistToken, 
  isTokenBlacklisted,
  tokenBlacklist 
};
