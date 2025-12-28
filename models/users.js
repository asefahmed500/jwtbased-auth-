// users.js

const bcrypt = require("bcryptjs");

// In-memory users array with hashed passwords
const users = [
  {
    id: 1,
    username: "admin",
    password: bcrypt.hashSync("admin123", 10),
    role: "admin"
  },
  {
    id: 2,
    username: "student1",
    password: bcrypt.hashSync("student123", 10),
    role: "student"
  },
  {
    id: 3,
    username: "student2",
    password: bcrypt.hashSync("student456", 10),
    role: "student"
  }
];

module.exports = users;
