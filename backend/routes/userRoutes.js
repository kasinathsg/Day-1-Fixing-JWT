const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const User = require("../models/User");

const router = express.Router();

const generateToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRATION,
  });
};

const validateInput = (username, password) => {
  const errors = [];

  if (!username || typeof username !== 'string' || username.trim().length < 3) {
    errors.push("Username must be at least 3 characters long");
  }

  if (!password || typeof password !== 'string' || password.length < 6) {
    errors.push("Password must be at least 6 characters long");
  }

  return errors;
};

router.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const errors = validateInput(username, password);

  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ message: "User already exists!" });
  }

  const hashPassword = bcrypt.hashSync(password, 10);
  const newUser = await User.create({
    username,
    password: hashPassword,
  });

  if (!newUser) {
    return res.status(400).json({ message: "Failed to create the user" });
  }

  const result = newUser.toJSON();
  delete result.password;
  result.token = generateToken({ userId: result._id });

  return res.status(201).json({
    status: 'success',
    data: result,
  });
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const errors = validateInput(username, password);

  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  const user = await User.findOne({ username });
  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ message: "Incorrect Email or password!" });
  }

  const token = generateToken({ userId: user._id });
  return res.json({ token });
});

module.exports = router;
