import express from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import bodyParser from "body-parser";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ------------------------- MongoDB -------------------------
mongoose.connect(process.env.STORAGE_2, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

// ------------------------- Schemas -------------------------
const userSchema = new mongoose.Schema({
  id: String,
  username: String,
  email: String,
  password: String,
  account_type: String,
  phone: String,
  NIN: String,
  CAC: String,
  device_id: String,
  token: String,
  token_expiry: Number,
  login_attempts: { count: Number, last_reset: Number },
  reset_token: String,
  reset_expiry: Number
});
const User = mongoose.model("User", userSchema);

const postSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  author_id: String,
  content: String,
  media: [String],
  likes: { type: Number, default: 0 },
  comments: [{ id: String, user_id: String, text: String, created_at: Number }],
  created_at: { type: Number, default: Date.now }
});
const Post = mongoose.model("Post", postSchema);

const chatSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  from_id: String,
  to_id: String,
  message: String,
  created_at: { type: Number, default: Date.now }
});
const Chat = mongoose.model("Chat", chatSchema);

// ------------------------- Constants -------------------------
const TOKEN_LIFETIME = 7 * 24 * 60 * 60 * 1000;
const MAX_DAILY_TRIALS = 5;
const transporter = nodemailer.createTransport({ jsonTransport: true });

// ------------------------- Helpers -------------------------
const createDeviceToken = (user_id, device_id) =>
  crypto.createHash("sha256").update(`${user_id}:${device_id}`).digest("base64").replace(/=/g, "").substring(0, 32);

const authMiddleware = async (token, device_id) => {
  if (!token || !device_id) return null;
  try {
    const user = await User.findOne({ token });
    if (!user) return null;
    if (user.device_id !== device_id) return null;
    if (Date.now() > user.token_expiry) return null;
    return user;
  } catch (err) {
    console.error("Auth middleware error:", err);
    return null;
  }
};

// ------------------------- Logging Wrapper -------------------------
const logApiCall = (endpoint, reqBody, userId, success, message) => {
  console.log(`[${new Date().toISOString()}] [${endpoint}] User: ${userId || "N/A"} | ${success ? "SUCCESS" : "FAIL"} | ${message} | Body: ${JSON.stringify(reqBody)}`);
};

// ------------------------- Auth Routes -------------------------
app.post("/signup", async (req, res) => {
  const endpoint = "/signup";
  try {
    const { username, email, password, account_type, device_id, phone, NIN, CAC } = req.body;
    if (!username || !password || !device_id || !account_type || (!email && !phone)) {
      logApiCall(endpoint, req.body, null, false, "Missing required fields");
      return res.json({ error: "Missing required fields: username, password, device_id, account_type, and email or phone" });
    }

    if (account_type === "individual" && !NIN) {
      logApiCall(endpoint, req.body, null, false, "Missing NIN for individual account");
      return res.json({ error: "NIN is required for individual accounts" });
    }
    if (account_type === "organization" && !CAC) {
      logApiCall(endpoint, req.body, null, false, "Missing CAC for organization account");
      return res.json({ error: "CAC is required for organization accounts" });
    }

    if (await User.findOne({ $or: [{ email }, { phone }] })) {
      logApiCall(endpoint, req.body, null, false, "Email or phone already exists");
      return res.json({ error: "Email or phone already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const token = createDeviceToken(id, device_id);
    const expiry = Date.now() + TOKEN_LIFETIME;

    await new User({
      id, username, email, password: hashed, account_type, phone, NIN, CAC,
      device_id, token, token_expiry: expiry,
      login_attempts: { count: 0, last_reset: Date.now() }
    }).save();

    logApiCall(endpoint, req.body, id, true, "Signup successful");
    res.json({ message: "Signup successful", token, expiry });
  } catch (err) {
    console.error("Signup error:", err);
    logApiCall("/signup", req.body, null, false, "Signup failed, server error");
    res.json({ error: "Signup failed, check server logs" });
  }
});

app.post("/login", async (req, res) => {
  const endpoint = "/login";
  try {
    const { email, phone, password, device_id } = req.body;
    if ((!email && !phone) || !password || !device_id) {
      logApiCall(endpoint, req.body, null, false, "Missing credentials");
      return res.json({ error: "Missing credentials: email or phone, password, and device_id" });
    }

    const user = await User.findOne({ $or: [{ email }, { phone }] });
    if (!user) {
      logApiCall(endpoint, req.body, null, false, "No account found");
      return res.json({ error: "No account found for provided credentials" });
    }

    const now = Date.now();
    if (now - (user.login_attempts.last_reset || 0) > 86400000) {
      user.login_attempts.count = 0;
      user.login_attempts.last_reset = now;
    }
    if (user.login_attempts.count >= MAX_DAILY_TRIALS) {
      logApiCall(endpoint, req.body, user.id, false, "Too many login attempts");
      return res.json({ error: "Too many login attempts today" });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      user.login_attempts.count++;
      await user.save();
      logApiCall(endpoint, req.body, user.id, false, "Invalid credentials");
      return res.json({ error: "Invalid credentials" });
    }

    user.device_id = device_id;
    user.token = createDeviceToken(user.id, device_id);
    user.token_expiry = now + TOKEN_LIFETIME;
    user.login_attempts.count = 0;
    await user.save();

    logApiCall(endpoint, req.body, user.id, true, "Login successful");
    res.json({ message: "Login successful", token: user.token, expiry: user.token_expiry });
  } catch (err) {
    console.error("Login error:", err);
    logApiCall("/login", req.body, null, false, "Login failed, server error");
    res.json({ error: "Login failed, check server logs" });
  }
});

// ------------------------- Add logApiCall to all other routes similarly -------------------------
// For /token-login, /recover, /reset-password, /me, posts, chat, etc.

app.listen(3000, () => console.log("Backend running on port 3000"));
