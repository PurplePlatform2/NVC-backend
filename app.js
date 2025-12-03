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

// ------------------------------------------------------------
// 🔌 CONNECT TO MONGODB USING STORAGE_2
// ------------------------------------------------------------
mongoose
  .connect(process.env.STORAGE_2, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err));

// ------------------------------------------------------------
// 📦 USER SCHEMA
// ------------------------------------------------------------
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

  login_attempts: {
    count: Number,
    last_reset: Number
  },

  reset_token: String,
  reset_expiry: Number
});

const User = mongoose.model("User", userSchema);

// ------------------------------------------------------------
// ⚙️ CONSTANTS
// ------------------------------------------------------------
const TOKEN_LIFETIME = 7 * 24 * 60 * 60 * 1000; // 1 week
const MAX_DAILY_TRIALS = 5;

// ------------------------------------------------------------
// 🔑 SHORT TOKEN (device-bound)
// ------------------------------------------------------------
function createDeviceBoundToken(user_id, device_id) {
  const raw = `${user_id}:${device_id}`;
  const hash = crypto.createHash("sha256").update(raw).digest("base64").replace(/=/g, "");
  return hash.substring(0, 32);
}

// ------------------------------------------------------------
// 📨 EMAIL TRANSPORT (Fake — logs to console)
// ------------------------------------------------------------
const transporter = nodemailer.createTransport({
  jsonTransport: true
});

// ------------------------------------------------------------
// SIGNUP
// ------------------------------------------------------------
app.post("/signup", async (req, res) => {
  const { username, email, password, account_type, device_id, phone, NIN, CAC } = req.body;

  if (!username) return res.json({ error: "Username is required" });
  if (!email) return res.json({ error: "Email is required" });
  if (!password) return res.json({ error: "Password is required" });
  if (!device_id) return res.json({ error: "Device ID is required" });
  if (!account_type) return res.json({ error: "Account type is required" });

  if (account_type === "individual" && !NIN)
    return res.json({ error: "NIN required for individual" });
  if (account_type === "organization" && !CAC)
    return res.json({ error: "CAC required for organization" });

  const exist = await User.findOne({ $or: [{ email }, { username }] });
  if (exist) return res.json({ error: "Email or username already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const id = uuidv4();

  const token = createDeviceBoundToken(id, device_id);
  const expiry = Date.now() + TOKEN_LIFETIME;

  const newUser = new User({
    id,
    username,
    email,
    password: hashed,
    account_type,
    phone,
    NIN,
    CAC,

    device_id,
    token,
    token_expiry: expiry,

    login_attempts: { count: 0, last_reset: Date.now() }
  });

  await newUser.save();

  res.json({
    message: "Signup successful",
    token,
    expiry
  });
});

// ------------------------------------------------------------
// LOGIN — device always changes (refresh every login)
// ------------------------------------------------------------
app.post("/login", async (req, res) => {
  const { email, password, device_id } = req.body;

  if (!email || !password || !device_id)
    return res.json({ error: "Email, password and device ID required" });

  const user = await User.findOne({
    $or: [{ email }, { username: email }]
  });

  if (!user) return res.json({ error: "No account found" });

  const now = Date.now();

  // Reset login attempts daily
  if (now - user.login_attempts.last_reset > 24 * 60 * 60 * 1000) {
    user.login_attempts.count = 0;
    user.login_attempts.last_reset = now;
  }

  if (user.login_attempts.count >= MAX_DAILY_TRIALS)
    return res.json({ error: "Too many attempts. Try again tomorrow" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    user.login_attempts.count += 1;
    await user.save();
    return res.json({ error: "Invalid credentials" });
  }

  // 🔥 DEVICE INFO ALWAYS UPDATES ON LOGIN
  user.device_id = device_id;

  // Generate brand-new token for the new device
  user.token = createDeviceBoundToken(user.id, device_id);
  user.token_expiry = now + TOKEN_LIFETIME;

  user.login_attempts.count = 0;
  await user.save();

  res.json({
    message: "Login successful",
    token: user.token,
    expiry: user.token_expiry
  });
});

// ------------------------------------------------------------
// TOKEN LOGIN — requires password when device changes
// ------------------------------------------------------------
app.post("/token-login", async (req, res) => {
  const { token, device_id, password } = req.body;

  if (!token || !device_id)
    return res.json({ error: "Token and device required" });

  const user = await User.findOne({ token });
  if (!user) return res.json({ error: "Invalid token" });

  if (Date.now() > user.token_expiry)
    return res.json({ error: "Token expired" });

  // If device is SAME — login instantly
  if (user.device_id === device_id) {
    return res.json({
      message: "Token login successful (same device)",
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  }

  // Device changed → must provide password
  if (!password)
    return res.json({
      error: "Password required because device is different"
    });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.json({ error: "Wrong password" });

  // ✔ Password correct → update device & generate new token
  user.device_id = device_id;
  user.token = createDeviceBoundToken(user.id, device_id);
  user.token_expiry = Date.now() + TOKEN_LIFETIME;
  await user.save();

  res.json({
    message: "Token login successful (device updated)",
    token: user.token,
    expiry: user.token_expiry
  });
});

// ------------------------------------------------------------
// PASSWORD RECOVERY — step 1: request reset link
// ------------------------------------------------------------
app.post("/recover", async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.json({ error: "No account with that email" });

  const reset_token = jwt.sign(
    { email },
    process.env.RESET_SECRET,
    { expiresIn: "15m" }
  );

  user.reset_token = reset_token;
  user.reset_expiry = Date.now() + 15 * 60 * 1000;
  await user.save();

  transporter.sendMail({
    to: email,
    subject: "Password Reset",
    text: `Use this code to reset your password:\n\n${reset_token}`
  });

  res.json({
    message: "Password reset token sent to email"
  });
});

// ------------------------------------------------------------
// PASSWORD RESET — step 2
// ------------------------------------------------------------
app.post("/reset-password", async (req, res) => {
  const { token, new_password } = req.body;

  if (!token || !new_password)
    return res.json({ error: "Token and new password are required" });

  let payload;
  try {
    payload = jwt.verify(token, process.env.RESET_SECRET);
  } catch {
    return res.json({ error: "Invalid or expired token" });
  }

  const user = await User.findOne({ email: payload.email });
  if (!user) return res.json({ error: "Account no longer exists" });

  if (user.reset_token !== token)
    return res.json({ error: "Token mismatch" });

  if (Date.now() > user.reset_expiry)
    return res.json({ error: "Reset token expired" });

  user.password = await bcrypt.hash(new_password, 10);
  user.reset_token = null;
  user.reset_expiry = null;
  await user.save();

  res.json({ message: "Password reset successful" });
});

// ------------------------------------------------------------
// PROTECTED ROUTE
// ------------------------------------------------------------
app.post("/me", async (req, res) => {
  const { token, device_id } = req.body;

  const user = await User.findOne({ token });
  if (!user) return res.json({ error: "Invalid token" });

  if (Date.now() > user.token_expiry)
    return res.json({ error: "Token expired" });

  if (user.device_id !== device_id)
    return res.json({ error: "Device mismatch" });

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    account_type: user.account_type,
    phone: user.phone,
    NIN: user.NIN,
    CAC: user.CAC
  });
});

// ------------------------------------------------------------
app.listen(3000, () => console.log("Backend running on port 3000"));
