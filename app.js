import express from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import bodyParser from "body-parser";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 🟦 SIMPLE IN-MEMORY DATABASE
let users = [];

/*
 users = [
   {
     id: "uuid",
     username: "JohnDoe",
     email: "test@example.com",
     password: "hashed password",
     account_type: "individual" | "organization",
     NIN: "1234567890",
     phone: "+2348109995009",
     father_name: "John Senior",
     mother_name: "Jane Doe",
     token: "device-bound-token",
     token_expiry: timestamp,
     device_id: "fingerprint-string",
     login_attempts: { count: 0, last_reset: timestamp }
   }
 ]
*/

// 🔒 TOKEN VALIDITY (1 WEEK)
const TOKEN_LIFETIME = 7 * 24 * 60 * 60 * 1000;

// 🔐 MAX PASSWORD TRIALS PER ACCOUNT EMAIL DAILY
const MAX_DAILY_TRIALS = 5;

// 🧩 Utility: Create short device-bound token
function createDeviceBoundToken(user_id, device_id) {
  const raw = user_id + ":" + device_id;
  const hash = crypto
    .createHash("sha256")
    .update(raw)
    .digest("base64")
    .replace(/=/g, "");
  return hash.substring(0, 32);
}

// ------------------------------------------------------------
// SIGNUP
// ------------------------------------------------------------
app.post("/signup", async (req, res) => {
  const { username, email, password, account_type, device_id, NIN, father_name, mother_name } = req.body;

  if (!username || !email || !password || !account_type || !device_id || !NIN || !father_name || !mother_name) {
    return res.json({ error: "All fields (username, email, password, account_type, device_id, NIN, father_name, mother_name) are required" });
  }

  const existing = users.find(u => u.email === email || u.username === username);
  if (existing) {
    return res.json({ error: "Email or username already registered. Try login or use different credentials." });
  }

  const hashed = await bcrypt.hash(password, 10);
  const id = uuidv4();

  const token = createDeviceBoundToken(id, device_id);
  const expiry = Date.now() + TOKEN_LIFETIME;

  const user = {
    id,
    username,
    email,
    password: hashed,
    account_type,
    NIN,
    phone,
    father_name,
    mother_name,
    token,
    token_expiry: expiry,
    device_id: typeof device_id === "string" ? device_id : JSON.stringify(device_id),
    login_attempts: { count: 0, last_reset: Date.now() }
  };

  users.push(user);

  res.json({
    message: "Signup successful",
    token,
    expiry
  });
});

// ------------------------------------------------------------
// LOGIN (email OR username + password → returns SAME token for same device)
// ------------------------------------------------------------
app.post("/login", async (req, res) => {
  const { email, password, device_id } = req.body;

  if (!email || !password || !device_id) {
    return res.json({ error: "Email/Username, password, and device_id are required" });
  }

  const user = users.find(u => u.email === email || u.username === email);
  if (!user) return res.json({ error: "No account found with this email or username" });

  // Reset daily login attempts if needed
  const now = Date.now();
  if (now - user.login_attempts.last_reset > 24 * 60 * 60 * 1000) {
    user.login_attempts.count = 0;
    user.login_attempts.last_reset = now;
  }

  if (user.login_attempts.count >= MAX_DAILY_TRIALS) {
    return res.json({ error: `Maximum daily login attempts exceeded (${MAX_DAILY_TRIALS}). Try again tomorrow.` });
  }

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    user.login_attempts.count += 1;
    return res.json({ error: `Invalid login credentials. Attempt ${user.login_attempts.count} of ${MAX_DAILY_TRIALS}` });
  }

  if (user.device_id !== (typeof device_id === "string" ? device_id : JSON.stringify(device_id))) {
    return res.json({ error: "Device mismatch. Please login from your registered device." });
  }

  // Reset attempts on successful login
  user.login_attempts.count = 0;
  user.token_expiry = now + TOKEN_LIFETIME;

  res.json({
    message: "Login successful",
    token: user.token,
    expiry: user.token_expiry,
    account_type: user.account_type
  });
});

// ------------------------------------------------------------
// TOKEN LOGIN (device + token)
// ------------------------------------------------------------
app.post("/token-login", (req, res) => {
  const { token, device_id } = req.body;

  if (!token || !device_id) {
    return res.json({ error: "Token and device_id are required for token login" });
  }

  const user = users.find(u => u.token === token);
  if (!user) return res.json({ error: "Invalid token provided" });

  if (Date.now() > user.token_expiry) {
    return res.json({ error: "Token has expired, please login again" });
  }

  if (user.device_id !== (typeof device_id === "string" ? device_id : JSON.stringify(device_id))) {
    return res.json({ error: "Device mismatch. Token does not belong to this device" });
  }

  res.json({
    message: "Token login successful",
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      account_type: user.account_type
    }
  });
});

// ------------------------------------------------------------
// PROTECTED DATA EXAMPLE (/me)
// ------------------------------------------------------------
app.post("/me", (req, res) => {
  const { token, device_id } = req.body;

  const user = users.find(u => u.token === token);
  if (!user) return res.json({ error: "Invalid token" });

  if (Date.now() > user.token_expiry) {
    return res.json({ error: "Token expired. Please login again" });
  }

  if (user.device_id !== (typeof device_id === "string" ? device_id : JSON.stringify(device_id))) {
    return res.json({ error: "Device mismatch" });
  }

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    account_type: user.account_type,
    NIN: user.NIN,
    father_name: user.father_name,
    mother_name: user.mother_name
  });
});

app.listen(3000, () => console.log("Backend running on port 3000"));
