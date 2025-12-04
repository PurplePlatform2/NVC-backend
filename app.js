import express from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import bodyParser from "body-parser";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";
import mongoose from "mongoose";
import nodemailer from "nodemailer";

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ------------------------- MongoDB -------------------------
mongoose
  .connect(process.env.STORAGE_2, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

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

  device_id: String,      // bound to last successful login
  token: String,          // regenerated every successful login
  token_expiry: Number,

  login_attempts: { count: Number, last_reset: Number },
  reset_token: String,
  reset_expiry: Number,

  dob: String,
  marital_status: String,
  gender: String,
  address: String,
  individual_description: String,
  organizational_description: String
});

const User = mongoose.model("User", userSchema);

// -----------------------------------------------------------
const postSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  author_id: String,
  content: String,
  media: [String],
  likes: { type: Number, default: 0 },
  comments: [
    { id: String, user_id: String, text: String, created_at: Number }
  ],
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

// ❗ NEW TOKEN CREATOR: No device_id used anymore
const createNewToken = (user_id) =>
  crypto
    .createHash("sha256")
    .update(user_id + ":" + crypto.randomUUID())
    .digest("base64")
    .replace(/=/g, "")
    .substring(0, 32);


// ------------------------- AUTH MIDDLEWARE -------------------------
const authMiddleware = async (token, device_id, password) => {
  if (!token) return { error: "Missing token" };

  const user = await User.findOne({ token });
  if (!user) return { error: "Invalid token" };

  if (Date.now() > user.token_expiry)
    return { error: "Token expired" };

  // Device check only on token login
  if(device_id == user.device_id) return {user};
 else if ( !password) {
    console.log(
      "UNKNOWN DEVICE ATTEMPTED TOKEN LOGIN FOR => " +
      user.username +
      "\nDEVICE USED: " + device_id +
      "\nREGISTERED DEVICE: " + user.device_id
    );
    return { error: "Hacking Detected--- Shutting down Account." };
  }

  
  const validPass = await bcrypt.compare(password || "", user.password);
  if (!validPass) {
    console.log("WRONG PASSWORD DURING TOKEN LOGIN => " + user.username);
    return { error: "Invalid credentials for token login" };
  }

  return { user };
};


// ------------------------- Logger -------------------------
const logApiCall = (endpoint, reqBody, userId, success, message) => {
  console.log(
    `[${new Date().toISOString()}] [${endpoint}] User:${userId || "N/A"} | ${success ? "SUCCESS" : "FAIL"} | ${message} | Body:${JSON.stringify(
      reqBody
    )}`
  );
};

// ------------------------- SIGNUP -------------------------
app.post("/signup", async (req, res) => {
  const endpoint = "/signup";
  try {
    const {
      username,
      email,
      password,
      account_type,
      device_id,
      phone,
      NIN,
      CAC,
      dob,
      marital_status,
      gender,
      address,
      individual_description,
      organizational_description
    } = req.body;

    if (!username || !password || !device_id || !account_type || (!email && !phone)) {
      logApiCall(endpoint, req.body, null, false, "Missing required fields");
      return res.json({
        error: "Missing fields: username, password, device_id, account_type, and email or phone"
      });
    }

    if (account_type === "individual" && !NIN)
      return res.json({ error: "NIN is required for individual accounts" });

    if (account_type === "organization" && !CAC)
      return res.json({ error: "CAC is required for organization accounts" });

    if (await User.findOne({ $or: [{ email }, { phone }] }))
      return res.json({ error: "Email or phone already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const token = createNewToken(id);
    const expiry = Date.now() + TOKEN_LIFETIME;

    await new User({
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
      login_attempts: { count: 0, last_reset: Date.now() },

      dob,
      marital_status,
      gender,
      address,
      individual_description,
      organizational_description
    }).save();

    logApiCall(endpoint, req.body, id, true, "Signup successful");
    res.json({ message: "Signup successful", token, expiry });
  } catch (err) {
    console.error(err);
    logApiCall(endpoint, req.body, null, false, "Server error");
    res.json({ error: "Signup failed" });
  }
});

// ------------------------- LOGIN -------------------------
app.post("/login", async (req, res) => {
  const endpoint = "/login";
  try {
    const { email, phone, password, device_id } = req.body;

    if ((!email && !phone) || !password || !device_id)
      return res.json({ error: "Missing: email or phone, password, device_id" });

    const user = await User.findOne({ $or: [{ email }, { phone }] });
    if (!user)
      return res.json({ error: "No account found" });

    const now = Date.now();

    if (now - (user.login_attempts.last_reset || 0) > 86400000) {
      user.login_attempts.count = 0;
      user.login_attempts.last_reset = now;
    }

    if (user.login_attempts.count >= MAX_DAILY_TRIALS)
      return res.json({ error: "Too many login attempts today" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      user.login_attempts.count++;
      await user.save();
      return res.json({ error: "Invalid credentials" });
    }

    // Successful login = always replace token + device_id
    user.device_id = device_id;
    user.token = createNewToken(user.id);
    user.token_expiry = now + TOKEN_LIFETIME;
    user.login_attempts.count = 0;
    await user.save();

    logApiCall(endpoint, req.body, user.id, true, "Login successful");
    res.json({ message: "Login successful", token: user.token, expiry: user.token_expiry });
  } catch (err) {
    console.error(err);
    res.json({ error: "Login failed" });
  }
});

// ------------------------- SEARCH USERS -------------------------
app.post("/search-users", async (req, res) => {
  const endpoint = "/search-users";
  const { token, device_id, username } = req.body;

  if (!token || !device_id || !username)
    return res.json({ error: "Missing: token, device_id, username" });

  const auth = await authMiddleware(token, device_id);

  if (auth.error) {
    logApiCall(endpoint, req.body, null, false, auth.error);
    return res.json({ error: auth.error });
  }

  const user = auth.user;

  try {
    const regex = new RegExp(username, "i");

    const users = await User.find({ username: regex }).select(`
      id username email phone account_type
      dob marital_status gender address
      NIN CAC individual_description organizational_description
    `);

    logApiCall(endpoint, req.body, user.id, true, "Search OK");
    res.json({ results: users });
  } catch (err) {
    console.error(err);
    res.json({ error: "Search failed" });
  }
});

// ------------------------- GET CURRENT USER -------------------------
app.post("/me", async (req, res) => {
  const { token, device_id, password: loginPassword } = req.body;

  if (!token) return res.json({ success: false, reason: "Missing token" });
  if (!device_id && !loginPassword) return res.json({ success: false, reason: "Provide device_id or password" });

  const auth = await authMiddleware({ token, device_id, loginPassword });
  if (auth.error) return res.json({ success: false, reason: auth.error });

  const { password, ...userData } = auth.user.toObject();
  logApiCall("/me", req.body, auth.user.id, true, "Fetched /me");
  res.json({ success: true, user: userData });
});


// ------------------------- SERVER -------------------------
app.listen(3000, () => console.log("Backend running on port 3000"));
