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
  id: String, username: String, email: String, password: String, account_type: String,
  phone: String, NIN: String, CAC: String,
  device_id: String, token: String, token_expiry: Number,
  login_attempts: { count: Number, last_reset: Number },
  reset_token: String, reset_expiry: Number
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

// ------------------------- Auth Routes -------------------------
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password, account_type, device_id, phone, NIN, CAC } = req.body;
    if (!username || !email || !password || !device_id || !account_type)
      return res.json({ error: "Missing required fields: username, email, password, device_id, or account_type" });
    if (account_type === "individual" && !NIN) return res.json({ error: "NIN is required for individual accounts" });
    if (account_type === "organization" && !CAC) return res.json({ error: "CAC is required for organization accounts" });

    if (await User.findOne({ $or: [{ email }, { username }] })) return res.json({ error: "Email or username already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const token = createDeviceToken(id, device_id);
    const expiry = Date.now() + TOKEN_LIFETIME;

    await new User({
      id, username, email, password: hashed, account_type, phone, NIN, CAC,
      device_id, token, token_expiry: expiry,
      login_attempts: { count: 0, last_reset: Date.now() }
    }).save();

    res.json({ message: "Signup successful", token, expiry });
  } catch (err) {
    console.error("Signup error:", err);
    res.json({ error: "Signup failed, check server logs" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password, device_id } = req.body;
    if (!email || !password || !device_id) return res.json({ error: "Missing credentials: email, password, or device_id" });

    const user = await User.findOne({ $or: [{ email }, { username: email }] });
    if (!user) return res.json({ error: "No account found for provided email/username" });

    const now = Date.now();
    if (now - user.login_attempts.last_reset > 86400000) {
      user.login_attempts.count = 0;
      user.login_attempts.last_reset = now;
    }
    if (user.login_attempts.count >= MAX_DAILY_TRIALS) return res.json({ error: "Too many login attempts today" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      user.login_attempts.count++;
      await user.save();
      return res.json({ error: "Invalid credentials" });
    }

    user.device_id = device_id;
    user.token = createDeviceToken(user.id, device_id);
    user.token_expiry = now + TOKEN_LIFETIME;
    user.login_attempts.count = 0;
    await user.save();

    res.json({ message: "Login successful", token: user.token, expiry: user.token_expiry });
  } catch (err) {
    console.error("Login error:", err);
    res.json({ error: "Login failed, check server logs" });
  }
});

app.post("/token-login", async (req, res) => {
  try {
    const { token, device_id, password } = req.body;
    if (!token || !device_id) return res.json({ error: "Token and device_id required" });

    const user = await User.findOne({ token });
    if (!user || Date.now() > user.token_expiry) return res.json({ error: "Invalid or expired token" });

    if (user.device_id !== device_id) {
      if (!password || !(await bcrypt.compare(password, user.password)))
        return res.json({ error: "Password required or incorrect for device change" });

      user.device_id = device_id;
      user.token = createDeviceToken(user.id, device_id);
      user.token_expiry = Date.now() + TOKEN_LIFETIME;
      await user.save();
      return res.json({ message: "Token login successful (device updated)", token: user.token, expiry: user.token_expiry });
    }

    res.json({ message: "Token login successful (same device)", user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    console.error("Token login error:", err);
    res.json({ error: "Token login failed, check server logs" });
  }
});

app.post("/recover", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ error: "Email required" });

    const user = await User.findOne({ email });
    if (!user) return res.json({ error: "No account associated with that email" });

    const reset_token = jwt.sign({ email }, process.env.RESET_SECRET, { expiresIn: "15m" });
    user.reset_token = reset_token;
    user.reset_expiry = Date.now() + 900000;
    await user.save();

    transporter.sendMail({ to: email, subject: "Password Reset", text: `Reset code:\n${reset_token}` });
    res.json({ message: "Password reset token sent to email" });
  } catch (err) {
    console.error("Recover error:", err);
    res.json({ error: "Failed to send password reset token" });
  }
});

app.post("/reset-password", async (req, res) => {
  try {
    const { token, new_password } = req.body;
    if (!token || !new_password) return res.json({ error: "Token and new password required" });

    let payload;
    try { payload = jwt.verify(token, process.env.RESET_SECRET); } 
    catch (err) { return res.json({ error: "Invalid or expired token" }); }

    const user = await User.findOne({ email: payload.email });
    if (!user || user.reset_token !== token || Date.now() > user.reset_expiry) return res.json({ error: "Token invalid or expired" });

    user.password = await bcrypt.hash(new_password, 10);
    user.reset_token = null; user.reset_expiry = null;
    await user.save();
    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.json({ error: "Password reset failed, check server logs" });
  }
});

app.post("/me", async (req, res) => {
  try {
    const user = await authMiddleware(req.body.token, req.body.device_id);
    if (!user) return res.json({ error: "Unauthorized" });
    const { id, username, email, account_type, phone, NIN, CAC } = user;
    res.json({ id, username, email, account_type, phone, NIN, CAC });
  } catch (err) {
    console.error("/me error:", err);
    res.json({ error: "Failed to fetch user info" });
  }
});

// ------------------------- Social Media Routes -------------------------
app.post("/post", async (req, res) => {
  try {
    const user = await authMiddleware(req.body.token, req.body.device_id);
    if (!user) return res.json({ error: "Unauthorized" });
    const post = await new Post({ author_id: user.id, content: req.body.content, media: req.body.media }).save();
    res.json({ message: "Post created", post });
  } catch (err) {
    console.error("Create post error:", err);
    res.json({ error: "Failed to create post" });
  }
});

app.get("/posts", async (_, res) => {
  try {
    const posts = await Post.find().sort({ created_at: -1 }).limit(50);
    res.json(posts);
  } catch (err) {
    console.error("Fetch posts error:", err);
    res.json({ error: "Failed to fetch posts" });
  }
});

app.post("/post/like", async (req, res) => {
  try {
    const user = await authMiddleware(req.body.token, req.body.device_id);
    if (!user) return res.json({ error: "Unauthorized" });

    const post = await Post.findOne({ id: req.body.post_id });
    if (!post) return res.json({ error: "Post not found" });

    post.likes++;
    await post.save();
    res.json({ message: "Post liked", likes: post.likes });
  } catch (err) {
    console.error("Like post error:", err);
    res.json({ error: "Failed to like post" });
  }
});

app.post("/post/comment", async (req, res) => {
  try {
    const user = await authMiddleware(req.body.token, req.body.device_id);
    if (!user) return res.json({ error: "Unauthorized" });

    const post = await Post.findOne({ id: req.body.post_id });
    if (!post) return res.json({ error: "Post not found" });

    post.comments.push({ id: uuidv4(), user_id: user.id, text: req.body.text, created_at: Date.now() });
    await post.save();
    res.json({ message: "Comment added", comments: post.comments });
  } catch (err) {
    console.error("Comment error:", err);
    res.json({ error: "Failed to add comment" });
  }
});

// ------------------------- Chat Routes -------------------------
app.post("/chat/send", async (req, res) => {
  try {
    const user = await authMiddleware(req.body.token, req.body.device_id);
    if (!user) return res.json({ error: "Unauthorized" });

    const chat = await new Chat({ from_id: user.id, to_id: req.body.to_id, message: req.body.message }).save();
    res.json({ message: "Message sent", chat });
  } catch (err) {
    console.error("Send chat error:", err);
    res.json({ error: "Failed to send message" });
  }
});

app.get("/chat/:userId", async (req, res) => {
  try {
    const user = await authMiddleware(req.query.token, req.query.device_id);
    if (!user) return res.json({ error: "Unauthorized" });

    const chats = await Chat.find({ 
      $or: [
        { from_id: user.id, to_id: req.params.userId }, 
        { from_id: req.params.userId, to_id: user.id } 
      ] 
    }).sort({ created_at: 1 });

    res.json(chats);
  } catch (err) {
    console.error("Fetch chat error:", err);
    res.json({ error: "Failed to fetch chats" });
  }
});

// ------------------------- Start Server -------------------------
app.listen(3000, () => console.log("Backend running on port 3000"));
