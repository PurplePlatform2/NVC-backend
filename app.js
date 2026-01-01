import express from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import bodyParser from "body-parser";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";
import mongoose from "mongoose";
import nodemailer from "nodemailer";

const app = express();
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["*"]
}));
app.use(bodyParser.json());

// ------------------------- MongoDB -------------------------
mongoose
  .connect(process.env.STORAGE_2, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

// ------------------------- COMMON SCHEMAS -------------------------
const visibility = { type: String, enum: ["public", "private", "selected"], default: "private" };

const fileSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4 },
  url: String,
  type: String,
  created_at: { type: Number, default: Date.now }
}, { _id: false });

// ------------------------- USER SCHEMA -------------------------
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
  reset_expiry: Number,

  // ---------- PERSONAL ----------
  personal: {
    dob: String,
    gender: String,
    marital_status: String,
    nationality: String,
    state_of_origin: String,
    lga: String,
    religion: String,
    address: String,
    blood_group: String,
    genotype: String,
    disabilities: String,
    hobbies: [String],
    likes: [String],
    dislikes: [String],
    languages: [String],
    links: [String],
    visibility
  },

  // ---------- FAMILY ----------
  family: {
    family_type: String,
    father: String,
    mother: String,
    stepfather: String,
    stepmother: String,
    siblings: [{ name: String, gender: String }],
    address: String,
    visibility
  },

  // ---------- EDUCATION ----------
  education: {
    schools: [{
      id: { type: String, default: uuidv4 },
      name: String,
      start_date: String,
      end_date: String,
      levels: [String],
      positions: [fileSchema],
      results: [fileSchema],
      awards: [fileSchema],
      visibility
    }],
    certificates: [{
      id: { type: String, default: uuidv4 },
      title: String,
      type: String,
      year: String,
      files: [fileSchema],
      visibility
    }]
  },

  // ---------- OCCUPATION ----------
  occupations: {
    self_employed: [{
      id: { type: String, default: uuidv4 },
      name: String,
      description: String,
      location: String,
      experience: String,
      work_time: String,
      income_range: String,
      contacts: { phone: String, email: String },
      links: [String],
      certifications: [fileSchema],
      services: [{
        id: { type: String, default: uuidv4 },
        title: String,
        description: String,
        quantity: Number,
        condition: String,
        price: String,
        images: [fileSchema],
        rating: Number
      }],
      previous_jobs: [fileSchema],
      visibility
    }],

    job_seeker: [{
      id: { type: String, default: uuidv4 },
      position: String,
      description: String,
      preferred_location: String,
      experience: String,
      income_range: String,
      contacts: { phone: String, email: String },
      attachments: [fileSchema],
      comments: String,
      visibility
    }],

    employed: [{
      id: { type: String, default: uuidv4 },
      company: String,
      position: String,
      description: String,
      work_type: String,
      duration: String,
      salary: String,
      location: String,
      credentials: [fileSchema],
      awards: [fileSchema],
      previous_positions: [String],
      contacts: { phone: String, email: String },
      links: [String],
      visibility
    }]
  },

  // ---------- PROPERTIES ----------
  properties: [{
    id: { type: String, default: uuidv4 },
    name: String,
    description: String,
    acquisition: String,
    cost: String,
    images: [fileSchema],
    documents: [fileSchema],
    visibility
  }],

  // ---------- TRANSACTIONS ----------
  transactions: [{
    id: { type: String, default: uuidv4 },
    type: { type: String, enum: ["purchase", "rental", "gift"] },
    seller: String,
    buyer: String,
    items: String,
    quantity: Number,
    unit_price: String,
    total_price: String,
    status: String,
    date: String,
    documents: [fileSchema]
  }],

  // ---------- MEDIA ----------
  media: [{
    id: { type: String, default: uuidv4 },
    file: fileSchema,
    title: String,
    description: String,
    rating: Number,
    likes: Number,
    dislikes: Number,
    created_at: { type: Number, default: Date.now },
    visibility
  }],

  // ---------- MERITS / DEMERITS ----------
  merits: [{
    title: String,
    institution: String,
    date: String,
    files: [fileSchema]
  }],

  demerits: [{
    crime: String,
    severity: String,
    conviction_date: String,
    authority: String,
    punishment: String,
    files: [fileSchema]
  }],

  created_at: { type: Number, default: Date.now }
});

const User = mongoose.model("User", userSchema);

// ------------------------- POSTS -------------------------
const postSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4 },
  author_id: String,
  content: String,
  media: [String],
  likes: { type: Number, default: 0 },
  comments: [{ id: String, user_id: String, text: String, created_at: Number }],
  created_at: { type: Number, default: Date.now }
});
const Post = mongoose.model("Post", postSchema);

// ------------------------- CHATS -------------------------
const chatSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4 },
  from_id: String,
  to_id: String,
  message: String,
  created_at: { type: Number, default: Date.now }
});
const Chat = mongoose.model("Chat", chatSchema);

// ------------------------- CONSTANTS -------------------------
const TOKEN_LIFETIME = 7 * 24 * 60 * 60 * 1000;
const MAX_DAILY_TRIALS = 5;
const transporter = nodemailer.createTransport({ jsonTransport: true });

// ------------------------- HELPERS -------------------------
const createNewToken = (user_id) =>
  crypto.createHash("sha256")
    .update(user_id + ":" + crypto.randomUUID())
    .digest("base64")
    .replace(/=/g, "")
    .substring(0, 32);

// ------------------------- AUTH -------------------------
const authMiddleware = async (token, device_id, password) => {
  if (!token) return { error: "Missing token" };
  const user = await User.findOne({ token });
  if (!user) return { error: "Invalid token" };
  if (Date.now() > user.token_expiry) return { error: "Token expired" };

  if (device_id === user.device_id) return { user };
  if (!password) return { error: "Hacking Detected--- Shutting down Account." };

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return { error: "Invalid credentials" };

  return { user };
};

// ------------------------- LOGGER -------------------------
const logApiCall = (endpoint, body, userId, success, msg) => {
  console.log(`[${new Date().toISOString()}] ${endpoint} | ${userId || "N/A"} | ${success ? "OK" : "FAIL"} | ${msg}`);
};

// ------------------------- SIGNUP -------------------------
app.post("/signup", async (req, res) => {
  const endpoint = "/signup";
  try {
    const { username, email, phone, password, account_type, device_id, NIN, CAC } = req.body;

    if (!username || !password || !device_id || !account_type)
      return res.json({ error: "Missing required fields" });

    if (account_type === "individual" && !NIN)
      return res.json({ error: "NIN required" });

    if (account_type === "organization" && !CAC)
      return res.json({ error: "CAC required" });

    if (await User.findOne({ $or: [{ email }, { phone }] }))
      return res.json({ error: "Email or phone exists" });

    const hashed = await bcrypt.hash(password, 10);
    const id = uuidv4();

    const user = await new User({
      id,
      username,
      email,
      phone,
      password: hashed,
      account_type,
      NIN,
      CAC,
      device_id,
      token: createNewToken(id),
      token_expiry: Date.now() + TOKEN_LIFETIME,
      login_attempts: { count: 0, last_reset: Date.now() }
    }).save();

    logApiCall(endpoint, req.body, id, true, "Signup");
    res.json({ message: "Signup successful", token: user.token });

  } catch (e) {
    logApiCall(endpoint, req.body, null, false, "Error");
    res.json({ error: "Signup failed" });
  }
});

// ------------------------- LOGIN -------------------------
app.post("/login", async (req, res) => {
  const { email, phone, password, device_id } = req.body;

  if ((!email && !phone) || !password || !device_id)
    return res.json({ error: "Missing login data" });

  const user = await User.findOne({ $or: [{ email }, { phone }] });
  if (!user) return res.json({ error: "Account not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.json({ error: "Invalid credentials" });

  user.device_id = device_id;
  user.token = createNewToken(user.id);
  user.token_expiry = Date.now() + TOKEN_LIFETIME;
  await user.save();

  res.json({ message: "Login successful", token: user.token });
});

// ------------------------- SEARCH USERS -------------------------
app.post("/search-users", async (req, res) => {
  const { token, device_id, username } = req.body;
  const auth = await authMiddleware(token, device_id);
  if (auth.error) return res.json({ error: auth.error });

  const users = await User.find({ username: new RegExp(username, "i") })
    .select("id username email phone account_type personal");

  res.json({ results: users });
});

// ------------------------- ME -------------------------
app.post("/me", async (req, res) => {
  const { token, device_id, password } = req.body;
  const auth = await authMiddleware(token, device_id, password);
  if (auth.error) return res.json({ error: auth.error });

  const { password: _, ...safe } = auth.user.toObject();
  res.json({ success: true, user: safe });
});

// ------------------------- UPDATE PROFILE -------------------------
app.post("/update-profile", async (req, res) => {
  const { token, device_id, user } = req.body;
  const auth = await authMiddleware(token, device_id);
  if (auth.error) return res.json({ error: auth.error });

  Object.assign(auth.user, user);
  await auth.user.save();

  const { password, ...safe } = auth.user.toObject();
  res.json({ success: true, user: safe });
});

// ------------------------- SERVER -------------------------
app.listen(3000, () => console.log("🚀 Backend running on port 3000"));

