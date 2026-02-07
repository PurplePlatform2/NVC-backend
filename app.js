import express from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import bodyParser from "body-parser";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";
import mongoose from "mongoose";
import nodemailer from "nodemailer";

const app = express();
app.use(cors({ origin: "*", methods: ["GET", "POST", "OPTIONS"], allowedHeaders: ["*"] }));
app.use(bodyParser.json());

mongoose.connect(process.env.STORAGE_2, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB Connected")).catch(err => console.error("❌ MongoDB Connection Error:", err));

// Centralized privacy rules configuration
const PRIVACY_RULES = {
  personal: ['dob', 'NIN', 'address', 'phone', 'blood_group', 'genotype'],
  family: ['address', 'father', 'mother', 'stepfather', 'stepmother'],
  education_schools: ['results', 'awards'],
  education_certificates: ['files'],
  occupations_self_employed: ['income_range', 'contacts', 'certifications', 'previous_jobs'],
  occupations_job_seeker: ['income_range', 'contacts', 'attachments'],
  occupations_employed: ['salary', 'contacts', 'credentials'],
  properties: ['cost', 'documents'],
  media: ['description', 'rating', 'likes', 'dislikes'],
  user_root: ['email', 'phone', 'NIN', 'CAC', 'device_id', 'token', 'token_expiry', 'login_attempts', 'reset_token', 'reset_expiry', 'password']
};

const maskField = (obj, field, value = null) => {
  if (!obj || obj[field] === undefined) return;
  if (!obj._hidden) obj._hidden = {};
  obj._hidden[field] = obj[field];
  obj[field] = value;
};

const restoreField = (obj, field) => {
  if (obj?._hidden?.[field] !== undefined) {
    obj[field] = obj._hidden[field];
    delete obj._hidden[field];
  }
};

const maskUserPrivateFields = (user) => {
  if (!user) return user;
  
  // Apply centralized privacy rules
  if (user.personal) PRIVACY_RULES.personal.forEach(f => maskField(user.personal, f));
  if (user.family) PRIVACY_RULES.family.forEach(f => maskField(user.family, f));
  
  // Education - schools
  user.education?.schools?.forEach(school => {
    PRIVACY_RULES.education_schools.forEach(f => maskField(school, f, []));
  });
  
  // Education - certificates
  user.education?.certificates?.forEach(cert => {
    PRIVACY_RULES.education_certificates.forEach(f => maskField(cert, f, []));
  });
  
  // Occupations - self employed
  user.occupations?.self_employed?.forEach(emp => {
    PRIVACY_RULES.occupations_self_employed.forEach(f => maskField(emp, f));
  });
  
  // Occupations - job seeker
  user.occupations?.job_seeker?.forEach(job => {
    PRIVACY_RULES.occupations_job_seeker.forEach(f => maskField(job, f));
  });
  
  // Occupations - employed
  user.occupations?.employed?.forEach(emp => {
    PRIVACY_RULES.occupations_employed.forEach(f => maskField(emp, f));
  });
  
  // Properties
  user.properties?.forEach(prop => {
    PRIVACY_RULES.properties.forEach(f => maskField(prop, f));
  });
  
  // Media
  user.media?.forEach(media => {
    PRIVACY_RULES.media.forEach(f => maskField(media, f));
  });
  
  // User root fields
  PRIVACY_RULES.user_root.forEach(f => maskField(user, f));
  
  return user;
};

const fileSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4 },
  url: String,
  type: String,
  created_at: { type: Number, default: Date.now }
}, { _id: false });

// Database indexes
const userSchema = new mongoose.Schema({
  id: String, 
  username: { type: String, index: true },
  email: { type: String, index: true },
  password: String, 
  account_type: { type: String, index: true },
  phone: { type: String, index: true },
  NIN: String, 
  CAC: String, 
  device_id: String, 
  token: { type: String, index: true },
  token_expiry: Number,
  login_attempts: { count: Number, last_reset: Number }, 
  reset_token: String, 
  reset_expiry: Number,
  personal: {
    dob: String, 
    gender: String, 
    marital_status: String, 
    nationality: String, 
    state_of_origin: { type: String, index: true },
    lga: { type: String, index: true },
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
    _hidden: { type: Object, default: {} }
  },
  family: {
    family_type: String, 
    father: String, 
    mother: String, 
    stepfather: String, 
    stepmother: String,
    siblings: [{ name: String, gender: String }], 
    address: String, 
    _hidden: { type: Object, default: {} }
  },
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
      _hidden: { type: Object, default: {} }
    }],
    certificates: [{
      id: { type: String, default: uuidv4 }, 
      title: String, 
      type: String, 
      year: String,
      files: [fileSchema], 
      _hidden: { type: Object, default: {} }
    }]
  },
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
      _hidden: { type: Object, default: {} }
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
      _hidden: { type: Object, default: {} }
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
      _hidden: { type: Object, default: {} }
    }]
  },
  properties: [{
    id: { type: String, default: uuidv4 }, 
    name: String, 
    description: String, 
    acquisition: String,
    cost: String, 
    images: [fileSchema], 
    documents: [fileSchema], 
    _hidden: { type: Object, default: {} }
  }],
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
  media: [{
    id: { type: String, default: uuidv4 }, 
    file: fileSchema, 
    title: String, 
    description: String,
    rating: Number, 
    likes: Number, 
    dislikes: Number, 
    created_at: { type: Number, default: Date.now },
    _hidden: { type: Object, default: {} }
  }],
  merits: [{ title: String, institution: String, date: String, files: [fileSchema] }],
  demerits: [{ crime: String, severity: String, conviction_date: String, authority: String, punishment: String, files: [fileSchema] }],
  created_at: { type: Number, default: Date.now }, 
  _hidden: { type: Object, default: {} }
}, {
  toJSON: {
    transform: function(doc, ret) {
      // Auto-strip sensitive fields on output
      delete ret.password;
      delete ret.token;
      delete ret.token_expiry;
      delete ret.reset_token;
      delete ret.reset_expiry;
      delete ret.login_attempts;
      delete ret._id;
      delete ret.__v;
      return ret;
    }
  }
});

const User = mongoose.model("User", userSchema);
const Post = mongoose.model("Post", new mongoose.Schema({
  id: { type: String, default: uuidv4 }, 
  author_id: String, 
  content: String, 
  media: [String],
  likes: { type: Number, default: 0 }, 
  comments: [{ id: String, user_id: String, text: String, created_at: Number }],
  created_at: { type: Number, default: Date.now }
}));
const Chat = mongoose.model("Chat", new mongoose.Schema({
  id: { type: String, default: uuidv4 }, 
  from_id: String, 
  to_id: String, 
  message: String,
  created_at: { type: Number, default: Date.now }
}));

const TOKEN_LIFETIME = 7 * 24 * 60 * 60 * 1000;
const createNewToken = (user_id) => crypto.createHash("sha256").update(user_id + ":" + crypto.randomUUID()).digest("base64").replace(/=/g, "").substring(0, 32);

// Normalized authMiddleware return
const authMiddleware = async (token, device_id, password) => {
  if (!token) return { ok: false, error: "Missing token" };
  const user = await User.findOne({ token });
  if (!user) return { ok: false, error: "Invalid token" };
  if (Date.now() > user.token_expiry) return { ok: false, error: "Token expired" };
  if (device_id === user.device_id) return { ok: true, user };
  if (!password) return { ok: false, error: "Hacking Detected--- Shutting down Account." };
  const valid = await bcrypt.compare(password, user.password);
  return valid ? { ok: true, user } : { ok: false, error: "Invalid credentials" };
};

const logApiCall = (endpoint, body, userId, success, msg) => console.log(`[${new Date().toISOString()}] ${endpoint} | ${userId || "N/A"} | ${success ? "OK" : "FAIL"} | ${msg}`);

app.post("/signup", async (req, res) => {
  const endpoint = "/signup";
  try {
    const { username, email, phone, password, account_type, device_id, NIN, CAC } = req.body;
    if (!username || !password || !device_id || !account_type) return res.json({ error: "Missing required fields" });
    if (account_type === "individual" && !NIN) return res.json({ error: "NIN required" });
    if (account_type === "organization" && !CAC) return res.json({ error: "CAC required" });
    if (await User.findOne({ $or: [{ email }, { phone }] })) return res.json({ error: "Email or phone exists" });
    
    const id = uuidv4();
    const user = await new User({
      id, username, email, phone, password: await bcrypt.hash(password, 10), account_type, NIN, CAC, device_id,
      token: createNewToken(id), token_expiry: Date.now() + TOKEN_LIFETIME, login_attempts: { count: 0, last_reset: Date.now() }
    }).save();
    
    logApiCall(endpoint, req.body, id, true, "Signup");
    res.json({ message: "Signup successful", token: user.token });
  } catch (e) {
    logApiCall(endpoint, req.body, null, false, "Error");
    res.json({ error: "Signup failed" });
  }
});

app.post("/login", async (req, res) => {
  const { email, phone, password, device_id } = req.body;
  if ((!email && !phone) || !password || !device_id) return res.json({ error: "Missing login data" });
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

app.post("/search-users", async (req, res) => {
  try {
    const { token, device_id, filters = {} } = req.body;
    if (!token || !device_id) return res.status(400).json({ error: "Missing token or device_id" });
    const auth = await authMiddleware(token, device_id);
    if (!auth.ok) return res.status(401).json({ error: auth.error });
    
    const esc = s => String(s || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const and = [];
    if (filters.username?.trim()) {
      if (filters.username.trim().length < 3) return res.status(400).json({ error: "Username must be ≥ 3 chars" });
     and.push({ username: {  $regex: esc(filters.username.trim()),  $options: "i" }});

    }
    
    ["state_of_origin", "lga", "nationality", "gender", "religion", "marital_status"].forEach(f => {
      if (filters[f]?.trim()) and.push({
        $or: [{ [`personal.${f}`]: filters[f].trim() }, { [`personal._hidden.${f}`]: filters[f].trim() }]
      });
    });
    
    if (filters.account_type?.trim()) and.push({ account_type: filters.account_type.trim() });
    
    const users = await User.find(and.length ? { $and: and } : {}).limit(50).lean().select({
      _id: 1, id: 1, username: 1, account_type: 1, created_at: 1, "personal.gender": 1, "personal.state_of_origin": 1,
      "personal.lga": 1, "personal.nationality": 1, "personal.marital_status": 1, "personal.religion": 1
    });
    
    res.json({ success: true, count: users.length, results: users.map(u => maskUserPrivateFields(JSON.parse(JSON.stringify(u)))) });
  } catch (e) {
    console.error("SEARCH ERROR:", e);
    res.status(500).json({ error: "Search failed", details: e.message });
  }
});

const sanitizeUser = (user) => {
  const { password, ...safe } = user.toObject();
  return safe;
};

app.post("/me/basic", async (req, res) => {
  const { token, device_id, password } = req.body;
  const auth = await authMiddleware(token, device_id, password);
  if (!auth.ok) return res.json({ error: auth.error });
  res.json({ success: true, user: sanitizeUser(auth.user) });
});

app.post("/me/private", async (req, res) => {
  const { token, device_id, password } = req.body;
  const auth = await authMiddleware(token, device_id, password);
  if (!auth.ok) return res.json({ error: auth.error });
  
  const userObj = auth.user.toObject();
  
  // Explicitly delete sensitive fields before sending response
  delete userObj.password;
  delete userObj.token;
  delete userObj.token_expiry;
  
  if (userObj._hidden) {
    Object.keys(userObj._hidden).forEach(f => {
      if (userObj[f] === null || userObj[f] === undefined) {
        userObj[f] = userObj._hidden[f];
      }
    });
  }
  
  res.json({ success: true, user: userObj });
});

app.post("/me/public", async (req, res) => {
  const { username } = req.body;
  if (!username) return res.json({ error: "Username required" });
  const user = await User.findOne({ username });
  if (!user) return res.json({ error: "User not found" });
  const userObj = user.toObject();
  const removeHidden = (obj) => {
    if (obj && typeof obj === 'object') {
      delete obj._hidden;
      Object.keys(obj).forEach(k => typeof obj[k] === 'object' && removeHidden(obj[k]));
    }
  };
  removeHidden(userObj);
  res.json({ success: true, user: maskUserPrivateFields(userObj) });
});

const ZONES = ["personal", "family", "education", "occupations", "properties", "media", "merits", "demerits", "phone", "email"];
const BLOCK = ["password", "token", "token_expiry", "login_attempts", "account_type", "id", "_id", "device_id", "created_at", "_hidden"];
const ok = p => !BLOCK.some(b => p == b || p.startsWith(b + ".")) && ZONES.some(z => p == z || p.startsWith(z + "."));

app.post("/update-profile", async (req, res) => {
  const { token, device_id, update } = req.body;
  const auth = await authMiddleware(token, device_id);
  if (!auth.ok) return res.json({ error: auth.error });
  if (!update || typeof update !== "object") return res.json({ error: "Invalid update" });
  
  let hit = false;
  const processUpdate = (obj, path, value) => {
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      Object.keys(value).forEach(key => {
        if (key === '_hidden') {
          if (value._hidden) {
            obj._hidden = obj._hidden || {};
            Object.keys(value._hidden).forEach(h => obj._hidden[h] = value._hidden[h]);
          }
        } else {
          if (obj[key] !== undefined) {
            obj._hidden = obj._hidden || {};
            obj._hidden[key] = obj[key];
          }
          obj[key] = value[key];
        }
      });
    } else {
      if (obj[path] !== undefined) {
        obj._hidden = obj._hidden || {};
        obj._hidden[path] = obj[path];
      }
      obj[path] = value;
    }
  };
  
  for (const path in update) {
    if (ok(path)) {
      const paths = path.split('.');
      let current = auth.user;
      for (let i = 0; i < paths.length - 1; i++) {
        current = current[paths[i]];
        if (!current) break;
      }
      if (current && paths.length > 0) {
        processUpdate(current, paths[paths.length - 1], update[path]);
        hit = true;
      }
    }
  }
  
  if (!hit) return res.json({ error: "No valid fields" });
  await auth.user.save();
  res.json({ success: true, user: sanitizeUser(auth.user) });
});

app.listen(3000, () => console.log("🚀 Backend running on port 3000"));
