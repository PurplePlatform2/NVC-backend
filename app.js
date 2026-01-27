import express from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import bodyParser from "body-parser";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";
import mongoose from "mongoose";
import nodemailer from "nodemailer";
import { MeiliSearch } from "meilisearch";

const app = express();
app.use(cors({ origin: "*", methods: ["GET", "POST", "OPTIONS", "PUT", "DELETE"], allowedHeaders: ["*"] }));
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "50mb" }));

// ------------------------- CONFIGURATION -------------------------
const CONFIG = {
  PORT: process.env.PORT || 3000,
  TOKEN_LIFETIME: 7 * 24 * 60 * 60 * 1000,
  MAX_DAILY_TRIALS: 5,
  MONGODB_OPTS: {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000
  },
  MEILI: {
    host: process.env.MEILISEARCH_HOST || "http://localhost:7700",
    apiKey: process.env.MEILISEARCH_API_KEY || "masterKey"
  }
};

// ------------------------- DATABASE CONNECTION -------------------------
mongoose.connect(process.env.STORAGE_2, CONFIG.MONGODB_OPTS)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

// ------------------------- MEILISEARCH -------------------------
const meiliClient = (() => {
  try {
    const client = new MeiliSearch(CONFIG.MEILI);
    console.log("✅ Meilisearch Client Initialized");
    return client;
  } catch (error) {
    console.error("❌ Meilisearch Connection Error:", error);
    return null;
  }
})();

// ------------------------- SCHEMAS -------------------------
const visibility = { type: String, enum: ["public", "private", "selected"], default: "private" };
const fileSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4 },
  url: String,
  type: String,
  created_at: { type: Number, default: Date.now }
}, { _id: false });

const createSchema = (schema, options = {}) => new mongoose.Schema(schema, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }, ...options });

const userSchema = createSchema({
  id: { type: String, unique: true, index: true },
  username: { type: String, index: true },
  email: { type: String, unique: true, index: true },
  password: String,
  account_type: { type: String, enum: ["individual", "organization"], index: true },
  phone: { type: String, index: true },
  NIN: { type: String, index: true },
  CAC: { type: String, index: true },
  device_id: String,
  token: { type: String, index: true },
  token_expiry: Number,
  login_attempts: { count: { type: Number, default: 0 }, last_reset: { type: Number, default: Date.now } },
  reset_token: String,
  reset_expiry: Number,
  personal: { dob: String, gender: String, marital_status: String, nationality: String, state_of_origin: String, lga: String, religion: String, address: String, blood_group: String, genotype: String, disabilities: String, hobbies: [String], likes: [String], dislikes: [String], languages: [String], links: [String], visibility },
  family: { family_type: String, father: String, mother: String, stepfather: String, stepmother: String, siblings: [{ name: String, gender: String }], address: String, visibility },
  education: {
    schools: [{ id: { type: String, default: uuidv4 }, name: String, start_date: String, end_date: String, levels: [String], positions: [fileSchema], results: [fileSchema], awards: [fileSchema], visibility }],
    certificates: [{ id: { type: String, default: uuidv4 }, title: String, type: String, year: String, files: [fileSchema], visibility }]
  },
  occupations: {
    self_employed: [{ id: { type: String, default: uuidv4 }, name: String, description: String, location: String, experience: String, work_time: String, income_range: String, contacts: { phone: String, email: String }, links: [String], certifications: [fileSchema], services: [{ id: { type: String, default: uuidv4 }, title: String, description: String, quantity: Number, condition: String, price: String, images: [fileSchema], rating: Number }], previous_jobs: [fileSchema], visibility }],
    job_seeker: [{ id: { type: String, default: uuidv4 }, position: String, description: String, preferred_location: String, experience: String, income_range: String, contacts: { phone: String, email: String }, attachments: [fileSchema], comments: String, visibility }],
    employed: [{ id: { type: String, default: uuidv4 }, company: String, position: String, description: String, work_type: String, duration: String, salary: String, location: String, credentials: [fileSchema], awards: [fileSchema], previous_positions: [String], contacts: { phone: String, email: String }, links: [String], visibility }]
  },
  properties: [{ id: { type: String, default: uuidv4 }, name: String, description: String, acquisition: String, cost: String, images: [fileSchema], documents: [fileSchema], visibility }],
  transactions: [{ id: { type: String, default: uuidv4 }, type: { type: String, enum: ["purchase", "rental", "gift"] }, seller: String, buyer: String, items: String, quantity: Number, unit_price: String, total_price: String, status: String, date: String, documents: [fileSchema] }],
  media: [{ id: { type: String, default: uuidv4 }, file: fileSchema, title: String, description: String, rating: Number, likes: Number, dislikes: Number, created_at: { type: Number, default: Date.now }, visibility }],
  merits: [{ title: String, institution: String, date: String, files: [fileSchema] }],
  demerits: [{ crime: String, severity: String, conviction_date: String, authority: String, punishment: String, files: [fileSchema] }],
  created_at: { type: Number, default: Date.now, index: true },
  updated_at: { type: Number, default: Date.now }
});

const companySchema = createSchema({
  id: { type: String, unique: true, default: uuidv4, index: true },
  owner_id: { type: String, index: true },
  name: { type: String, required: true, index: true },
  description: String,
  email: { type: String, index: true },
  phone: { type: String, index: true },
  website: String,
  registration_number: { type: String, index: true },
  tax_id: String,
  industry: { type: String, index: true },
  company_type: { type: String, enum: ["llc", "corporation", "partnership", "sole_proprietorship"] },
  founded_date: String,
  size: { type: String, enum: ["1-10", "11-50", "51-200", "201-500", "501-1000", "1000+"] },
  address: String,
  city: String,
  state: String,
  country: String,
  postal_code: String,
  social_media: { linkedin: String, twitter: String, facebook: String, instagram: String },
  documents: [fileSchema],
  products_services: [{ id: { type: String, default: uuidv4 }, name: String, description: String, category: String, price_range: String, images: [fileSchema] }],
  team_members: [{ id: { type: String, default: uuidv4 }, user_id: String, name: String, position: String, email: String, phone: String, role: { type: String, enum: ["owner", "admin", "manager", "employee"] } }],
  annual_revenue: String,
  funding_status: String,
  investors: [String],
  visibility,
  status: { type: String, enum: ["active", "inactive", "pending", "suspended"], default: "active", index: true }
});

const postSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4 },
  author_id: String,
  content: String,
  media: [String],
  likes: { type: Number, default: 0 },
  comments: [{ id: String, user_id: String, text: String, created_at: Number }],
  created_at: { type: Number, default: Date.now }
});

const chatSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4 },
  from_id: String,
  to_id: String,
  message: String,
  created_at: { type: Number, default: Date.now }
});

// ------------------------- MODELS -------------------------
const User = mongoose.model("User", userSchema);
const Company = mongoose.model("Company", companySchema);
const Post = mongoose.model("Post", postSchema);
const Chat = mongoose.model("Chat", chatSchema);
const transporter = nodemailer.createTransport({ jsonTransport: true });

// ------------------------- UTILITIES -------------------------
const createToken = (id) => crypto.createHash("sha256").update(id + ":" + crypto.randomUUID()).digest("base64").replace(/=/g, "").substring(0, 32);
const log = (endpoint, userId, success, msg) => console.log(`[${new Date().toISOString()}] ${endpoint} | ${userId || "N/A"} | ${success ? "OK" : "FAIL"} | ${msg}`);
const sanitizeUser = (user) => { const { password, ...safe } = user.toObject(); return safe; };
const filterByVisibility = (arr) => arr?.filter(item => item.visibility === "public") || [];

const auth = async (token, device_id, password) => {
  if (!token) return { error: "Missing token" };
  const user = await User.findOne({ token });
  if (!user) return { error: "Invalid token" };
  if (Date.now() > user.token_expiry) return { error: "Token expired" };
  if (device_id === user.device_id) return { user };
  if (!password) return { error: "Hacking Detected--- Shutting down Account." };
  const valid = await bcrypt.compare(password, user.password);
  return valid ? { user } : { error: "Invalid credentials" };
};

// ------------------------- MEILISEARCH FUNCTIONS -------------------------
const meiliIndexes = {
  users: { searchable: ['username', 'email', 'phone', 'personal.address', 'personal.state_of_origin', 'personal.nationality', 'occupations.self_employed.name', 'occupations.employed.company', 'account_type'], filterable: ['account_type', 'personal.state_of_origin', 'personal.gender', 'created_at'], sortable: ['created_at', 'username'] },
  companies: { searchable: ['name', 'description', 'industry', 'address', 'city', 'state', 'country', 'registration_number', 'products_services.name', 'team_members.name'], filterable: ['industry', 'state', 'country', 'company_type', 'size', 'status', 'created_at'], sortable: ['created_at', 'name'] }
};

const initSearch = async () => {
  if (!meiliClient) return console.warn("⚠️ Meilisearch not available");
  try {
    for (const [index, settings] of Object.entries(meiliIndexes)) {
      await meiliClient.index(index).updateSettings({
        searchableAttributes: settings.searchable,
        filterableAttributes: settings.filterable,
        sortableAttributes: settings.sortable,
        displayedAttributes: ['id', ...settings.searchable.slice(0, 7)]
      });
    }
    console.log("✅ Search indexes initialized");
  } catch (e) { console.error("❌ Search init error:", e); }
};

const updateSearch = async (index, data) => {
  if (!meiliClient) return;
  try {
    await meiliClient.index(index).addDocuments([data]);
  } catch (e) { console.error(`❌ Error updating ${index}:`, e); }
};

const deleteSearch = async (index, id) => {
  if (!meiliClient) return;
  try {
    await meiliClient.index(index).deleteDocument(id);
  } catch (e) { console.error(`❌ Error deleting from ${index}:`, e); }
};

// ------------------------- AUTH ENDPOINTS -------------------------
app.post("/signup", async (req, res) => {
  try {
    const { username, email, phone, password, account_type, device_id, NIN, CAC } = req.body;
    const missing = !username || !password || !device_id || !account_type;
    if (missing) return res.json({ error: "Missing required fields" });
    if (account_type === "individual" && !NIN) return res.json({ error: "NIN required" });
    if (account_type === "organization" && !CAC) return res.json({ error: "CAC required" });
    if (await User.findOne({ $or: [{ email }, { phone }] })) return res.json({ error: "Email or phone exists" });
    
    const id = uuidv4();
    const user = await new User({
      id, username, email, phone, password: await bcrypt.hash(password, 10), account_type, NIN, CAC, device_id,
      token: createToken(id), token_expiry: Date.now() + CONFIG.TOKEN_LIFETIME, login_attempts: { count: 0, last_reset: Date.now() }
    }).save();
    
    await updateSearch('users', { id, username, email, phone, account_type, personal: user.personal, occupations: user.occupations, created_at: user.created_at });
    log("/signup", id, true, "Signup");
    res.json({ message: "Signup successful", token: user.token });
  } catch (e) {
    log("/signup", null, false, e.message);
    res.json({ error: "Signup failed: " + e.message });
  }
});

app.post("/login", async (req, res) => {
  const { email, phone, password, device_id } = req.body;
  if ((!email && !phone) || !password || !device_id) return res.json({ error: "Missing login data" });
  const user = await User.findOne({ $or: [{ email }, { phone }] });
  if (!user || !(await bcrypt.compare(password, user.password))) return res.json({ error: "Invalid credentials" });
  user.device_id = device_id;
  user.token = createToken(user.id);
  user.token_expiry = Date.now() + CONFIG.TOKEN_LIFETIME;
  await user.save();
  res.json({ message: "Login successful", token: user.token });
});

// ------------------------- SEARCH FUNCTIONS -------------------------
const searchMongo = async (Model, conditions, filters, fields, { limit, offset, sort }) => {
  const query = conditions.length ? { $or: conditions } : {};
  Object.entries(filters || {}).forEach(([k, v]) => { if (v) query[k] = v; });
  const [data, total] = await Promise.all([
    Model.find(query).select(fields).skip(offset).limit(limit).sort(sort).lean(),
    Model.countDocuments(query)
  ]);
  return { data, total };
};

const searchMeili = async (index, query, filters, { limit, offset, sort }) => {
  const params = { limit, offset, sort: [sort] };
  if (filters && Object.keys(filters).length) params.filter = Object.entries(filters).map(([k, v]) => `${k} = "${v}"`);
  return await meiliClient.index(index).search(query, params);
};

const handleSearch = (index, Model, conditionBuilder, filterMapper = {}) => async (req, res) => {
  try {
    const { query = "", filters = {}, limit = 20, offset = 0, sort_by = "created_at:desc", token, device_id } = req.body;
    if (token && device_id) { const authRes = await auth(token, device_id); if (authRes.error) return res.json({ error: authRes.error }); }
    
    let results;
    if (!meiliClient) {
      const mongoFilters = {};
      Object.entries(filterMapper).forEach(([src, dest]) => { if (filters[src]) mongoFilters[dest] = filters[src]; });
      const conditions = query ? conditionBuilder(query) : [];
      const { data, total } = await searchMongo(Model, conditions, mongoFilters, {}, { limit, offset, sort: { created_at: -1 } });
      results = { hits: data, estimatedTotalHits: total, processingTimeMs: 0 };
    } else {
      const meiliFilters = {};
      Object.entries(filterMapper).forEach(([src, dest]) => { if (filters[src]) meiliFilters[dest] = filters[src]; });
      results = await searchMeili(index, query, meiliFilters, { limit, offset, sort: sort_by });
    }
    
    res.json({
      success: true,
      results: results.hits,
      pagination: {
        total: results.estimatedTotalHits,
        limit, offset,
        has_more: offset + results.hits.length < results.estimatedTotalHits
      },
      processing_time_ms: results.processingTimeMs,
      source: meiliClient ? "meilisearch" : "mongodb_fallback"
    });
  } catch (e) {
    console.error(`❌ Search ${index} error:`, e);
    res.status(500).json({ error: "Search failed", details: e.message });
  }
};

// ------------------------- SEARCH ENDPOINTS -------------------------
app.post("/search/users", handleSearch('users', User, (q) => [
  { username: new RegExp(q, "i") }, { email: new RegExp(q, "i") }, { phone: new RegExp(q, "i") },
  { "personal.address": new RegExp(q, "i") }, { "personal.state_of_origin": new RegExp(q, "i") },
  { "occupations.self_employed.name": new RegExp(q, "i") }, { "occupations.employed.company": new RegExp(q, "i") }
], { account_type: "account_type", state: "personal.state_of_origin", gender: "personal.gender" }));

app.post("/search/companies", handleSearch('companies', Company, (q) => [
  { name: new RegExp(q, "i") }, { description: new RegExp(q, "i") }, { industry: new RegExp(q, "i") },
  { address: new RegExp(q, "i") }, { city: new RegExp(q, "i") }, { state: new RegExp(q, "i") },
  { "products_services.name": new RegExp(q, "i") }
], { industry: "industry", state: "state", country: "country", company_type: "company_type", size: "size", status: "status" }));

app.post("/search/all", async (req, res) => {
  try {
    const { query = "", limit = 10, token, device_id } = req.body;
    if (token && device_id) { const authRes = await auth(token, device_id); if (authRes.error) return res.json({ error: authRes.error }); }
    
    const [usersResults, companiesResults] = await Promise.all([
      User.find({ $or: [
        { username: new RegExp(query, "i") }, { email: new RegExp(query, "i") },
        { "personal.address": new RegExp(query, "i") }, { "personal.state_of_origin": new RegExp(query, "i") }
      ]}).select("id username email account_type personal.address personal.state_of_origin").limit(limit).lean(),
      Company.find({ $or: [
        { name: new RegExp(query, "i") }, { description: new RegExp(query, "i") },
        { industry: new RegExp(query, "i") }, { address: new RegExp(query, "i") }, { state: new RegExp(query, "i") }
      ]}).select("id name description industry address state country").limit(limit).lean()
    ]);
    
    res.json({ success: true, users: usersResults, companies: companiesResults, total: usersResults.length + companiesResults.length });
  } catch (e) {
    console.error("❌ Combined search error:", e);
    res.status(500).json({ error: "Search failed", details: e.message });
  }
});

// ------------------------- COMPANY ENDPOINTS -------------------------
const companyHandler = (method) => async (req, res) => {
  try {
    const { token, device_id, ...data } = req.body;
    const authRes = await auth(token, device_id);
    if (authRes.error) return res.json({ error: authRes.error });
    if (method === 'create' && authRes.user.account_type !== "organization") return res.json({ error: "Only organization accounts can create companies" });
    
    let result;
    switch(method) {
      case 'create':
        result = await new Company({ ...data, owner_id: authRes.user.id, id: uuidv4() }).save();
        await updateSearch('companies', result);
        break;
      case 'update':
        const company = await Company.findOne({ id: req.params.id });
        if (!company) return res.json({ error: "Company not found" });
        if (company.owner_id !== authRes.user.id) return res.json({ error: "No permission" });
        Object.assign(company, data, { updated_at: Date.now() });
        await company.save();
        await updateSearch('companies', company);
        result = company;
        break;
      case 'get':
        result = await Company.findOne({ id: req.params.id });
        if (!result) return res.json({ error: "Company not found" });
        break;
      case 'list':
        const { limit = 20, offset = 0 } = data;
        const [companies, total] = await Promise.all([
          Company.find({ owner_id: authRes.user.id }).skip(offset).limit(limit).sort({ created_at: -1 }).lean(),
          Company.countDocuments({ owner_id: authRes.user.id })
        ]);
        return res.json({ success: true, companies, pagination: { total, limit, offset, has_more: offset + companies.length < total } });
      case 'delete':
        const delCompany = await Company.findOne({ id: req.params.id });
        if (!delCompany) return res.json({ error: "Company not found" });
        if (delCompany.owner_id !== authRes.user.id) return res.json({ error: "No permission" });
        await delCompany.deleteOne();
        await deleteSearch('companies', req.params.id);
        return res.json({ success: true, message: "Company deleted" });
    }
    
    res.json({ success: true, message: `Company ${method === 'create' ? 'created' : 'updated'}`, company: result });
  } catch (e) {
    console.error(`❌ ${method} company error:`, e);
    res.status(500).json({ error: `Failed to ${method} company`, details: e.message });
  }
};

app.post("/companies/create", companyHandler('create'));
app.put("/companies/:id", companyHandler('update'));
app.post("/companies/:id", companyHandler('get'));
app.post("/companies/my", companyHandler('list'));
app.delete("/companies/:id", companyHandler('delete'));

// ------------------------- USER ENDPOINTS -------------------------
const userHandler = (type) => async (req, res) => {
  try {
    const { token, device_id, password, username } = req.body;
    
    if (type === 'public') {
      if (!username) return res.json({ error: "Username required" });
      const user = await User.findOne({ username });
      if (!user) return res.json({ error: "User not found" });
      const u = user.toObject();
      return res.json({
        success: true,
        user: {
          id: u.id, username: u.username, account_type: u.account_type, created_at: u.created_at,
          personal: u.personal?.visibility === "public" ? u.personal : undefined,
          family: u.family?.visibility === "public" ? u.family : undefined,
          education: { schools: filterByVisibility(u.education?.schools), certificates: filterByVisibility(u.education?.certificates) },
          occupations: {
            self_employed: filterByVisibility(u.occupations?.self_employed),
            job_seeker: filterByVisibility(u.occupations?.job_seeker),
            employed: filterByVisibility(u.occupations?.employed)
          },
          properties: filterByVisibility(u.properties),
          media: filterByVisibility(u.media)
        }
      });
    }
    
    const authRes = await auth(token, device_id, password);
    if (authRes.error) return res.json({ error: authRes.error });
    
    res.json({
      success: true,
      user: type === 'private' ? authRes.user.toObject() : sanitizeUser(authRes.user)
    });
  } catch (e) {
    res.json({ error: e.message });
  }
};

app.post("/me/basic", userHandler('basic'));
app.post("/me/private", userHandler('private'));
app.post("/me/public", userHandler('public'));

app.post("/update-profile", async (req, res) => {
  try {
    const { token, device_id, update } = req.body;
    const authRes = await auth(token, device_id);
    if (authRes.error || !update || typeof update !== "object") return res.json({ error: authRes.error || "Invalid update" });
    
    const ZONES = ["personal","family","education","occupations","properties","media","merits","demerits","phone","email"];
    const BLOCK = ["password","token","token_expiry","login_attempts","account_type","id","_id","device_id","created_at"];
    const valid = Object.keys(update).filter(p => !BLOCK.some(b => p===b||p.startsWith(b+".")) && ZONES.some(z => p===z||p.startsWith(z+".")));
    
    if (!valid.length) return res.json({ error: "No valid fields" });
    valid.forEach(p => authRes.user.set(p, update[p]));
    authRes.user.updated_at = Date.now();
    await authRes.user.save();
    await updateSearch('users', authRes.user);
    
    res.json({ success: true, user: sanitizeUser(authRes.user) });
  } catch (e) {
    res.json({ error: e.message });
  }
});

// ------------------------- ADMIN & HEALTH -------------------------
app.post("/sync/search-index", async (req, res) => {
  try {
    const { token, device_id, type = "all" } = req.body;
    const authRes = await auth(token, device_id);
    if (authRes.error || authRes.user.account_type !== "organization") return res.json({ error: authRes.error || "Unauthorized" });
    
    const results = {};
    if (meiliClient) {
      if (type === "users" || type === "all") {
        const users = await User.find({}).limit(5000).lean();
        if (users.length) {
          await meiliClient.index('users').addDocuments(users.map(u => ({
            id: u.id, username: u.username, email: u.email, phone: u.phone, account_type: u.account_type,
            personal: u.personal, occupations: u.occupations, created_at: u.created_at
          })));
          results.users = { synced: users.length };
        }
      }
      if (type === "companies" || type === "all") {
        const companies = await Company.find({}).limit(5000).lean();
        if (companies.length) {
          await meiliClient.index('companies').addDocuments(companies);
          results.companies = { synced: companies.length };
        }
      }
    }
    
    res.json({ success: true, message: "Search index sync completed", results });
  } catch (e) {
    console.error("❌ Sync error:", e);
    res.status(500).json({ error: "Sync failed", details: e.message });
  }
});

app.get("/health", (req, res) => res.json({
  status: "healthy",
  timestamp: new Date().toISOString(),
  services: {
    mongodb: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    meilisearch: meiliClient ? "connected" : "disconnected",
    server: "running"
  }
}));

// ------------------------- SERVER -------------------------
app.listen(CONFIG.PORT, () => {
  console.log(`🚀 Backend running on port ${CONFIG.PORT}`);
  setTimeout(initSearch, 3000);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received: closing server');
  app.close(() => {
    mongoose.connection.close(false, () => {
      console.log('Connections closed');
      process.exit(0);
    });
  });
});
