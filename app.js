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
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
  allowedHeaders: ["*"]
}));
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "50mb" }));

// ------------------------- MongoDB -------------------------
mongoose
  .connect(process.env.STORAGE_2, { 
    useNewUrlParser: true, 
    useUnifiedTopology: true,
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

// ------------------------- Meilisearch Client -------------------------
let meiliClient;
try {
  meiliClient = new MeiliSearch({
    host: process.env.MEILISEARCH_HOST || "http://localhost:7700",
    apiKey: process.env.MEILISEARCH_API_KEY || "masterKey"
  });
  console.log("✅ Meilisearch Client Initialized");
} catch (error) {
  console.error("❌ Meilisearch Connection Error:", error);
  meiliClient = null;
}

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

  login_attempts: { 
    count: { type: Number, default: 0 },
    last_reset: { type: Number, default: Date.now }
  },
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

  created_at: { type: Number, default: Date.now, index: true },
  updated_at: { type: Number, default: Date.now }
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

const User = mongoose.model("User", userSchema);

// ------------------------- COMPANY SCHEMA -------------------------
const companySchema = new mongoose.Schema({
  id: { type: String, unique: true, default: uuidv4, index: true },
  owner_id: { type: String, index: true },
  name: { type: String, required: true, index: true },
  description: String,
  email: { type: String, index: true },
  phone: { type: String, index: true },
  website: String,
  
  // Company Details
  registration_number: { type: String, index: true },
  tax_id: String,
  industry: { type: String, index: true },
  company_type: { type: String, enum: ["llc", "corporation", "partnership", "sole_proprietorship"] },
  founded_date: String,
  size: { type: String, enum: ["1-10", "11-50", "51-200", "201-500", "501-1000", "1000+"] },
  
  // Location
  address: String,
  city: String,
  state: String,
  country: String,
  postal_code: String,
  
  // Social Media
  social_media: {
    linkedin: String,
    twitter: String,
    facebook: String,
    instagram: String
  },
  
  // Documents
  documents: [fileSchema],
  
  // Products/Services
  products_services: [{
    id: { type: String, default: uuidv4 },
    name: String,
    description: String,
    category: String,
    price_range: String,
    images: [fileSchema]
  }],
  
  // Team
  team_members: [{
    id: { type: String, default: uuidv4 },
    user_id: String,
    name: String,
    position: String,
    email: String,
    phone: String,
    role: { type: String, enum: ["owner", "admin", "manager", "employee"] }
  }],
  
  // Financial Information
  annual_revenue: String,
  funding_status: String,
  investors: [String],
  
  // Visibility Settings
  visibility: visibility,
  
  // Status
  status: { type: String, enum: ["active", "inactive", "pending", "suspended"], default: "active", index: true },
  
  created_at: { type: Number, default: Date.now, index: true },
  updated_at: { type: Number, default: Date.now }
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

const Company = mongoose.model("Company", companySchema);

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

// ------------------------- MEILISEARCH HELPERS -------------------------
const initMeiliSearchIndexes = async () => {
  if (!meiliClient) {
    console.warn("⚠️ Meilisearch not available, skipping index initialization");
    return;
  }

  try {
    // Initialize Users Index
    const usersIndex = meiliClient.index('users');
    
    await usersIndex.updateSettings({
      searchableAttributes: [
        'username',
        'email',
        'phone',
        'personal.address',
        'personal.state_of_origin',
        'personal.nationality',
        'occupations.self_employed.name',
        'occupations.employed.company',
        'account_type'
      ],
      filterableAttributes: [
        'account_type',
        'personal.state_of_origin',
        'personal.gender',
        'created_at'
      ],
      sortableAttributes: ['created_at', 'username'],
      displayedAttributes: [
        'id',
        'username',
        'email',
        'phone',
        'account_type',
        'personal',
        'occupations',
        'created_at'
      ]
    });
    
    console.log("✅ Users index settings updated");

    // Initialize Companies Index
    const companiesIndex = meiliClient.index('companies');
    
    await companiesIndex.updateSettings({
      searchableAttributes: [
        'name',
        'description',
        'industry',
        'address',
        'city',
        'state',
        'country',
        'registration_number',
        'products_services.name',
        'team_members.name'
      ],
      filterableAttributes: [
        'industry',
        'state',
        'country',
        'company_type',
        'size',
        'status',
        'created_at'
      ],
      sortableAttributes: ['created_at', 'name'],
      displayedAttributes: [
        'id',
        'name',
        'description',
        'email',
        'phone',
        'address',
        'city',
        'state',
        'country',
        'industry',
        'company_type',
        'size',
        'status',
        'website',
        'social_media',
        'products_services',
        'created_at'
      ]
    });
    
    console.log("✅ Companies index settings updated");

    // Sync existing users to Meilisearch
    const users = await User.find({}).limit(1000).lean();
    if (users.length > 0) {
      const formattedUsers = users.map(user => ({
        ...user,
        _id: undefined,
        password: undefined,
        token: undefined,
        reset_token: undefined
      }));
      await usersIndex.addDocuments(formattedUsers);
      console.log(`✅ Synced ${users.length} users to Meilisearch`);
    }

    // Sync existing companies to Meilisearch
    const companies = await Company.find({}).limit(1000).lean();
    if (companies.length > 0) {
      await companiesIndex.addDocuments(companies);
      console.log(`✅ Synced ${companies.length} companies to Meilisearch`);
    }

  } catch (error) {
    console.error("❌ Error initializing Meilisearch indexes:", error);
  }
};

const updateUserInSearchIndex = async (user) => {
  if (!meiliClient) return;
  
  try {
    const usersIndex = meiliClient.index('users');
    const userData = {
      id: user.id,
      username: user.username,
      email: user.email,
      phone: user.phone,
      account_type: user.account_type,
      personal: user.personal,
      occupations: user.occupations,
      created_at: user.created_at
    };
    
    await usersIndex.addDocuments([userData]);
  } catch (error) {
    console.error("❌ Error updating user in search index:", error);
  }
};

const updateCompanyInSearchIndex = async (company) => {
  if (!meiliClient) return;
  
  try {
    const companiesIndex = meiliClient.index('companies');
    await companiesIndex.addDocuments([company.toObject()]);
  } catch (error) {
    console.error("❌ Error updating company in search index:", error);
  }
};

const deleteFromSearchIndex = async (indexName, documentId) => {
  if (!meiliClient) return;
  
  try {
    const index = meiliClient.index(indexName);
    await index.deleteDocument(documentId);
  } catch (error) {
    console.error(`❌ Error deleting from ${indexName} index:`, error);
  }
};

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

    // Add to search index
    await updateUserInSearchIndex(user);

    logApiCall(endpoint, req.body, id, true, "Signup");
    res.json({ message: "Signup successful", token: user.token });

  } catch (e) {
    logApiCall(endpoint, req.body, null, false, "Error: " + e.message);
    res.json({ error: "Signup failed: " + e.message });
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

// ------------------------- SEARCH ENDPOINTS -------------------------
// Search Users with Meilisearch
app.post("/search/users", async (req, res) => {
  try {
    const { 
      query = "", 
      filters = {}, 
      limit = 20, 
      offset = 0,
      sort_by = "created_at:desc"
    } = req.body;

    const { token, device_id } = req.body;
    
    // Optional authentication - remove if you want public search
    if (token && device_id) {
      const auth = await authMiddleware(token, device_id);
      if (auth.error) return res.json({ error: auth.error });
    }

    if (!meiliClient) {
      // Fallback to MongoDB search if Meilisearch is not available
      const searchConditions = [];
      
      if (query) {
        searchConditions.push(
          { username: new RegExp(query, "i") },
          { email: new RegExp(query, "i") },
          { phone: new RegExp(query, "i") },
          { "personal.address": new RegExp(query, "i") },
          { "personal.state_of_origin": new RegExp(query, "i") },
          { "occupations.self_employed.name": new RegExp(query, "i") },
          { "occupations.employed.company": new RegExp(query, "i") }
        );
      }

      const mongoQuery = searchConditions.length > 0 ? { $or: searchConditions } : {};
      
      // Apply filters
      if (filters.account_type) mongoQuery.account_type = filters.account_type;
      if (filters.state) mongoQuery["personal.state_of_origin"] = filters.state;
      if (filters.gender) mongoQuery["personal.gender"] = filters.gender;

      const users = await User.find(mongoQuery)
        .select("id username email phone account_type personal.family personal.address personal.state_of_origin occupations created_at")
        .skip(offset)
        .limit(limit)
        .sort({ created_at: -1 })
        .lean();

      const total = await User.countDocuments(mongoQuery);

      return res.json({
        success: true,
        results: users,
        pagination: {
          total,
          limit,
          offset,
          has_more: offset + users.length < total
        },
        source: "mongodb_fallback"
      });
    }

    // Use Meilisearch for search
    const usersIndex = meiliClient.index('users');
    
    const searchParams = {
      limit,
      offset,
      sort: [sort_by]
    };

    // Add filters if provided
    const filterConditions = [];
    if (filters.account_type) filterConditions.push(`account_type = "${filters.account_type}"`);
    if (filters.state) filterConditions.push(`personal.state_of_origin = "${filters.state}"`);
    if (filters.gender) filterConditions.push(`personal.gender = "${filters.gender}"`);
    
    if (filterConditions.length > 0) {
      searchParams.filter = filterConditions;
    }

    const searchResults = await usersIndex.search(query, searchParams);

    res.json({
      success: true,
      results: searchResults.hits,
      pagination: {
        total: searchResults.estimatedTotalHits,
        limit,
        offset,
        has_more: offset + searchResults.hits.length < searchResults.estimatedTotalHits
      },
      processing_time_ms: searchResults.processingTimeMs,
      source: "meilisearch"
    });

  } catch (error) {
    console.error("❌ Search users error:", error);
    res.status(500).json({ error: "Search failed", details: error.message });
  }
});

// Search Companies with Meilisearch
app.post("/search/companies", async (req, res) => {
  try {
    const { 
      query = "", 
      filters = {}, 
      limit = 20, 
      offset = 0,
      sort_by = "created_at:desc"
    } = req.body;

    const { token, device_id } = req.body;
    
    // Optional authentication
    if (token && device_id) {
      const auth = await authMiddleware(token, device_id);
      if (auth.error) return res.json({ error: auth.error });
    }

    if (!meiliClient) {
      // Fallback to MongoDB search
      const searchConditions = [];
      
      if (query) {
        searchConditions.push(
          { name: new RegExp(query, "i") },
          { description: new RegExp(query, "i") },
          { industry: new RegExp(query, "i") },
          { address: new RegExp(query, "i") },
          { city: new RegExp(query, "i") },
          { state: new RegExp(query, "i") },
          { "products_services.name": new RegExp(query, "i") }
        );
      }

      const mongoQuery = searchConditions.length > 0 ? { $or: searchConditions } : {};
      
      // Apply filters
      if (filters.industry) mongoQuery.industry = filters.industry;
      if (filters.state) mongoQuery.state = filters.state;
      if (filters.country) mongoQuery.country = filters.country;
      if (filters.company_type) mongoQuery.company_type = filters.company_type;
      if (filters.size) mongoQuery.size = filters.size;
      if (filters.status) mongoQuery.status = filters.status;

      const companies = await Company.find(mongoQuery)
        .select("id name description email phone address city state country industry company_type size status website social_media products_services created_at")
        .skip(offset)
        .limit(limit)
        .sort({ created_at: -1 })
        .lean();

      const total = await Company.countDocuments(mongoQuery);

      return res.json({
        success: true,
        results: companies,
        pagination: {
          total,
          limit,
          offset,
          has_more: offset + companies.length < total
        },
        source: "mongodb_fallback"
      });
    }

    // Use Meilisearch for search
    const companiesIndex = meiliClient.index('companies');
    
    const searchParams = {
      limit,
      offset,
      sort: [sort_by]
    };

    // Add filters if provided
    const filterConditions = [];
    if (filters.industry) filterConditions.push(`industry = "${filters.industry}"`);
    if (filters.state) filterConditions.push(`state = "${filters.state}"`);
    if (filters.country) filterConditions.push(`country = "${filters.country}"`);
    if (filters.company_type) filterConditions.push(`company_type = "${filters.company_type}"`);
    if (filters.size) filterConditions.push(`size = "${filters.size}"`);
    if (filters.status) filterConditions.push(`status = "${filters.status}"`);
    
    if (filterConditions.length > 0) {
      searchParams.filter = filterConditions;
    }

    const searchResults = await companiesIndex.search(query, searchParams);

    res.json({
      success: true,
      results: searchResults.hits,
      pagination: {
        total: searchResults.estimatedTotalHits,
        limit,
        offset,
        has_more: offset + searchResults.hits.length < searchResults.estimatedTotalHits
      },
      processing_time_ms: searchResults.processingTimeMs,
      source: "meilisearch"
    });

  } catch (error) {
    console.error("❌ Search companies error:", error);
    res.status(500).json({ error: "Search failed", details: error.message });
  }
});

// Combined search (both users and companies)
app.post("/search/all", async (req, res) => {
  try {
    const { query = "", limit = 10 } = req.body;

    const { token, device_id } = req.body;
    
    // Optional authentication
    if (token && device_id) {
      const auth = await authMiddleware(token, device_id);
      if (auth.error) return res.json({ error: auth.error });
    }

    const [usersResults, companiesResults] = await Promise.all([
      User.find({
        $or: [
          { username: new RegExp(query, "i") },
          { email: new RegExp(query, "i") },
          { "personal.address": new RegExp(query, "i") },
          { "personal.state_of_origin": new RegExp(query, "i") }
        ]
      })
      .select("id username email account_type personal.address personal.state_of_origin")
      .limit(limit)
      .lean(),
      
      Company.find({
        $or: [
          { name: new RegExp(query, "i") },
          { description: new RegExp(query, "i") },
          { industry: new RegExp(query, "i") },
          { address: new RegExp(query, "i") },
          { state: new RegExp(query, "i") }
        ]
      })
      .select("id name description industry address state country")
      .limit(limit)
      .lean()
    ]);

    res.json({
      success: true,
      users: usersResults,
      companies: companiesResults,
      total: usersResults.length + companiesResults.length
    });

  } catch (error) {
    console.error("❌ Combined search error:", error);
    res.status(500).json({ error: "Search failed", details: error.message });
  }
});

// ------------------------- COMPANY ENDPOINTS -------------------------
// Create Company
app.post("/companies/create", async (req, res) => {
  try {
    const { token, device_id, ...companyData } = req.body;

    const auth = await authMiddleware(token, device_id);
    if (auth.error) return res.json({ error: auth.error });

    // Check if user is organization type
    if (auth.user.account_type !== "organization") {
      return res.json({ error: "Only organization accounts can create companies" });
    }

    const company = await new Company({
      ...companyData,
      owner_id: auth.user.id,
      id: uuidv4()
    }).save();

    // Add to search index
    await updateCompanyInSearchIndex(company);

    res.json({
      success: true,
      message: "Company created successfully",
      company
    });

  } catch (error) {
    console.error("❌ Create company error:", error);
    res.status(500).json({ error: "Failed to create company", details: error.message });
  }
});

// Update Company
app.put("/companies/:id", async (req, res) => {
  try {
    const { token, device_id, ...updateData } = req.body;
    const companyId = req.params.id;

    const auth = await authMiddleware(token, device_id);
    if (auth.error) return res.json({ error: auth.error });

    const company = await Company.findOne({ id: companyId });
    if (!company) return res.json({ error: "Company not found" });

    // Check ownership
    if (company.owner_id !== auth.user.id) {
      return res.json({ error: "You don't have permission to update this company" });
    }

    Object.assign(company, updateData, { updated_at: Date.now() });
    await company.save();

    // Update search index
    await updateCompanyInSearchIndex(company);

    res.json({
      success: true,
      message: "Company updated successfully",
      company
    });

  } catch (error) {
    console.error("❌ Update company error:", error);
    res.status(500).json({ error: "Failed to update company", details: error.message });
  }
});

// Get Company by ID
app.post("/companies/:id", async (req, res) => {
  try {
    const { token, device_id } = req.body;
    const companyId = req.params.id;

    const auth = await authMiddleware(token, device_id);
    if (auth.error) return res.json({ error: auth.error });

    const company = await Company.findOne({ id: companyId });
    if (!company) return res.json({ error: "Company not found" });

    res.json({
      success: true,
      company
    });

  } catch (error) {
    console.error("❌ Get company error:", error);
    res.status(500).json({ error: "Failed to get company", details: error.message });
  }
});

// List User's Companies
app.post("/companies/my", async (req, res) => {
  try {
    const { token, device_id, limit = 20, offset = 0 } = req.body;

    const auth = await authMiddleware(token, device_id);
    if (auth.error) return res.json({ error: auth.error });

    const companies = await Company.find({ owner_id: auth.user.id })
      .skip(offset)
      .limit(limit)
      .sort({ created_at: -1 })
      .lean();

    const total = await Company.countDocuments({ owner_id: auth.user.id });

    res.json({
      success: true,
      companies,
      pagination: {
        total,
        limit,
        offset,
        has_more: offset + companies.length < total
      }
    });

  } catch (error) {
    console.error("❌ List companies error:", error);
    res.status(500).json({ error: "Failed to list companies", details: error.message });
  }
});

// Delete Company
app.delete("/companies/:id", async (req, res) => {
  try {
    const { token, device_id } = req.body;
    const companyId = req.params.id;

    const auth = await authMiddleware(token, device_id);
    if (auth.error) return res.json({ error: auth.error });

    const company = await Company.findOne({ id: companyId });
    if (!company) return res.json({ error: "Company not found" });

    // Check ownership
    if (company.owner_id !== auth.user.id) {
      return res.json({ error: "You don't have permission to delete this company" });
    }

    await company.deleteOne();
    
    // Remove from search index
    await deleteFromSearchIndex('companies', companyId);

    res.json({
      success: true,
      message: "Company deleted successfully"
    });

  } catch (error) {
    console.error("❌ Delete company error:", error);
    res.status(500).json({ error: "Failed to delete company", details: error.message });
  }
});

// ------------------------- ME ENDPOINTS -------------------------
const sanitizeUser = (user) => {
  const { password, ...safe } = user.toObject();
  return safe;
};

app.post("/me/basic", async (req, res) => {
  const { token, device_id, password } = req.body;

  const auth = await authMiddleware(token, device_id, password);
  if (auth.error) return res.json({ error: auth.error });

  res.json({
    success: true,
    user: sanitizeUser(auth.user)
  });
});

app.post("/me/private", async (req, res) => {
  const { token, device_id, password } = req.body;

  const auth = await authMiddleware(token, device_id, password);
  if (auth.error) return res.json({ error: auth.error });

  res.json({
    success: true,
    user: auth.user.toObject()
  });
});

app.post("/me/public", async (req, res) => {
  const { username } = req.body;
  if (!username) return res.json({ error: "Username required" });

  const user = await User.findOne({ username });
  if (!user) return res.json({ error: "User not found" });

  const u = user.toObject();

  const filterByVisibility = (obj) =>
    obj && obj.visibility === "public" ? obj : undefined;

  res.json({
    success: true,
    user: {
      id: u.id,
      username: u.username,
      account_type: u.account_type,
      created_at: u.created_at,

      personal: filterByVisibility(u.personal),
      family: filterByVisibility(u.family),

      education: {
        schools: u.education?.schools?.filter(s => s.visibility === "public"),
        certificates: u.education?.certificates?.filter(c => c.visibility === "public")
      },

      occupations: {
        self_employed: u.occupations?.self_employed?.filter(o => o.visibility === "public"),
        job_seeker: u.occupations?.job_seeker?.filter(o => o.visibility === "public"),
        employed: u.occupations?.employed?.filter(o => o.visibility === "public")
      },

      properties: u.properties?.filter(p => p.visibility === "public"),
      media: u.media?.filter(m => m.visibility === "public")
    }
  });
});

// ---------------- UPDATE PROFILE ----------------
const ZONES = ["personal","family","education","occupations","properties","media","merits","demerits","phone","email"];
const BLOCK = ["password","token","token_expiry","login_attempts","account_type","id","_id","device_id","created_at"];
const ok = p => !BLOCK.some(b => p==b||p.startsWith(b+".")) && ZONES.some(z => p==z||p.startsWith(z+"."));

app.post("/update-profile", async (req, res) => {
  const { token, device_id, update } = req.body;
  const auth = await authMiddleware(token, device_id);
  if (auth.error) return res.json({ error: auth.error });
  if (!update || typeof update !== "object") return res.json({ error: "Invalid update" });

  let hit = false;
  for (const p in update) {
    if (ok(p)) {
      auth.user.set(p, update[p]);
      hit = true;
    }
  }
  if (!hit) return res.json({ error: "No valid fields" });

  auth.user.updated_at = Date.now();
  await auth.user.save();

  // Update search index
  await updateUserInSearchIndex(auth.user);

  res.json({ success: true, user: sanitizeUser(auth.user) });
});

// ------------------------- SYNC ENDPOINTS -------------------------
// Manual sync for Meilisearch (admin endpoint)
app.post("/sync/search-index", async (req, res) => {
  try {
    const { token, device_id, type = "all" } = req.body;

    const auth = await authMiddleware(token, device_id);
    if (auth.error) return res.json({ error: auth.error });

    // Simple admin check (you might want to implement proper admin authentication)
    if (auth.user.account_type !== "organization") {
      return res.json({ error: "Only organization accounts can sync search index" });
    }

    let results = {};

    if (type === "users" || type === "all") {
      const users = await User.find({}).limit(5000).lean();
      if (meiliClient && users.length > 0) {
        const formattedUsers = users.map(user => ({
          id: user.id,
          username: user.username,
          email: user.email,
          phone: user.phone,
          account_type: user.account_type,
          personal: user.personal,
          occupations: user.occupations,
          created_at: user.created_at
        }));
        
        await meiliClient.index('users').addDocuments(formattedUsers);
        results.users = { synced: users.length };
      }
    }

    if (type === "companies" || type === "all") {
      const companies = await Company.find({}).limit(5000).lean();
      if (meiliClient && companies.length > 0) {
        await meiliClient.index('companies').addDocuments(companies);
        results.companies = { synced: companies.length };
      }
    }

    res.json({
      success: true,
      message: "Search index sync completed",
      results
    });

  } catch (error) {
    console.error("❌ Sync search index error:", error);
    res.status(500).json({ error: "Sync failed", details: error.message });
  }
});

// Health check endpoint
app.get("/health", (req, res) => {
  const health = {
    status: "healthy",
    timestamp: new Date().toISOString(),
    services: {
      mongodb: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
      meilisearch: meiliClient ? "connected" : "disconnected",
      server: "running"
    }
  };
  res.json(health);
});

// ------------------------- SERVER -------------------------
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, async () => {
  console.log(`🚀 Backend running on port ${PORT}`);
  
  // Initialize Meilisearch indexes after server starts
  setTimeout(() => {
    initMeiliSearchIndexes();
  }, 3000); // Wait 3 seconds for server to fully start
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});
