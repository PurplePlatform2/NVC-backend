import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 🟦 SIMPLE IN-MEMORY DATABASE (replace with MongoDB or MySQL)
let users = [];

/*
 users = [
   {
     id: "uuid",
     email: "test@example.com",
     password: "hashed password",
     account_type: "individual" | "organization",
     token: "long-lived-token",
     token_expiry: 1733309200000  (timestamp)
   }
 ]
*/

// 🔒 TOKEN VALIDITY
const TOKEN_LIFETIME = 7 * 24 * 60 * 60 * 1000; // 1 week

// ------------------------------------------------------------
// SIGNUP
// ------------------------------------------------------------
app.post("/signup", async (req, res) => {
  const { email, password, account_type } = req.body;

  if (!email || !password || !account_type) {
    return res.json({ error: "Missing fields" });
  }

  const existing = users.find(u => u.email === email);
  if (existing) {
    return res.json({ error: "Email already exists" });
  }

  const hashed = await bcrypt.hash(password, 10);

  const token = uuidv4() + uuidv4() + uuidv4(); 
  const expiry = Date.now() + TOKEN_LIFETIME;

  const user = {
    id: uuidv4(),
    email,
    password: hashed,
    account_type,
    token,
    token_expiry: expiry
  };

  users.push(user);

  // ⬅️ FRONTEND WILL OBFUSCATE THIS TOKEN
  res.json({
    message: "Signup successful",
    token,
    expiry
  });
});

// ------------------------------------------------------------
// LOGIN (email + password → returns same long-lived token)
// ------------------------------------------------------------
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) return res.json({ error: "Invalid login" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.json({ error: "Invalid login" });

  // Refresh token expiry
  user.token_expiry = Date.now() + TOKEN_LIFETIME;

  res.json({
    message: "Login successful",
    token: user.token,
    expiry: user.token_expiry,
    account_type: user.account_type
  });
});

// ------------------------------------------------------------
// TOKEN LOGIN (frontend decodes → sends raw token here)
// ------------------------------------------------------------
app.post("/token-login", (req, res) => {
  const { token } = req.body;

  if (!token) return res.json({ error: "Token required" });

  const user = users.find(u => u.token === token);
  if (!user) return res.json({ error: "Invalid token" });

  if (Date.now() > user.token_expiry) {
    return res.json({ error: "Token expired" });
  }

  res.json({
    message: "Token login successful",
    user: {
      id: user.id,
      email: user.email,
      account_type: user.account_type
    }
  });
});

// ------------------------------------------------------------
// PROTECTED DATA EXAMPLE
// ------------------------------------------------------------
app.post("/me", (req, res) => {
  const { token } = req.body;

  const user = users.find(u => u.token === token);
  if (!user) return res.json({ error: "Invalid token" });
  if (Date.now() > user.token_expiry) {
    return res.json({ error: "Token expired" });
  }

  res.json({
    id: user.id,
    email: user.email,
    account_type: user.account_type
  });
});

app.listen(3000, () => console.log("Backend running on port 3000"));
