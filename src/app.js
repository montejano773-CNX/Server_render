import "dotenv/config";
import express from "express";
import cors from "cors";
import { requireAuth } from "./middlewares/auth.js";

const app = express();

app.use(
  cors({
    origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(",") : "*",
    credentials: true,
  }),
);

app.use(express.json());

app.get("/health", (req, res) => {
  res.json({ ok: true, name: "CNX API", time: new Date().toISOString() });
});

app.get("/me", requireAuth, (req, res) => {
  res.json({
    auth_user_id: req.authUser.id,
    email: req.authUser.email,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ API rodando na porta ${PORT}`));
