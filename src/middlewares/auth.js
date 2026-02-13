import { supabaseAdmin } from "../supabaseAdmin.js";

export async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;

    if (!token) {
      return res.status(401).json({ error: "Token ausente" });
    }

    const { data, error } = await supabaseAdmin.auth.getUser(token);

    if (error || !data?.user) {
      return res.status(401).json({ error: "Token inválido" });
    }

    req.authUser = data.user;
    next();
  } catch (err) {
    console.error("requireAuth error:", err);
    return res.status(500).json({ error: "Erro interno no auth" });
  }
}
