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

    const { data: usuarioInterno, error: usuarioError } = await supabaseAdmin
      .from("cadastro_user")
      .select("id, situacao")
      .eq("id", data.user.id)
      .maybeSingle();

    if (usuarioError) {
      console.error("requireAuth cadastro_user error:", usuarioError);
      return res.status(500).json({ ok: false, error: "Erro interno no auth" });
    }

    const situacao = String(usuarioInterno?.situacao || "")
      .trim()
      .toLowerCase();

    if (usuarioInterno && situacao !== "ativo") {
      return res.status(403).json({
        ok: false,
        error: "Usuário inativo",
      });
    }

    req.authUser = data.user;
    req.usuarioInterno = usuarioInterno;
    next();
  } catch (err) {
    console.error("requireAuth error:", err);
    return res.status(500).json({ error: "Erro interno no auth" });
  }
}
