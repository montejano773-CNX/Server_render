import { supabaseAdmin } from "../supabaseAdmin.js";
import { limitAuthenticatedUser } from "./requestLimits.js";

export async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;

    if (!token) {
      return res.status(401).json({
        ok: false,
        error: "Sessão inválida ou expirada. Faça login novamente.",
      });
    }

    const { data, error } = await supabaseAdmin.auth.getUser(token);

    if (error || !data?.user) {
      return res.status(401).json({
        ok: false,
        error: "Sessão inválida ou expirada. Faça login novamente.",
      });
    }

    const { data: usuarioInterno, error: usuarioError } = await supabaseAdmin
      .from("cadastro_user")
      .select("id, situacao")
      .eq("id", data.user.id)
      .maybeSingle();

    if (usuarioError) {
      console.error("requireAuth cadastro_user error:", usuarioError);
      return res.status(500).json({
        ok: false,
        error: "Erro interno. Tente novamente em instantes.",
      });
    }

    if (!usuarioInterno) {
      return res.status(403).json({
        ok: false,
        error: "Você não tem permissão para acessar o sistema.",
      });
    }

    const situacao = String(usuarioInterno?.situacao || "")
      .trim()
      .toLowerCase();

    if (situacao !== "ativo") {
      return res.status(403).json({
        ok: false,
        error: "Seu acesso está inativo. Fale com o administrador.",
      });
    }

    req.authUser = data.user;
    req.usuarioInterno = usuarioInterno;
    return limitAuthenticatedUser(req, res, next);
  } catch (err) {
    console.error("requireAuth error:", err);
    return res.status(500).json({
      ok: false,
      error: "Erro interno. Tente novamente em instantes.",
    });
  }
}
