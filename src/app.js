import "dotenv/config";
import express from "express";
import cors from "cors";
import { requireAuth } from "./middlewares/auth.js";
import { supabaseAdmin } from "./supabaseAdmin.js";

const allowedOrigins = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      // permite ferramentas como curl/postman
      if (!origin) return callback(null, true);

      if (allowedOrigins.length === 0) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error(`CORS bloqueado para: ${origin}`));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false, // 👈 ESSENCIAL
  }),
);

app.options("*", cors());

// ==================================================
// HEALTH
// ==================================================
app.get("/health", (req, res) => {
  res.json({ ok: true, name: "CNX API", time: new Date().toISOString() });
});

// ==================================================
// /me (perfil completo)
// - usa o auth.user.id para buscar em public.cadastro_user
// ==================================================
app.get("/me", requireAuth, async (req, res) => {
  try {
    const authId = req.authUser.id;

    const { data, error } = await supabaseAdmin
      .from("cadastro_user")
      .select("id, nome, email, nivel_acesso, situacao")
      .eq("id", authId)
      .single();

    if (error) {
      console.error("GET /me error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao carregar perfil" });
    }

    return res.json({ ok: true, data });
  } catch (err) {
    console.error("GET /me exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// ==================================================
// FUNCIONÁRIOS
// Tabela: public.cadastro_func
// ==================================================
app.get("/funcionarios", requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("cadastro_func")
      .select("id, nome, apelido, funcao, cpf, situacao")
      .order("nome", { ascending: true });

    if (error) {
      console.error("GET /funcionarios error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao listar funcionários" });
    }

    return res.json({ ok: true, data: data || [] });
  } catch (err) {
    console.error("GET /funcionarios exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.post("/funcionarios", requireAuth, async (req, res) => {
  try {
    const payload = {
      nome: (req.body?.nome || "").trim(),
      apelido: req.body?.apelido?.trim?.() || null,
      funcao: req.body?.funcao?.trim?.() || null,
      cpf: req.body?.cpf ? String(req.body.cpf).replace(/\D/g, "") : null,
      situacao: (req.body?.situacao || "ativo").toLowerCase(),
      razao_social: req.body?.razao_social?.trim?.() || null,
      titular_conta: req.body?.titular_conta?.trim?.() || null,
      banco: req.body?.banco?.trim?.() || null,
      agencia: req.body?.agencia?.trim?.() || null,
      conta: req.body?.conta?.trim?.() || null,
      chave_pix: req.body?.chave_pix?.trim?.() || null,
      observaco: req.body?.observaco?.trim?.() || null,
    };

    if (!payload.nome) {
      return res
        .status(400)
        .json({ ok: false, error: "Informe o nome do funcionário" });
    }

    const { data, error } = await supabaseAdmin
      .from("cadastro_func")
      .insert(payload)
      .select("id")
      .single();

    if (error) {
      console.error("POST /funcionarios error:", error);
      return res.status(500).json({ ok: false, error: error.message });
    }

    return res.status(201).json({ ok: true, data });
  } catch (err) {
    console.error("POST /funcionarios exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// ==================================================
// OBRAS
// Tabela: public.cadastro_obra
// Regra: usuário só vê as obras vinculadas a ele
// 👉 filtro por responsavel == req.authUser.id
// ==================================================
app.get("/obras", requireAuth, async (req, res) => {
  try {
    const authId = req.authUser.id;

    const { data, error } = await supabaseAdmin
      .from("cadastro_obra")
      .select("id, nome, cidade, uf, situacao, responsavel")
      .eq("responsavel", authId)
      .order("nome", { ascending: true });

    if (error) {
      console.error("GET /obras error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao listar obras" });
    }

    return res.json({ ok: true, data: data || [] });
  } catch (err) {
    console.error("GET /obras exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.post("/obras", requireAuth, async (req, res) => {
  try {
    const authId = req.authUser.id;

    const payload = {
      nome: (req.body?.nome || "").trim(),
      cidade: req.body?.cidade?.trim?.() || null,
      uf: req.body?.uf || null,
      situacao: req.body?.situacao || "ativo",

      // ✅ trava o vínculo pro filtro “minhas obras” funcionar sempre
      responsavel: authId,

      // campos extras do form (só funcionam se existirem na tabela)
      endereco: req.body?.endereco?.trim?.() || null,
      observacao: req.body?.observacao?.trim?.() || null,
    };

    if (!payload.nome) {
      return res
        .status(400)
        .json({ ok: false, error: "Informe o nome da obra" });
    }

    const { data, error } = await supabaseAdmin
      .from("cadastro_obra")
      .insert(payload)
      .select("id")
      .single();

    if (error) {
      console.error("POST /obras error:", error);
      return res.status(500).json({ ok: false, error: "Falha ao salvar obra" });
    }

    return res.status(201).json({ ok: true, data });
  } catch (err) {
    console.error("POST /obras exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// ==================================================
// USERS (criar usuário via API)
// - cria usuário no Supabase Auth (admin)
// - grava em public.cadastro_user com id = user.id (Auth UUID)
// ==================================================
app.post("/users", requireAuth, async (req, res) => {
  try {
    const nome = (req.body?.nome || "").trim();
    const email = (req.body?.email || "").trim();
    const senha = (req.body?.senha || "").trim();
    const nivel_acesso = req.body?.nivel_acesso || "encarregado";
    const situacao = req.body?.situacao || "ativo";
    const observacao = req.body?.observacao || null;

    if (!nome)
      return res.status(400).json({ ok: false, error: "nome é obrigatório" });
    if (!email)
      return res.status(400).json({ ok: false, error: "email é obrigatório" });
    if (!senha || senha.length < 6) {
      return res.status(400).json({
        ok: false,
        error: "senha precisa ter pelo menos 6 caracteres",
      });
    }

    // 1) cria no Auth
    const { data: created, error: createErr } =
      await supabaseAdmin.auth.admin.createUser({
        email,
        password: senha,
        email_confirm: true,
      });

    if (createErr) {
      console.error("POST /users createUser error:", createErr);
      return res
        .status(409)
        .json({ ok: false, error: "Já existe um usuário com esse e-mail" });
    }

    const newAuthId = created?.user?.id;
    if (!newAuthId) {
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao criar usuário no Auth" });
    }

    // 2) grava no cadastro_user
    const row = {
      id: newAuthId, // ✅ mesmo UUID do Auth
      nome,
      email,
      nivel_acesso,
      situacao,
      observacao,
    };

    const { error: insertErr } = await supabaseAdmin
      .from("cadastro_user")
      .insert(row);

    if (insertErr) {
      console.error("POST /users insert cadastro_user error:", insertErr);

      // rollback (remove do auth)
      try {
        await supabaseAdmin.auth.admin.deleteUser(newAuthId);
      } catch (e) {
        console.warn("Rollback deleteUser failed:", e);
      }

      return res
        .status(500)
        .json({ ok: false, error: "Falha ao salvar cadastro_user" });
    }

    return res.status(201).json({ ok: true, data: { id: newAuthId } });
  } catch (err) {
    console.error("POST /users exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ API rodando na porta ${PORT}`));
