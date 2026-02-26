import "dotenv/config";
import express from "express";
import cors from "cors";
import { requireAuth } from "./middlewares/auth.js";
import { supabaseAdmin } from "./supabaseAdmin.js";

const app = express();

// ==================================================
// CORS
// ==================================================
const allowedOrigins = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      // ✅ permite file:// e curl/postman
      if (!origin || origin === "null") return callback(null, true);

      if (allowedOrigins.length === 0) return callback(null, true);

      if (allowedOrigins.includes(origin)) return callback(null, true);

      console.log("❌ CORS BLOQUEADO:", origin, "permitidos:", allowedOrigins);
      return callback(new Error(`CORS bloqueado para: ${origin}`));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false,
  }),
);

// Preflight
app.options("*", cors());

app.use(express.json());

// ==================================================
// Helpers
// ==================================================
function isUuid(v) {
  if (!v) return false;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    String(v).trim(),
  );
}
function normValorDiaria(v) {
  // aceita: null/undefined/""
  if (v === undefined || v === null || v === "") return null;

  // aceita string com vírgula (ex: "200,50")
  const s = String(v).trim().replace(",", ".");
  const n = Number(s);

  if (!Number.isFinite(n) || n < 0) return NaN;
  return n;
}
function normSituacao(v, fallback = "ativo") {
  const s = String(v || fallback)
    .toLowerCase()
    .trim();
  return s === "inativo" ? "inativo" : "ativo";
}

// --------------------------------------------------
// Enriquecimento manual (sem depender de FK)
// --------------------------------------------------
async function enrichEquipeRowsWithNames(rows) {
  const out = rows || [];
  const funcIds = [
    ...new Set(out.map((r) => r.funcionario_id).filter(Boolean)),
  ];

  if (funcIds.length === 0) {
    return out.map((r) => ({
      ...r,
      funcionario_nome: null,
      funcionario_funcao: null,
    }));
  }

  const { data: funcs, error: errF } = await supabaseAdmin
    .from("cadastro_func")
    .select("id, nome, funcao, situacao")
    .in("id", funcIds);

  if (errF) {
    console.error("enrichEquipeRowsWithNames cadastro_func error:", errF);
    return out.map((r) => ({
      ...r,
      funcionario_nome: null,
      funcionario_funcao: null,
    }));
  }

  const map = {};
  (funcs || []).forEach((f) => (map[f.id] = f));

  return out.map((r) => ({
    ...r,
    funcionario_nome: map[r.funcionario_id]?.nome || null,
    funcionario_funcao: map[r.funcionario_id]?.funcao || null,
  }));
}

async function enrichEquipeRowsWithObraNames(rows) {
  const out = rows || [];
  const obraIds = [...new Set(out.map((r) => r.obra_id).filter(Boolean))];

  if (obraIds.length === 0) {
    return out.map((r) => ({
      ...r,
      obra_nome: null,
      obra_situacao: null,
    }));
  }

  const { data: obras, error: errO } = await supabaseAdmin
    .from("cadastro_obra")
    .select("id, nome, situacao")
    .in("id", obraIds);

  if (errO) {
    console.error("enrichEquipeRowsWithObraNames cadastro_obra error:", errO);
    return out.map((r) => ({
      ...r,
      obra_nome: null,
      obra_situacao: null,
    }));
  }

  const map = {};
  (obras || []).forEach((o) => (map[o.id] = o));

  return out.map((r) => ({
    ...r,
    obra_nome: map[r.obra_id]?.nome || null,
    obra_situacao: map[r.obra_id]?.situacao || null,
  }));
}

// ==================================================
// HEALTH
// ==================================================
app.get("/health", (req, res) => {
  res.json({ ok: true, name: "CNX API", time: new Date().toISOString() });
});

// ==================================================
// /me (perfil completo)
// ✅ CORRIGIDO: usa id = auth.id (seu cadastro_user usa o uuid do Auth como id)
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
        .status(404)
        .json({ ok: false, error: "Perfil não encontrado no cadastro_user" });
    }

    return res.json({ ok: true, data });
  } catch (err) {
    console.error("GET /me exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// ==================================================
// USUÁRIOS (CRUD) - public.cadastro_user
// ==================================================

// LISTAR
app.get("/usuarios", requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("cadastro_user")
      .select("id, nome, email, nivel_acesso, situacao")
      .order("nome", { ascending: true });

    if (error) {
      console.error("GET /usuarios error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao listar usuários" });
    }

    return res.json({ ok: true, data: data || [] });
  } catch (err) {
    console.error("GET /usuarios exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// BUSCAR POR ID
app.get("/usuarios/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const { data, error } = await supabaseAdmin
      .from("cadastro_user")
      .select("id, nome, email, nivel_acesso, situacao, observacao")
      .eq("id", id)
      .single();

    if (error) {
      console.error("GET /usuarios/:id error:", error);
      return res
        .status(404)
        .json({ ok: false, error: "Usuário não encontrado" });
    }

    return res.json({ ok: true, data });
  } catch (err) {
    console.error("GET /usuarios/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// CRIAR (Auth + cadastro_user)
app.post("/usuarios", requireAuth, async (req, res) => {
  try {
    const nome = (req.body?.nome || "").trim();
    const email = (req.body?.email || "").trim();
    const senha = (req.body?.senha || "").trim();

    const nivel_acesso = (req.body?.nivel_acesso || "encarregado").trim();
    const situacao = normSituacao(req.body?.situacao, "ativo");
    const observacao = req.body?.observacao
      ? String(req.body.observacao).trim()
      : null;

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
      console.error("POST /usuarios createUser error:", createErr);
      return res.status(409).json({
        ok: false,
        error: "Já existe um usuário com esse e-mail",
      });
    }

    const newAuthId = created?.user?.id;
    if (!newAuthId) {
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao criar usuário no Auth" });
    }

    // 2) grava no cadastro_user (id = auth uuid)
    const row = {
      id: newAuthId,
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
      console.error("POST /usuarios insert cadastro_user error:", insertErr);

      // rollback
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
    console.error("POST /usuarios exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// EDITAR (PATCH)
app.patch("/usuarios/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const patch = {
      ...(req.body?.nome !== undefined
        ? { nome: String(req.body.nome).trim() }
        : {}),
      ...(req.body?.nivel_acesso !== undefined
        ? { nivel_acesso: String(req.body.nivel_acesso).trim() }
        : {}),
      ...(req.body?.situacao !== undefined
        ? { situacao: normSituacao(req.body.situacao) }
        : {}),
      ...(req.body?.observacao !== undefined
        ? {
            observacao: req.body.observacao
              ? String(req.body.observacao).trim()
              : null,
          }
        : {}),
    };

    const novoEmail =
      req.body?.email !== undefined
        ? String(req.body.email || "").trim()
        : null;

    const novaSenha =
      req.body?.senha !== undefined
        ? String(req.body.senha || "").trim()
        : null;

    if (novoEmail) patch.email = novoEmail;

    if (Object.keys(patch).length > 0) {
      const { error: upErr } = await supabaseAdmin
        .from("cadastro_user")
        .update(patch)
        .eq("id", id);

      if (upErr) {
        console.error("PATCH /usuarios/:id update cadastro_user error:", upErr);
        return res
          .status(500)
          .json({ ok: false, error: "Falha ao atualizar usuário" });
      }
    }

    if (novoEmail || novaSenha) {
      const payloadAuth = {};
      if (novoEmail) payloadAuth.email = novoEmail;
      if (novaSenha) {
        if (novaSenha.length < 6) {
          return res.status(400).json({
            ok: false,
            error: "senha precisa ter pelo menos 6 caracteres",
          });
        }
        payloadAuth.password = novaSenha;
      }

      const { error: authErr } = await supabaseAdmin.auth.admin.updateUserById(
        id,
        payloadAuth,
      );

      if (authErr) {
        console.error("PATCH /usuarios/:id update Auth error:", authErr);
        return res.status(200).json({
          ok: true,
          warning: "Atualizou cadastro_user, mas falhou ao atualizar Auth",
        });
      }
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("PATCH /usuarios/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// DELETAR
app.delete("/usuarios/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const { error: delRowErr } = await supabaseAdmin
      .from("cadastro_user")
      .delete()
      .eq("id", id);

    if (delRowErr) {
      console.error(
        "DELETE /usuarios/:id delete cadastro_user error:",
        delRowErr,
      );
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao deletar cadastro_user" });
    }

    const { error: delAuthErr } = await supabaseAdmin.auth.admin.deleteUser(id);

    if (delAuthErr) {
      console.error("DELETE /usuarios/:id delete Auth error:", delAuthErr);
      return res.status(200).json({
        ok: true,
        warning: "Deletou cadastro_user, mas falhou ao deletar no Auth",
      });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /usuarios/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// ==================================================
// RELATÓRIOS
// GET /relatorios/pagamento?inicio=YYYY-MM-DD&fim=YYYY-MM-DD
// ==================================================
app.get("/relatorios/pagamento", requireAuth, async (req, res) => {
  try {
    const inicio = String(req.query?.inicio || "").trim();
    const fim = String(req.query?.fim || "").trim();

    if (!inicio || !fim) {
      return res.status(400).json({
        ok: false,
        error: "Informe inicio e fim no formato YYYY-MM-DD",
      });
    }

    // 1) Funcionários
    const { data: funcionarios, error: errFunc } = await supabaseAdmin
      .from("cadastro_func")
      .select(
        "id, nome, apelido, funcao, razao_social, titular_conta, cpf, banco, agencia, conta, chave_pix, situacao",
      )
      .order("nome", { ascending: true });

    if (errFunc) {
      console.error("GET /relatorios/pagamento funcionarios error:", errFunc);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao listar funcionários" });
    }

    const funcList = funcionarios || [];
    const funcIds = funcList.map((f) => f.id);

    if (funcIds.length === 0) return res.json({ ok: true, data: [] });

    // 2) Diárias no período (lanc_diarias)
    const { data: diarias, error: errDiarias } = await supabaseAdmin
      .from("lanc_diarias")
      .select("funcionario_id, data, qtd, valor_diaria_aplicado")
      .in("funcionario_id", funcIds)
      .gte("data", inicio)
      .lte("data", fim);

    if (errDiarias) {
      console.error("GET /relatorios/pagamento diarias error:", errDiarias);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao buscar diárias" });
    }

    // 3) Empreitas no período (empreitas)
    const { data: empreitas, error: errEmp } = await supabaseAdmin
      .from("empreitas")
      .select("funcionario_id, data_pagamento, valor")
      .in("funcionario_id", funcIds)
      .gte("data_pagamento", inicio)
      .lte("data_pagamento", fim);

    if (errEmp) {
      console.error("GET /relatorios/pagamento empreitas error:", errEmp);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao buscar empreitas" });
    }
    // 3.5) Ajustes no período (lanc_diarias_ajustes)
    // OBS: aqui usamos data_inicio como "data do lançamento do período"
    const { data: ajustesRows, error: errAj } = await supabaseAdmin
      .from("lanc_diarias_ajustes")
      .select("funcionario_id, data_inicio, reembolso, adiantamento")
      .in("funcionario_id", funcIds)
      .gte("data_inicio", inicio)
      .lte("data_inicio", fim);

    if (errAj) {
      console.error("GET /relatorios/pagamento ajustes error:", errAj);
      return res.status(500).json({
        ok: false,
        error: "Falha ao buscar ajustes (reembolso/adiantamento)",
      });
    }
    const map = new Map();

    function ensure(funcId) {
      if (!map.has(funcId)) {
        map.set(funcId, {
          dias: {},
          total_diaria: 0,
          total_empreita: 0,
          total_reembolso: 0,
          total_adiantamento: 0,
        });
      }
      return map.get(funcId);
    }

    // Diárias
    for (const row of diarias || []) {
      const funcId = row.funcionario_id;
      const dia = row.data;
      const qtd = Number(row.qtd ?? 1);
      const v = Number(row.valor_diaria_aplicado ?? 0);
      const valorDia =
        (Number.isFinite(qtd) ? qtd : 1) * (Number.isFinite(v) ? v : 0);

      const obj = ensure(funcId);
      if (!obj.dias[dia]) obj.dias[dia] = { diaria: 0, empreita: 0 };

      obj.dias[dia].diaria += valorDia;
      obj.total_diaria += valorDia;
    }

    // Empreitas
    for (const row of empreitas || []) {
      const funcId = row.funcionario_id;
      const dia = row.data_pagamento;
      const valor = Number(row.valor ?? 0);

      const obj = ensure(funcId);
      if (!obj.dias[dia]) obj.dias[dia] = { diaria: 0, empreita: 0 };

      obj.dias[dia].empreita += valor;
      obj.total_empreita += valor;
    }
    // Ajustes (reembolso / adiantamento)
    for (const row of ajustesRows || []) {
      const funcId = row.funcionario_id;
      const reembolso = Number(row.reembolso ?? 0);
      const adiantamento = Number(row.adiantamento ?? 0);

      const obj = ensure(funcId);
      obj.total_reembolso += Number.isFinite(reembolso) ? reembolso : 0;
      obj.total_adiantamento += Number.isFinite(adiantamento)
        ? adiantamento
        : 0;
    }
    const out = funcList.map((f) => {
      const agg = ensure(f.id);

      const total_reembolso = Number(agg.total_reembolso || 0);
      const total_adiantamento = Number(agg.total_adiantamento || 0);

      const total_pagar =
        Number(agg.total_diaria || 0) +
        Number(agg.total_empreita || 0) +
        total_reembolso -
        total_adiantamento;

      return {
        funcionario: f,
        dias: agg.dias,
        total_diaria: agg.total_diaria,
        total_empreita: agg.total_empreita,
        total_reembolso,
        total_adiantamento,
        total_pagar,
      };
    });

    return res.json({ ok: true, data: out });
  } catch (err) {
    console.error("GET /relatorios/pagamento exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});
// ==================================================
// FUNCIONÁRIOS (CRUD) - public.cadastro_func
// (mantive seu campo "observacao" como estava no seu código)
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
// ==================================================
// ATUALIZAR FUNCIONÁRIO (PUT /funcionarios/:id)
// - pensado para a tela editar (envia o "form completo")
// - inclui valor_diaria
// ==================================================
app.put("/funcionarios/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    // nome é obrigatório no PUT (seu form exige)
    const nome = String(req.body?.nome || "").trim();
    if (!nome) {
      return res
        .status(400)
        .json({ ok: false, error: "Informe o nome do funcionário" });
    }

    // ✅ valor_diaria (numeric >= 0) ou null
    const vdi = normValorDiaria(req.body?.valor_diaria);
    if (Number.isNaN(vdi)) {
      return res
        .status(400)
        .json({ ok: false, error: "valor_diaria inválido" });
    }

    const payload = {
      nome,
      apelido: req.body?.apelido ? String(req.body.apelido).trim() : null,
      funcao: req.body?.funcao ? String(req.body.funcao).trim() : null,
      valor_diaria: vdi,
      cpf: req.body?.cpf ? String(req.body.cpf).replace(/\D/g, "") : null,
      situacao: normSituacao(req.body?.situacao, "ativo"),
      razao_social: req.body?.razao_social
        ? String(req.body.razao_social).trim()
        : null,
      titular_conta: req.body?.titular_conta
        ? String(req.body.titular_conta).trim()
        : null,
      banco: req.body?.banco ? String(req.body.banco).trim() : null,
      agencia: req.body?.agencia ? String(req.body.agencia).trim() : null,
      conta: req.body?.conta ? String(req.body.conta).trim() : null,
      chave_pix: req.body?.chave_pix ? String(req.body.chave_pix).trim() : null,
      observacao: req.body?.observacao
        ? String(req.body.observacao).trim()
        : null,
    };

    const { error } = await supabaseAdmin
      .from("cadastro_func")
      .update(payload)
      .eq("id", id);

    if (error) {
      console.error("PUT /funcionarios/:id error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao atualizar funcionário" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("PUT /funcionarios/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});
app.get("/funcionarios/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const { data, error } = await supabaseAdmin
      .from("cadastro_func")
      .select("*")
      .eq("id", id)
      .single();

    if (error) {
      console.error("GET /funcionarios/:id error:", error);
      return res
        .status(404)
        .json({ ok: false, error: "Funcionário não encontrado" });
    }

    return res.json({ ok: true, data });
  } catch (err) {
    console.error("GET /funcionarios/:id exception:", err);
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
      situacao: normSituacao(req.body?.situacao, "ativo"),
      razao_social: req.body?.razao_social?.trim?.() || null,
      titular_conta: req.body?.titular_conta?.trim?.() || null,
      banco: req.body?.banco?.trim?.() || null,
      agencia: req.body?.agencia?.trim?.() || null,
      conta: req.body?.conta?.trim?.() || null,
      chave_pix: req.body?.chave_pix?.trim?.() || null,
      observacao: req.body?.observacao?.trim?.() || null,
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

app.patch("/funcionarios/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const patch = {
      ...(req.body?.nome !== undefined
        ? { nome: String(req.body.nome).trim() }
        : {}),
      ...(req.body?.apelido !== undefined
        ? { apelido: req.body.apelido ? String(req.body.apelido).trim() : null }
        : {}),
      ...(req.body?.funcao !== undefined
        ? { funcao: req.body.funcao ? String(req.body.funcao).trim() : null }
        : {}),
      ...(req.body?.cpf !== undefined
        ? { cpf: req.body.cpf ? String(req.body.cpf).replace(/\D/g, "") : null }
        : {}),
      ...(req.body?.situacao !== undefined
        ? { situacao: normSituacao(req.body.situacao) }
        : {}),
      ...(req.body?.razao_social !== undefined
        ? {
            razao_social: req.body.razao_social
              ? String(req.body.razao_social).trim()
              : null,
          }
        : {}),
      ...(req.body?.titular_conta !== undefined
        ? {
            titular_conta: req.body.titular_conta
              ? String(req.body.titular_conta).trim()
              : null,
          }
        : {}),
      ...(req.body?.banco !== undefined
        ? { banco: req.body.banco ? String(req.body.banco).trim() : null }
        : {}),
      ...(req.body?.agencia !== undefined
        ? { agencia: req.body.agencia ? String(req.body.agencia).trim() : null }
        : {}),
      ...(req.body?.conta !== undefined
        ? { conta: req.body.conta ? String(req.body.conta).trim() : null }
        : {}),
      ...(req.body?.chave_pix !== undefined
        ? {
            chave_pix: req.body.chave_pix
              ? String(req.body.chave_pix).trim()
              : null,
          }
        : {}),
      ...(req.body?.observacao !== undefined
        ? {
            observacao: req.body.observacao
              ? String(req.body.observacao).trim()
              : null,
          }
        : {}),
    };

    if (Object.keys(patch).length === 0) {
      return res.status(400).json({ ok: false, error: "Nada para atualizar" });
    }

    const { error } = await supabaseAdmin
      .from("cadastro_func")
      .update(patch)
      .eq("id", id);

    if (error) {
      console.error("PATCH /funcionarios/:id error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao atualizar funcionário" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("PATCH /funcionarios/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.delete("/funcionarios/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const { error } = await supabaseAdmin
      .from("cadastro_func")
      .delete()
      .eq("id", id);

    if (error) {
      console.error("DELETE /funcionarios/:id error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao deletar funcionário" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /funcionarios/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// ==================================================
// EQUIPE POR OBRA (CRUD) - public.equipe_obra
// ==================================================

// LISTAR EQUIPE DA OBRA
// ✅ CORRIGIDO: agora devolve funcionario_nome / funcionario_funcao também
app.get("/equipe-obra", requireAuth, async (req, res) => {
  try {
    const obraId = String(req.query?.obra_id || "").trim();

    if (!isUuid(obraId)) {
      return res.status(400).json({
        ok: false,
        error: "obra_id inválido (precisa ser UUID)",
      });
    }

    const { data, error } = await supabaseAdmin
      .from("equipe_obra")
      .select("id, obra_id, funcionario_id, situacao, observacao, created_at")
      .eq("obra_id", obraId)
      .order("created_at", { ascending: true });

    if (error) {
      console.error("GET /equipe-obra error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao listar equipe" });
    }

    const enriched = await enrichEquipeRowsWithNames(data || []);
    return res.json({ ok: true, data: enriched });
  } catch (err) {
    console.error("GET /equipe-obra exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// ADICIONAR / ATUALIZAR (UPSERT MANUAL)
app.post("/equipe-obra", requireAuth, async (req, res) => {
  try {
    const obra_id = String(req.body?.obra_id || "").trim();
    const funcionario_id = String(req.body?.funcionario_id || "").trim();

    if (!isUuid(obra_id)) {
      return res
        .status(400)
        .json({ ok: false, error: "obra_id inválido (UUID)" });
    }
    if (!isUuid(funcionario_id)) {
      return res
        .status(400)
        .json({ ok: false, error: "funcionario_id inválido (UUID)" });
    }

    let valor_diaria = null;
    if (
      req.body?.valor_diaria !== undefined &&
      req.body?.valor_diaria !== null &&
      req.body?.valor_diaria !== ""
    ) {
      const n = Number(req.body.valor_diaria);
      if (Number.isNaN(n) || n < 0) {
        return res
          .status(400)
          .json({ ok: false, error: "valor_diaria inválido" });
      }
      valor_diaria = n;
    }

    const situacao = normSituacao(req.body?.situacao, "ativo");
    const observacao = req.body?.observacao
      ? String(req.body.observacao).trim()
      : null;

    const { data: existente, error: selErr } = await supabaseAdmin
      .from("equipe_obra")
      .select("id")
      .eq("obra_id", obra_id)
      .eq("funcionario_id", funcionario_id)
      .order("created_at", { ascending: false })
      .limit(1);

    if (selErr) {
      console.error("POST /equipe-obra select existente error:", selErr);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao verificar vínculo" });
    }

    if (existente && existente.length > 0) {
      const id = existente[0].id;

      const { error: upErr } = await supabaseAdmin
        .from("equipe_obra")
        .update({ situacao, observacao })
        .eq("id", id);

      if (upErr) {
        console.error("POST /equipe-obra update error:", upErr);
        return res
          .status(500)
          .json({ ok: false, error: "Falha ao atualizar vínculo" });
      }

      return res.status(200).json({ ok: true, data: { id, updated: true } });
    } else {
      const { data: ins, error: insErr } = await supabaseAdmin
        .from("equipe_obra")
        .insert({ obra_id, funcionario_id, situacao, observacao })
        .select("id")
        .single();

      if (insErr) {
        console.error("POST /equipe-obra insert error:", insErr);
        return res
          .status(500)
          .json({ ok: false, error: "Falha ao criar vínculo" });
      }

      return res.status(201).json({ ok: true, data: ins });
    }
  } catch (err) {
    console.error("POST /equipe-obra exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// REMOVER (INATIVAR)
app.delete("/equipe-obra/:id", requireAuth, async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();

    if (!isUuid(id)) {
      return res.status(400).json({ ok: false, error: "id inválido (UUID)" });
    }

    const { error } = await supabaseAdmin
      .from("equipe_obra")
      .update({ situacao: "inativo" })
      .eq("id", id);

    if (error) {
      console.error("DELETE /equipe-obra/:id error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao remover vínculo" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /equipe-obra/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// =====================================================
// DIÁRIAS - SELECT + UPSERT (lanc_diarias)
// =====================================================
app.get("/lanc-diarias", requireAuth, async (req, res) => {
  try {
    const obra_id = String(req.query?.obra_id || "").trim();
    const data_inicio = String(req.query?.data_inicio || "").trim();
    const data_fim = String(req.query?.data_fim || "").trim();

    if (!isUuid(obra_id) || !data_inicio || !data_fim) {
      return res.status(400).json({
        ok: false,
        error: "Parâmetros obrigatórios: obra_id(UUID), data_inicio, data_fim",
      });
    }

    const { data, error } = await supabaseAdmin
      .from("lanc_diarias")
      .select("obra_id, funcionario_id, data, qtd, valor_diaria_aplicado")
      .eq("obra_id", obra_id)
      .gte("data", data_inicio)
      .lte("data", data_fim);

    if (error) {
      console.error("GET /lanc-diarias error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Erro ao buscar diárias" });
    }

    return res.json({ ok: true, data: data || [] });
  } catch (e) {
    console.error("GET /lanc-diarias exception:", e);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.post("/lanc-diarias", requireAuth, async (req, res) => {
  try {
    const registros = req.body?.registros;
    if (!Array.isArray(registros) || registros.length === 0) {
      return res
        .status(400)
        .json({ ok: false, error: "Envie { registros: [...] }" });
    }

    const normalized = registros.map((r) => {
      const obra_id = String(r.obra_id || "").trim();
      const funcionario_id = String(r.funcionario_id || "").trim();
      const data = String(r.data || "").trim();

      if (!isUuid(obra_id) || !isUuid(funcionario_id) || !data) {
        throw new Error(
          "Registro inválido: obra_id/funcionario_id(UUID) e data são obrigatórios.",
        );
      }

      const qtd = Number(r.qtd);
      const vda = Number(r.valor_diaria_aplicado);

      if (!Number.isFinite(qtd)) throw new Error("qtd inválido.");
      if (!Number.isFinite(vda) || vda <= 0)
        throw new Error("valor_diaria_aplicado inválido.");

      return { obra_id, funcionario_id, data, qtd, valor_diaria_aplicado: vda };
    });

    const { error } = await supabaseAdmin
      .from("lanc_diarias")
      .upsert(normalized, { onConflict: "obra_id,funcionario_id,data" });

    if (error) {
      console.error("POST /lanc-diarias error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Erro ao salvar diárias" });
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error("POST /lanc-diarias exception:", e);
    return res
      .status(400)
      .json({ ok: false, error: e.message || "Erro ao processar diárias" });
  }
});

// =====================================================
// AJUSTES DO PERÍODO (lanc_diarias_ajustes)
// ✅ SEU SCHEMA REAL: reembolso numeric, adiantamento numeric
// ✅ COMPAT: aceita também reembolso_centavos/adiantamento_centavos e converte
// =====================================================

app.get("/diarias-ajustes", requireAuth, async (req, res) => {
  try {
    const obra_id = String(req.query?.obra_id || "").trim();
    const data_inicio = String(req.query?.data_inicio || "").trim();

    if (!isUuid(obra_id) || !data_inicio) {
      return res.status(400).json({
        ok: false,
        error: "Parâmetros obrigatórios: obra_id(UUID), data_inicio",
      });
    }

    const { data, error } = await supabaseAdmin
      .from("lanc_diarias_ajustes")
      .select("obra_id, funcionario_id, data_inicio, reembolso, adiantamento")
      .eq("obra_id", obra_id)
      .eq("data_inicio", data_inicio);

    if (error) {
      console.error("GET /diarias-ajustes error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Erro ao buscar ajustes" });
    }

    return res.json({ ok: true, data: data || [] });
  } catch (e) {
    console.error("GET /diarias-ajustes exception:", e);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.post("/diarias-ajustes", requireAuth, async (req, res) => {
  try {
    const ajustes = req.body?.ajustes;
    if (!Array.isArray(ajustes)) {
      return res
        .status(400)
        .json({ ok: false, error: "Envie { ajustes: [...] }" });
    }

    const normalized = ajustes.map((a) => {
      const obra_id = String(a.obra_id || "").trim();
      const funcionario_id = String(a.funcionario_id || "").trim();
      const data_inicio = String(a.data_inicio || "").trim();

      if (!isUuid(obra_id) || !isUuid(funcionario_id) || !data_inicio) {
        throw new Error(
          "Ajuste inválido: obra_id/funcionario_id(UUID) e data_inicio são obrigatórios.",
        );
      }

      // centavos do front
      const reembolso_centavos = Number(a.reembolso_centavos ?? 0);
      const adiantamento_centavos = Number(a.adiantamento_centavos ?? 0);

      if (!Number.isFinite(reembolso_centavos) || reembolso_centavos < 0) {
        throw new Error("reembolso_centavos inválido.");
      }
      if (
        !Number.isFinite(adiantamento_centavos) ||
        adiantamento_centavos < 0
      ) {
        throw new Error("adiantamento_centavos inválido.");
      }

      // ✅ banco: numeric (reais)
      const reembolso = reembolso_centavos / 100;
      const adiantamento = adiantamento_centavos / 100;

      // ✅ valor da diária snapshot (numeric)
      const valor = Number(a.valor ?? 0);
      if (!Number.isFinite(valor) || valor < 0) {
        throw new Error("valor (diária) inválido.");
      }

      return {
        obra_id,
        funcionario_id,
        data_inicio,
        reembolso,
        adiantamento,
        valor, // ✅ salva a diária do período
      };
    });

    const { error } = await supabaseAdmin
      .from("lanc_diarias_ajustes")
      .upsert(normalized, { onConflict: "obra_id,funcionario_id,data_inicio" });

    if (error) {
      console.error("POST /diarias-ajustes error:", error);
      return res
        .status(500)
        .json({ ok: false, error: error.message || "Erro ao salvar ajustes" });
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error("POST /diarias-ajustes exception:", e);
    return res
      .status(400)
      .json({ ok: false, error: e.message || "Erro ao processar ajustes" });
  }
});

// =====================================================
// ✅ NOVA ROTA: FUNCIONÁRIOS VINCULADOS (para extras no diarias.html)
// Formato que o front espera:
// { id, nome, funcao, valor_diaria, obra_id, obra_nome, situacao }
// =====================================================
app.get("/funcionarios-vinculados", requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("equipe_obra")
      .select("obra_id, funcionario_id, valor_diaria, situacao");

    if (error) {
      console.error("GET /funcionarios-vinculados error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Erro ao buscar vínculos" });
    }

    const withNames = await enrichEquipeRowsWithNames(data || []);
    const withObras = await enrichEquipeRowsWithObraNames(withNames);

    const out = (withObras || []).map((r) => ({
      id: r.funcionario_id,
      nome: r.funcionario_nome,
      funcao: r.funcionario_funcao,
      valor_diaria: r.valor_diaria,
      obra_id: r.obra_id,
      obra_nome: r.obra_nome,
      situacao: r.situacao,
    }));

    return res.json({ ok: true, data: out });
  } catch (e) {
    console.error("GET /funcionarios-vinculados exception:", e);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// =====================================================
// ✅ /equipe-obra/todas (CORRIGIDA)
// - antes estava quebrando por usar "supabase" inexistente
// - agora usa supabaseAdmin + requireAuth
// =====================================================
app.get("/equipe-obra/todas", requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("equipe_obra")
      .select("obra_id, funcionario_id, valor_diaria, situacao");

    if (error) {
      console.error("Erro GET /equipe-obra/todas:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Erro ao buscar equipe_obra (todas)." });
    }

    const withNames = await enrichEquipeRowsWithNames(data || []);
    const withObras = await enrichEquipeRowsWithObraNames(withNames);

    const enriched = (withObras || []).map((r) => ({
      obra_id: r.obra_id,
      funcionario_id: r.funcionario_id,
      valor_diaria: r.valor_diaria,
      situacao: r.situacao,
      obra_nome: r.obra_nome || null,
      obra_situacao: r.obra_situacao || null,
      funcionario_nome: r.funcionario_nome || null,
      funcionario_funcao: r.funcionario_funcao || null,
    }));

    return res.json({ ok: true, data: enriched });
  } catch (e) {
    console.error("Falha GET /equipe-obra/todas:", e);
    return res.status(500).json({ ok: false, error: "Erro interno." });
  }
});

// ==================================================
// EMPREITAS (CRUD) - public.empreitas
// ==================================================
app.get("/empreitas", requireAuth, async (req, res) => {
  try {
    const { inicio, fim, obra_id, funcionario_id } = req.query;

    let q = supabaseAdmin
      .from("empreitas")
      .select(
        "id, obra_id, funcionario_id, data_pagamento, valor, descricao, created_at",
      )
      .order("data_pagamento", { ascending: true })
      .order("created_at", { ascending: true });

    if (obra_id) {
      if (!isUuid(obra_id)) {
        return res
          .status(400)
          .json({ ok: false, error: "obra_id inválido (UUID)" });
      }
      q = q.eq("obra_id", obra_id);
    }

    if (funcionario_id) {
      if (!isUuid(funcionario_id)) {
        return res
          .status(400)
          .json({ ok: false, error: "funcionario_id inválido (UUID)" });
      }
      q = q.eq("funcionario_id", funcionario_id);
    }

    if (inicio) q = q.gte("data_pagamento", String(inicio));
    if (fim) q = q.lte("data_pagamento", String(fim));

    const { data, error } = await q;

    if (error) {
      console.error("GET /empreitas error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao listar empreitas" });
    }

    return res.json({ ok: true, data: data || [] });
  } catch (err) {
    console.error("GET /empreitas exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.get("/empreitas/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const { data, error } = await supabaseAdmin
      .from("empreitas")
      .select("*")
      .eq("id", id)
      .single();

    if (error) {
      console.error("GET /empreitas/:id error:", error);
      return res
        .status(404)
        .json({ ok: false, error: "Empreita não encontrada" });
    }

    return res.json({ ok: true, data });
  } catch (err) {
    console.error("GET /empreitas/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.post("/empreitas", requireAuth, async (req, res) => {
  try {
    const obra_id = req.body?.obra_id;
    const funcionario_id = req.body?.funcionario_id;
    const data_pagamento = req.body?.data_pagamento;
    const valorRaw = req.body?.valor;
    const descricao = req.body?.descricao
      ? String(req.body.descricao).trim()
      : null;

    if (!isUuid(obra_id)) {
      return res
        .status(400)
        .json({ ok: false, error: "obra_id é obrigatório (UUID)" });
    }
    if (!isUuid(funcionario_id)) {
      return res
        .status(400)
        .json({ ok: false, error: "funcionario_id é obrigatório (UUID)" });
    }
    if (!data_pagamento) {
      return res.status(400).json({
        ok: false,
        error: "data_pagamento é obrigatória (YYYY-MM-DD)",
      });
    }

    const valor = Number(valorRaw);
    if (!Number.isFinite(valor) || valor < 0) {
      return res.status(400).json({ ok: false, error: "valor inválido" });
    }

    const payload = {
      obra_id,
      funcionario_id,
      data_pagamento: String(data_pagamento),
      valor,
      descricao,
      created_by: req.authUser?.id || null,
    };

    const { data, error } = await supabaseAdmin
      .from("empreitas")
      .insert(payload)
      .select("id")
      .single();

    if (error) {
      console.error("POST /empreitas error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao salvar empreita" });
    }

    return res.status(201).json({ ok: true, data });
  } catch (err) {
    console.error("POST /empreitas exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.patch("/empreitas/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const patch = {
      ...(req.body?.obra_id !== undefined
        ? (() => {
            if (!isUuid(req.body.obra_id))
              throw new Error("obra_id inválido (UUID)");
            return { obra_id: req.body.obra_id };
          })()
        : {}),
      ...(req.body?.funcionario_id !== undefined
        ? (() => {
            if (!isUuid(req.body.funcionario_id))
              throw new Error("funcionario_id inválido (UUID)");
            return { funcionario_id: req.body.funcionario_id };
          })()
        : {}),
      ...(req.body?.data_pagamento !== undefined
        ? { data_pagamento: String(req.body.data_pagamento) }
        : {}),
      ...(req.body?.valor !== undefined
        ? (() => {
            const v = Number(req.body.valor);
            if (!Number.isFinite(v) || v < 0) throw new Error("valor inválido");
            return { valor: v };
          })()
        : {}),
      ...(req.body?.descricao !== undefined
        ? {
            descricao: req.body.descricao
              ? String(req.body.descricao).trim()
              : null,
          }
        : {}),
    };

    if (Object.keys(patch).length === 0) {
      return res.status(400).json({ ok: false, error: "Nada para atualizar" });
    }

    const { error } = await supabaseAdmin
      .from("empreitas")
      .update(patch)
      .eq("id", id);

    if (error) {
      console.error("PATCH /empreitas/:id error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao atualizar empreita" });
    }

    return res.json({ ok: true });
  } catch (err) {
    const msg = String(err?.message || "");
    if (msg.includes("inválido"))
      return res.status(400).json({ ok: false, error: msg });
    console.error("PATCH /empreitas/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.delete("/empreitas/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const { error } = await supabaseAdmin
      .from("empreitas")
      .delete()
      .eq("id", id);

    if (error) {
      console.error("DELETE /empreitas/:id error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao deletar empreita" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /empreitas/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// ==================================================
// OBRAS (CRUD) - public.cadastro_obra
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

app.get("/obras/todas", requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("cadastro_obra")
      .select("id, nome, cidade, uf, situacao, responsavel")
      .order("nome", { ascending: true });

    if (error) {
      console.error("GET /obras/todas error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao listar obras (todas)" });
    }

    return res.json({ ok: true, data: data || [] });
  } catch (err) {
    console.error("GET /obras/todas exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.get("/obras/:id", requireAuth, async (req, res) => {
  try {
    const authId = req.authUser.id;
    const id = req.params.id;

    const { data, error } = await supabaseAdmin
      .from("cadastro_obra")
      .select("*")
      .eq("id", id)
      .eq("responsavel", authId)
      .single();

    if (error) {
      console.error("GET /obras/:id error:", error);
      return res.status(404).json({ ok: false, error: "Obra não encontrada" });
    }

    return res.json({ ok: true, data });
  } catch (err) {
    console.error("GET /obras/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.get("/obras/admin/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const { data, error } = await supabaseAdmin
      .from("cadastro_obra")
      .select("*")
      .eq("id", id)
      .single();

    if (error) {
      console.error("GET /obras/admin/:id error:", error);
      return res.status(404).json({ ok: false, error: "Obra não encontrada" });
    }

    return res.json({ ok: true, data });
  } catch (err) {
    console.error("GET /obras/admin/:id exception:", err);
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
      situacao: normSituacao(req.body?.situacao, "ativo"),
      responsavel: authId,
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

app.post("/obras/admin", requireAuth, async (req, res) => {
  try {
    const responsavel = req.body?.responsavel;

    if (!isUuid(responsavel)) {
      return res.status(400).json({
        ok: false,
        error: "Responsável inválido (precisa ser auth_user_id UUID)",
      });
    }

    const payload = {
      nome: (req.body?.nome || "").trim(),
      cidade: req.body?.cidade?.trim?.() || null,
      uf: req.body?.uf || null,
      situacao: normSituacao(req.body?.situacao, "ativo"),
      responsavel,
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
      console.error("POST /obras/admin error:", error);
      return res.status(500).json({ ok: false, error: "Falha ao salvar obra" });
    }

    return res.status(201).json({ ok: true, data });
  } catch (err) {
    console.error("POST /obras/admin exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.patch("/obras/:id", requireAuth, async (req, res) => {
  try {
    const authId = req.authUser.id;
    const id = req.params.id;

    const patch = {
      ...(req.body?.nome !== undefined
        ? { nome: String(req.body.nome).trim() }
        : {}),
      ...(req.body?.cidade !== undefined
        ? { cidade: req.body.cidade ? String(req.body.cidade).trim() : null }
        : {}),
      ...(req.body?.uf !== undefined ? { uf: req.body.uf || null } : {}),
      ...(req.body?.situacao !== undefined
        ? { situacao: normSituacao(req.body.situacao) }
        : {}),
      ...(req.body?.endereco !== undefined
        ? {
            endereco: req.body.endereco
              ? String(req.body.endereco).trim()
              : null,
          }
        : {}),
      ...(req.body?.observacao !== undefined
        ? {
            observacao: req.body.observacao
              ? String(req.body.observacao).trim()
              : null,
          }
        : {}),
    };

    if (Object.keys(patch).length === 0) {
      return res.status(400).json({ ok: false, error: "Nada para atualizar" });
    }

    const { error } = await supabaseAdmin
      .from("cadastro_obra")
      .update(patch)
      .eq("id", id)
      .eq("responsavel", authId);

    if (error) {
      console.error("PATCH /obras/:id error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao atualizar obra" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("PATCH /obras/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.patch("/obras/admin/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const patch = {
      ...(req.body?.nome !== undefined
        ? { nome: String(req.body.nome).trim() }
        : {}),
      ...(req.body?.cidade !== undefined
        ? { cidade: req.body.cidade ? String(req.body.cidade).trim() : null }
        : {}),
      ...(req.body?.uf !== undefined ? { uf: req.body.uf || null } : {}),
      ...(req.body?.situacao !== undefined
        ? { situacao: normSituacao(req.body.situacao) }
        : {}),
      ...(req.body?.endereco !== undefined
        ? {
            endereco: req.body.endereco
              ? String(req.body.endereco).trim()
              : null,
          }
        : {}),
      ...(req.body?.observacao !== undefined
        ? {
            observacao: req.body.observacao
              ? String(req.body.observacao).trim()
              : null,
          }
        : {}),
    };

    if (req.body?.responsavel !== undefined) {
      if (!isUuid(req.body.responsavel)) {
        return res.status(400).json({
          ok: false,
          error: "Responsável inválido (precisa ser auth_user_id UUID)",
        });
      }
      patch.responsavel = req.body.responsavel;
    }

    if (Object.keys(patch).length === 0) {
      return res.status(400).json({ ok: false, error: "Nada para atualizar" });
    }

    const { error } = await supabaseAdmin
      .from("cadastro_obra")
      .update(patch)
      .eq("id", id);

    if (error) {
      console.error("PATCH /obras/admin/:id error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao atualizar obra (admin)" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("PATCH /obras/admin/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.delete("/obras/:id", requireAuth, async (req, res) => {
  try {
    const authId = req.authUser.id;
    const id = req.params.id;

    const { error } = await supabaseAdmin
      .from("cadastro_obra")
      .delete()
      .eq("id", id)
      .eq("responsavel", authId);

    if (error) {
      console.error("DELETE /obras/:id error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao deletar obra" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /obras/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

app.delete("/obras/admin/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const { error } = await supabaseAdmin
      .from("cadastro_obra")
      .delete()
      .eq("id", id);

    if (error) {
      console.error("DELETE /obras/admin/:id error:", error);
      return res
        .status(500)
        .json({ ok: false, error: "Falha ao deletar obra (admin)" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /obras/admin/:id exception:", err);
    return res.status(500).json({ ok: false, error: "Erro interno" });
  }
});

// ==================================================
// START
// ==================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ API rodando na porta ${PORT}`));
