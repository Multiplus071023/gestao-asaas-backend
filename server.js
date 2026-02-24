/**
 * Gestão Asaas — Backend Proxy Server
 * Hospedagem: Railway.app
 */

const express = require("express");
const cors    = require("cors");
const axios   = require("axios");
require("dotenv").config();

const app  = express();
const PORT = process.env.PORT || 3001;

const ASAAS_ENV  = process.env.ASAAS_ENV || "production";
const ASAAS_BASE = ASAAS_ENV === "sandbox"
  ? "https://sandbox.asaas.com/api/v3"
  : "https://api.asaas.com/v3";

app.use(cors({ origin: "*" }));
app.use(express.json());

// ── Rota inicial (confirma que o servidor está ok) ────────────────────────────
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    sistema: "Gestão Asaas Backend",
    ambiente: ASAAS_ENV,
    versao: "1.0.0"
  });
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    ambiente: ASAAS_ENV,
    endpoint: ASAAS_BASE,
    timestamp: new Date().toISOString()
  });
});

// ── Helper: pega e sanitiza a API Key ─────────────────────────────────────────
function getApiKey(req) {
  // Prioridade: variável de ambiente do servidor (Railway)
  // O Railway às vezes interpreta o $ da chave como variável de shell.
  // Por isso salvamos a chave em ASAAS_API_KEY_RAW (sem o $) e adicionamos aqui.
  let key = process.env.ASAAS_API_KEY_RAW || process.env.ASAAS_API_KEY || "";

  // Se a chave vier sem o $ no início (salva como _RAW), adiciona
  if (key && !key.startsWith("$")) {
    key = "$" + key;
  }

  // Fallback: header enviado pelo frontend
  if (!key && req.headers["x-asaas-key"]) {
    key = req.headers["x-asaas-key"];
  }

  return key.trim();
}

// ── Helper: proxy para a Asaas ────────────────────────────────────────────────
async function proxyAsaas(req, res, method, path) {
  const apiKey = getApiKey(req);

  if (!apiKey || apiKey === "$") {
    console.error("[PROXY] ❌ API Key ausente");
    return res.status(401).json({
      error: true,
      message: "API Key não configurada no servidor. Adicione ASAAS_API_KEY_RAW nas variáveis do Railway."
    });
  }

  const keyPreview = `${apiKey.slice(0, 12)}...${apiKey.slice(-4)}`;
  console.log(`[PROXY] ${method} ${path} | key: ${keyPreview}`);

  try {
    const response = await axios({
      method,
      url: `${ASAAS_BASE}${path}`,
      headers: {
        "access_token": apiKey,
        "Content-Type": "application/json",
        "User-Agent": "GestaoAsaas/1.0",
      },
      params: req.query,
      data: req.body || undefined,
      validateStatus: () => true,
    });

    if (response.status >= 400) {
      console.error(`[PROXY] Asaas ${response.status}:`, JSON.stringify(response.data));
    }

    return res.status(response.status).json(response.data);
  } catch (err) {
    console.error(`[PROXY ERROR] ${method} ${path}:`, err.message);
    return res.status(502).json({ error: true, message: err.message });
  }
}

// ── Rotas ─────────────────────────────────────────────────────────────────────
app.get("/api/asaas/balance",                        (req, res) => proxyAsaas(req, res, "GET",    "/finance/balance"));
app.get("/api/asaas/accounts",                       (req, res) => proxyAsaas(req, res, "GET",    "/accounts"));
app.post("/api/asaas/accounts",                      (req, res) => proxyAsaas(req, res, "POST",   "/accounts"));
app.get("/api/asaas/accounts/:id",                   (req, res) => proxyAsaas(req, res, "GET",    `/accounts/${req.params.id}`));
app.get("/api/asaas/accounts/:id/balance",           (req, res) => proxyAsaas(req, res, "GET",    `/accounts/${req.params.id}/balance`));
app.get("/api/asaas/payments",                       (req, res) => proxyAsaas(req, res, "GET",    "/payments"));
app.post("/api/asaas/payments",                      (req, res) => proxyAsaas(req, res, "POST",   "/payments"));
app.get("/api/asaas/payments/:id",                   (req, res) => proxyAsaas(req, res, "GET",    `/payments/${req.params.id}`));
app.delete("/api/asaas/payments/:id",                (req, res) => proxyAsaas(req, res, "DELETE", `/payments/${req.params.id}`));
app.get("/api/asaas/payments/:id/pixQrCode",         (req, res) => proxyAsaas(req, res, "GET",    `/payments/${req.params.id}/pixQrCode`));
app.get("/api/asaas/payments/:id/identificationField",(req, res)=> proxyAsaas(req, res, "GET",    `/payments/${req.params.id}/identificationField`));
app.get("/api/asaas/customers",                      (req, res) => proxyAsaas(req, res, "GET",    "/customers"));
app.post("/api/asaas/customers",                     (req, res) => proxyAsaas(req, res, "POST",   "/customers"));
app.put("/api/asaas/customers/:id",                  (req, res) => proxyAsaas(req, res, "PUT",    `/customers/${req.params.id}`));
app.delete("/api/asaas/customers/:id",               (req, res) => proxyAsaas(req, res, "DELETE", `/customers/${req.params.id}`));
app.get("/api/asaas/transfers",                      (req, res) => proxyAsaas(req, res, "GET",    "/transfers"));
app.post("/api/asaas/transfers",                     (req, res) => proxyAsaas(req, res, "POST",   "/transfers"));
app.post("/api/asaas/webhook",                       (req, res) => { console.log("[WEBHOOK]", req.body); res.json({ received: true }); });
app.all("/api/asaas/*",                              (req, res) => proxyAsaas(req, res, req.method, req.path.replace("/api/asaas", "")));

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Gestão Asaas Backend rodando na porta ${PORT}`);
  console.log(`   Ambiente : ${ASAAS_ENV}`);
  console.log(`   Asaas    : ${ASAAS_BASE}`);
  console.log(`   Health   : http://localhost:${PORT}/health`);
  console.log(`   API Key  : ${process.env.ASAAS_API_KEY_RAW ? "✅ ASAAS_API_KEY_RAW configurada" : process.env.ASAAS_API_KEY ? "⚠️  ASAAS_API_KEY configurada (use _RAW)" : "❌ NÃO configurada"}`);
});
