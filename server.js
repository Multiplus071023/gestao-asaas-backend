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

app.get("/", (req, res) => {
  res.json({ status: "ok", sistema: "Gestão Asaas Backend", ambiente: ASAAS_ENV });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", ambiente: ASAAS_ENV, endpoint: ASAAS_BASE, timestamp: new Date().toISOString() });
});

// ── Pega e sanitiza a API Key ─────────────────────────────────────────────────
function getApiKey(req) {
  let key = process.env.ASAAS_API_KEY_RAW || process.env.ASAAS_API_KEY || "";
  // Railway remove o $ — adicionamos de volta se necessário
  if (key && !key.startsWith("$")) key = "$" + key;
  // Fallback: header do frontend
  if ((!key || key === "$") && req.headers["x-asaas-key"]) {
    key = req.headers["x-asaas-key"];
  }
  return key.trim();
}

// ── Proxy para a Asaas ────────────────────────────────────────────────────────
async function proxyAsaas(req, res, method, path) {
  const apiKey = getApiKey(req);

  if (!apiKey || apiKey === "$") {
    console.error("[PROXY] ❌ API Key ausente");
    return res.status(401).json({ error: true, message: "ASAAS_API_KEY_RAW não configurada no Railway." });
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
        "Accept": "application/json",
        // User-Agent padrão de browser para não ser bloqueado pelo CloudFront da Asaas
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "pt-BR,pt;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
      },
      params:  req.query,
      data:    req.body || undefined,
      validateStatus: () => true,
      timeout: 15000,
    });

    if (response.status >= 400) {
      console.error(`[PROXY] Asaas ${response.status}:`, typeof response.data === "string" ? response.data.slice(0, 200) : JSON.stringify(response.data));
    }

    // Se a Asaas retornou HTML (CloudFront bloqueou), retorna erro legível
    const isHtml = typeof response.data === "string" && response.data.trim().startsWith("<");
    if (isHtml) {
      return res.status(502).json({
        error: true,
        message: "Requisição bloqueada pelo CloudFront da Asaas. Tente novamente em alguns instantes.",
        status: response.status
      });
    }

    return res.status(response.status).json(response.data);
  } catch (err) {
    console.error(`[PROXY ERROR] ${method} ${path}:`, err.message);
    return res.status(502).json({ error: true, message: err.message });
  }
}

// ── Rotas ─────────────────────────────────────────────────────────────────────
app.get("/api/asaas/balance",                         (req, res) => proxyAsaas(req, res, "GET",    "/finance/balance"));
app.get("/api/asaas/accounts",                        (req, res) => proxyAsaas(req, res, "GET",    "/accounts"));
app.post("/api/asaas/accounts",                       (req, res) => proxyAsaas(req, res, "POST",   "/accounts"));
app.get("/api/asaas/accounts/:id",                    (req, res) => proxyAsaas(req, res, "GET",    `/accounts/${req.params.id}`));
app.get("/api/asaas/accounts/:id/balance",            (req, res) => proxyAsaas(req, res, "GET",    `/accounts/${req.params.id}/balance`));
app.get("/api/asaas/payments",                        (req, res) => proxyAsaas(req, res, "GET",    "/payments"));
app.post("/api/asaas/payments",                       (req, res) => proxyAsaas(req, res, "POST",   "/payments"));
app.get("/api/asaas/payments/:id",                    (req, res) => proxyAsaas(req, res, "GET",    `/payments/${req.params.id}`));
app.delete("/api/asaas/payments/:id",                 (req, res) => proxyAsaas(req, res, "DELETE", `/payments/${req.params.id}`));
app.get("/api/asaas/payments/:id/pixQrCode",          (req, res) => proxyAsaas(req, res, "GET",    `/payments/${req.params.id}/pixQrCode`));
app.get("/api/asaas/payments/:id/identificationField",(req, res) => proxyAsaas(req, res, "GET",    `/payments/${req.params.id}/identificationField`));
app.get("/api/asaas/customers",                       (req, res) => proxyAsaas(req, res, "GET",    "/customers"));
app.post("/api/asaas/customers",                      (req, res) => proxyAsaas(req, res, "POST",   "/customers"));
app.put("/api/asaas/customers/:id",                   (req, res) => proxyAsaas(req, res, "PUT",    `/customers/${req.params.id}`));
app.delete("/api/asaas/customers/:id",                (req, res) => proxyAsaas(req, res, "DELETE", `/customers/${req.params.id}`));
app.get("/api/asaas/transfers",                       (req, res) => proxyAsaas(req, res, "GET",    "/transfers"));
app.post("/api/asaas/transfers",                      (req, res) => proxyAsaas(req, res, "POST",   "/transfers"));
app.post("/api/asaas/webhook",                        (req, res) => { console.log("[WEBHOOK]", req.body); res.json({ received: true }); });
app.all("/api/asaas/*",                               (req, res) => proxyAsaas(req, res, req.method, req.path.replace("/api/asaas", "")));

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  const keyStatus = process.env.ASAAS_API_KEY_RAW
    ? "✅ ASAAS_API_KEY_RAW configurada"
    : process.env.ASAAS_API_KEY
    ? "⚠️  ASAAS_API_KEY configurada (prefira _RAW)"
    : "❌ NÃO configurada";
  console.log(`✅ Gestão Asaas Backend rodando na porta ${PORT}`);
  console.log(`   Ambiente : ${ASAAS_ENV}`);
  console.log(`   Asaas    : ${ASAAS_BASE}`);
  console.log(`   API Key  : ${keyStatus}`);
});
