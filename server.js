/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║   GESTÃO ASAAS — Backend Proxy Server                  ║
 * ║   Hospedagem: Railway.app                              ║
 * ╚══════════════════════════════════════════════════════════╝
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

// Libera acesso de qualquer origem (Netlify + local)
app.use(cors({ origin: "*" }));
app.use(express.json());

// Helper: repassa requisição para a Asaas
async function proxyAsaas(req, res, method, path) {
  const apiKey = req.headers["x-asaas-key"] || process.env.ASAAS_API_KEY || "";
  if (!apiKey) {
    return res.status(401).json({ error: true, message: "API Key não configurada." });
  }
  try {
    const response = await axios({
      method,
      url: `${ASAAS_BASE}${path}`,
      headers: {
        "access_token": apiKey,
        "Content-Type": "application/json",
        "User-Agent": "GestaoAsaas/1.0",
      },
      params:  req.query,
      data:    req.body || undefined,
      validateStatus: () => true,
    });
    return res.status(response.status).json(response.data);
  } catch (err) {
    console.error(`[PROXY ERROR] ${method} ${path}:`, err.message);
    return res.status(502).json({ error: true, message: err.message });
  }
}

// ── Health check ──────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", ambiente: ASAAS_ENV, endpoint: ASAAS_BASE, timestamp: new Date().toISOString() });
});

// ── Saldo ─────────────────────────────────────────────────
app.get("/api/asaas/balance",         (req, res) => proxyAsaas(req, res, "GET",    "/finance/balance"));

// ── Subcontas ─────────────────────────────────────────────
app.get("/api/asaas/accounts",        (req, res) => proxyAsaas(req, res, "GET",    "/accounts"));
app.post("/api/asaas/accounts",       (req, res) => proxyAsaas(req, res, "POST",   "/accounts"));
app.get("/api/asaas/accounts/:id",    (req, res) => proxyAsaas(req, res, "GET",    `/accounts/${req.params.id}`));
app.get("/api/asaas/accounts/:id/balance", (req, res) => proxyAsaas(req, res, "GET", `/accounts/${req.params.id}/balance`));

// ── Cobranças ─────────────────────────────────────────────
app.get("/api/asaas/payments",        (req, res) => proxyAsaas(req, res, "GET",    "/payments"));
app.post("/api/asaas/payments",       (req, res) => proxyAsaas(req, res, "POST",   "/payments"));
app.get("/api/asaas/payments/:id",    (req, res) => proxyAsaas(req, res, "GET",    `/payments/${req.params.id}`));
app.delete("/api/asaas/payments/:id", (req, res) => proxyAsaas(req, res, "DELETE", `/payments/${req.params.id}`));
app.get("/api/asaas/payments/:id/pixQrCode",          (req, res) => proxyAsaas(req, res, "GET", `/payments/${req.params.id}/pixQrCode`));
app.get("/api/asaas/payments/:id/identificationField",(req, res) => proxyAsaas(req, res, "GET", `/payments/${req.params.id}/identificationField`));

// ── Clientes Asaas ────────────────────────────────────────
app.get("/api/asaas/customers",       (req, res) => proxyAsaas(req, res, "GET",    "/customers"));
app.post("/api/asaas/customers",      (req, res) => proxyAsaas(req, res, "POST",   "/customers"));
app.put("/api/asaas/customers/:id",   (req, res) => proxyAsaas(req, res, "PUT",    `/customers/${req.params.id}`));
app.delete("/api/asaas/customers/:id",(req, res) => proxyAsaas(req, res, "DELETE", `/customers/${req.params.id}`));

// ── Transferências ────────────────────────────────────────
app.get("/api/asaas/transfers",       (req, res) => proxyAsaas(req, res, "GET",    "/transfers"));
app.post("/api/asaas/transfers",      (req, res) => proxyAsaas(req, res, "POST",   "/transfers"));

// ── Webhook (Asaas → backend) ─────────────────────────────
app.post("/api/asaas/webhook", (req, res) => {
  console.log("[WEBHOOK]", JSON.stringify(req.body));
  res.json({ received: true });
});

// ── Proxy genérico para rotas não mapeadas ────────────────
app.all("/api/asaas/*", (req, res) => {
  const path = req.path.replace("/api/asaas", "");
  proxyAsaas(req, res, req.method, path);
});

app.listen(PORT, () => {
  console.log(`✅ Gestão Asaas Backend rodando na porta ${PORT}`);
  console.log(`   Ambiente: ${ASAAS_ENV}`);
  console.log(`   Asaas:    ${ASAAS_BASE}`);
  console.log(`   Health:   http://localhost:${PORT}/health`);
});
