// Webhook do Asaas: quando uma cobrança é paga, dá baixa na planilha de cobrança.
// Configurar no Asaas (Integrações > Webhooks):
//   URL: https://<backend>.vercel.app/api/asaas-webhook
//   Token de autenticação: o mesmo valor de ASAAS_WEBHOOK_TOKEN no Vercel
//   Eventos: Cobrança recebida (PAYMENT_RECEIVED) e Cobrança confirmada (PAYMENT_CONFIRMED)
// Variáveis no Vercel: ASAAS_WEBHOOK_TOKEN, ASAAS_API_KEY (para buscar o nome do cliente),
//   APPS_SCRIPT_URL, APPS_SCRIPT_SECRET
const { enviarBaixaPlanilha } = require("../lib/planilha");
const { waitUntil } = require("@vercel/functions");

const EVENTOS = ["PAYMENT_RECEIVED", "PAYMENT_CONFIRMED"];

async function nomeCliente(customerId) {
  const key = process.env.ASAAS_API_KEY;
  if (!key || !customerId) return "";
  try {
    const r = await fetch("https://api.asaas.com/v3/customers/" + customerId, {
      headers: { access_token: key, Accept: "application/json" },
    });
    const j = await r.json();
    return j && j.name ? j.name : "";
  } catch { return ""; }
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") return res.status(200).json({ ok: true, servico: "asaas-webhook" });

  const token = req.headers["asaas-access-token"] || "";
  if (!process.env.ASAAS_WEBHOOK_TOKEN || token !== process.env.ASAAS_WEBHOOK_TOKEN) {
    return res.status(401).json({ ok: false, erro: "token inválido" });
  }

  const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
  const p = body.payment || {};
  // Responde 200 para eventos que não interessam, senão o Asaas pausa a fila.
  if (!EVENTOS.includes(body.event) || !p.id) return res.status(200).json({ ok: true, ignorado: body.event || "" });

  // Responde na hora (o Asaas reenvia se a resposta demorar) e processa em seguida.
  waitUntil((async () => {
    try {
      const r = await enviarBaixaPlanilha({
        origem: "asaas:" + body.event,
        id: p.id,
        cliente: await nomeCliente(p.customer),
        descricao: p.description || "",
        valor: p.value,
        valorPago: p.value,
        data: (p.clientPaymentDate || p.paymentDate || p.confirmedDate || new Date().toISOString()).slice(0, 10),
      });
      console.log("asaas-webhook", p.id, JSON.stringify(r));
    } catch (err) {
      console.error("asaas-webhook", p.id, err);
    }
  })());
  return res.status(200).json({ ok: true, recebido: p.id });
};
