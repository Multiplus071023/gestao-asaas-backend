// Baixa de cobrança local feita no app (dinheiro, Sicoob, terapeuta) -> planilha de cobrança.
// O app envia o token do campo "Token da planilha" (Configurações), que deve ser igual a
// PLANILHA_APP_TOKEN no Vercel.
const { enviarBaixaPlanilha } = require("../lib/planilha");

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-planilha-token");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, erro: "use POST" });

  const token = req.headers["x-planilha-token"] || "";
  if (!process.env.PLANILHA_APP_TOKEN || token !== process.env.PLANILHA_APP_TOKEN) {
    return res.status(401).json({ ok: false, erro: "token da planilha inválido" });
  }

  const b = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
  if (!b.id) return res.status(400).json({ ok: false, erro: "id obrigatório" });

  try {
    const r = await enviarBaixaPlanilha({
      origem: "app",
      id: String(b.id),
      cliente: b.cliente || "",
      descricao: b.descricao || "",
      valor: b.valor,
      valorPago: b.valorPago,
      data: b.data || "",
    });
    return res.status(200).json(r);
  } catch (err) {
    return res.status(500).json({ ok: false, erro: err.message });
  }
};
