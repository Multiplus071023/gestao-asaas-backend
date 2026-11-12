// Novo cliente cadastrado no app -> aba "Clientes" da planilha de cobrança.
// Usa o mesmo token da baixa (PLANILHA_APP_TOKEN / "Token da planilha" no app).
const { enviarBaixaPlanilha } = require("../lib/planilha");

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-planilha-token");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, erro: "use POST" });

  const token = String(req.headers["x-planilha-token"] || "").trim();
  if (!process.env.PLANILHA_APP_TOKEN || token !== process.env.PLANILHA_APP_TOKEN.trim()) {
    return res.status(401).json({ ok: false, erro: "token da planilha inválido" });
  }

  const b = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
  if (!b.responsavel && !b.aluno) return res.status(400).json({ ok: false, erro: "cliente sem nome" });

  try {
    const r = await enviarBaixaPlanilha({ acao: "cliente", origem: "app:cliente", id: String(b.id || ""), cliente: b });
    return res.status(200).json(r);
  } catch (err) {
    return res.status(500).json({ ok: false, erro: err.message });
  }
};
