// Envia uma baixa para o Apps Script da planilha de cobrança.
// Variáveis no Vercel: APPS_SCRIPT_URL, APPS_SCRIPT_SECRET
async function enviarBaixaPlanilha(dados) {
  const url = process.env.APPS_SCRIPT_URL;
  const secret = process.env.APPS_SCRIPT_SECRET;
  if (!url || !secret) return { ok: false, erro: "APPS_SCRIPT_URL ou APPS_SCRIPT_SECRET não configurados no Vercel" };
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify({ ...dados, acao: "baixa", secret }),
    redirect: "follow",
  });
  const text = await r.text();
  try { return JSON.parse(text); } catch { return { ok: false, erro: "Resposta inesperada do Apps Script (HTTP " + r.status + ")" }; }
}

module.exports = { enviarBaixaPlanilha };
