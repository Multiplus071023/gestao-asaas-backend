export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-asaas-key");
  if (req.method === "OPTIONS") return res.status(204).end();

  const path = (req.query.path || "").replace(/^\/+/, "");

  if (!path || path === "health") {
    return res.json({ status: "ok", sistema: "Gestão Asaas Backend", timestamp: new Date().toISOString() });
  }

  if (path.startsWith("api/asaas/")) {
    const asaasPath = path.replace("api/asaas/", "");
    const q = { ...req.query };
    delete q.path;
    const qs = Object.keys(q).length ? "?" + new URLSearchParams(q).toString() : "";
    const url = `https://api.asaas.com/v3/${asaasPath}${qs}`;

    const apiKey = process.env.ASAAS_API_KEY || req.headers["x-asaas-key"] || "";
    if (!apiKey) return res.status(401).json({ error: true, message: "ASAAS_API_KEY não configurada." });

    let body = undefined;
    if (["POST", "PUT", "PATCH"].includes(req.method)) body = JSON.stringify(req.body);

    try {
      const r = await fetch(url, {
        method: req.method,
        headers: { "access_token": apiKey, "Content-Type": "application/json", "Accept": "application/json" },
        body,
      });
      const text = await r.text();
      if (!text || text.trim() === "") return res.status(502).json({ error: true, message: "Asaas retornou resposta vazia." });
      if (text.trim().startsWith("<")) return res.status(502).json({ error: true, message: "Asaas bloqueou a requisição." });
      return res.status(r.status).json(JSON.parse(text));
    } catch (err) {
      return res.status(500).json({ error: true, message: err.message });
    }
  }

  return res.json({ status: "ok", path });
}
