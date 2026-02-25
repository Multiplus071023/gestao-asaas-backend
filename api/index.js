export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-asaas-key");
  if (req.method === "OPTIONS") return res.status(204).end();

  const path = req.url;

  // Raiz e health
  if (path === "/" || path === "") return res.json({ status: "ok", sistema: "Gestão Asaas Backend" });
  if (path.startsWith("/health")) return res.json({ status: "ok", sistema: "Gestão Asaas Backend", timestamp: new Date().toISOString() });

  // Proxy Asaas
  if (path.startsWith("/api/asaas/")) {
    const asaasPath = path.replace("/api/asaas/", "");
    const url = `https://api.asaas.com/v3/${asaasPath}`;
    const apiKey = process.env.ASAAS_API_KEY || req.headers["x-asaas-key"] || "";

    let body = undefined;
    if (["POST", "PUT", "PATCH"].includes(req.method)) body = JSON.stringify(req.body);

    try {
      const r = await fetch(url, {
        method: req.method,
        headers: { "access_token": apiKey, "Content-Type": "application/json", "Accept": "application/json" },
        body,
      });
      const text = await r.text();
      if (text.trim().startsWith("<")) return res.status(502).json({ error: true, message: "Erro de comunicação com a Asaas." });
      return res.status(r.status).json(JSON.parse(text));
    } catch (err) {
      return res.status(500).json({ error: true, message: err.message });
    }
  }

  res.status(404).json({ error: "Rota não encontrada" });
}
