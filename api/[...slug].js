export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-asaas-key");
  if (req.method === "OPTIONS") return res.status(204).end();

  const slug = req.query.slug || [];
  const parts = Array.isArray(slug) ? slug : [slug];
  const fullPath = parts.join("/");

  // Health check
  if (fullPath === "health") {
    return res.json({ status: "ok", sistema: "Gestão Asaas Backend", timestamp: new Date().toISOString() });
  }

  // Proxy Asaas: api/asaas/finance/balance → https://api.asaas.com/v3/finance/balance
  if (parts[0] === "api" && parts[1] === "asaas") {
    const asaasPath = parts.slice(2).join("/");
    
    // Monta query string (remove slug da query)
    const q = { ...req.query };
    delete q.slug;
    const qs = Object.keys(q).length ? "?" + new URLSearchParams(q).toString() : "";
    const url = `https://api.asaas.com/v3/${asaasPath}${qs}`;
    
    const apiKey = process.env.ASAAS_API_KEY || "";
    if (!apiKey) {
      return res.status(401).json({ error: true, message: "ASAAS_API_KEY não configurada no Vercel. Vá em Settings → Environment Variables." });
    }

    let body = undefined;
    if (["POST", "PUT", "PATCH"].includes(req.method)) {
      body = JSON.stringify(req.body);
    }

    try {
      const r = await fetch(url, {
        method: req.method,
        headers: {
          "access_token": apiKey,
          "Content-Type": "application/json",
          "Accept": "application/json",
        },
        body,
      });
      const text = await r.text();
      if (!text || text.trim() === "") {
        return res.status(502).json({ error: true, message: "Asaas retornou resposta vazia. Verifique a API Key." });
      }
      if (text.trim().startsWith("<")) {
        return res.status(502).json({ error: true, message: "Asaas retornou HTML. IP bloqueado ou erro de rede." });
      }
      return res.status(r.status).json(JSON.parse(text));
    } catch (err) {
      return res.status(500).json({ error: true, message: err.message, path: url });
    }
  }

  // Raiz
  return res.json({ status: "ok", sistema: "Gestão Asaas Backend (Vercel)", path: fullPath });
}
