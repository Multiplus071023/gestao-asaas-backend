export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-asaas-key");
  if (req.method === "OPTIONS") return res.status(204).end();

  const segments = req.query.path || [];
  const asaasPath = Array.isArray(segments) ? segments.join("/") : segments;
  const query = new URLSearchParams(req.query);
  query.delete("path");
  const qs = query.toString() ? "?" + query.toString() : "";
  const url = `https://api.asaas.com/v3/${asaasPath}${qs}`;

  const apiKey = process.env.ASAAS_API_KEY || req.headers["x-asaas-key"] || "";

  let body = undefined;
  if (["POST", "PUT", "PATCH"].includes(req.method)) {
    body = JSON.stringify(req.body);
  }

  try {
    const r = await fetch(url, {
      method: req.method,
      headers: { "access_token": apiKey, "Content-Type": "application/json", "Accept": "application/json" },
      body,
    });
    const text = await r.text();
    if (text.trim().startsWith("<")) {
      return res.status(502).json({ error: true, message: "Erro de comunicação com a Asaas." });
    }
    res.status(r.status).json(JSON.parse(text));
  } catch (err) {
    res.status(500).json({ error: true, message: err.message });
  }
}
