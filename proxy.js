export default async function handler(req, res) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-asaas-key");
  if (req.method === "OPTIONS") return res.status(204).end();

  const { path } = req.query;
  const asaasPath = Array.isArray(path) ? path.join("/") : path || "";

  // Health check
  if (asaasPath === "health") {
    return res.json({ status: "ok", sistema: "Gestão Asaas Backend", timestamp: new Date().toISOString() });
  }

  // Raiz
  if (!asaasPath || asaasPath === "") {
    return res.json({ status: "ok", sistema: "Gestão Asaas Backend (Vercel)" });
  }

  const apiKey = process.env.ASAAS_API_KEY || req.headers["x-asaas-key"] || "";
  const ASAAS_BASE = "https://api.asaas.com/v3";
  const url = `${ASAAS_BASE}/${asaasPath}${req.url.includes("?") ? "?" + req.url.split("?")[1] : ""}`;

  let body = undefined;
  if (["POST", "PUT", "PATCH"].includes(req.method)) {
    body = JSON.stringify(req.body);
  }

  try {
    const response = await fetch(url, {
      method: req.method,
      headers: {
        "access_token": apiKey,
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body,
    });

    const text = await response.text();
    if (text.trim().startsWith("<")) {
      return res.status(502).json({ error: true, message: "Erro de comunicação com a Asaas. Tente novamente." });
    }

    res.status(response.status).json(JSON.parse(text));
  } catch (err) {
    res.status(500).json({ error: true, message: err.message });
  }
}
