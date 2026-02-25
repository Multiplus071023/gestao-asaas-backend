export default function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.json({ status: "ok", sistema: "Gestão Asaas Backend", timestamp: new Date().toISOString() });
}
