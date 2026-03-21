// api/nfse.js — Integração Portal Nacional NFS-e (REST API mTLS)
const https  = require("https");
const zlib   = require("zlib");
const forge  = require("node-forge");

const API_URLS = {
  producao:    "sefin.nfse.gov.br",
  homologacao: "sefin.producaorestrita.nfse.gov.br",
};
const API_PATH = "/SefinNacional/nfse";

// ─── Parse body manualmente (Vercel não faz isso automaticamente) ─────────────
function parseBody(req) {
  return new Promise((resolve, reject) => {
    if (req.body && typeof req.body === "object") return resolve(req.body);
    let data = "";
    req.on("data", chunk => data += chunk);
    req.on("end", () => {
      try { resolve(JSON.parse(data || "{}")); }
      catch (e) { reject(new Error("Body JSON inválido")); }
    });
    req.on("error", reject);
  });
}

// ─── Assina XML com certificado A1 ───────────────────────────────────────────
function assinarXML(xmlStr, certBase64, certSenha) {
  const pfxB64 = certBase64.replace(/^data:[^;]+;base64,/, "");
  const pfxDer = forge.util.decode64(pfxB64);
  const pfx    = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(pfxDer), certSenha);

  const certBag = pfx.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag][0];
  const keyBag  = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
  const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(certBag.cert)).getBytes();
  const certB64 = forge.util.encode64(certDer);

  const md = forge.md.sha1.create();
  md.update(forge.util.encodeUtf8(xmlStr));
  const digestB64 = forge.util.encode64(md.digest().getBytes());

  const signedInfo =
    `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    `<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>` +
    `<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>` +
    `<Reference URI=""><Transforms>` +
    `<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` +
    `</Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>` +
    `<DigestValue>${digestB64}</DigestValue></Reference></SignedInfo>`;

  const md2 = forge.md.sha1.create();
  md2.update(forge.util.encodeUtf8(signedInfo));
  const sigB64 = forge.util.encode64(keyBag.key.sign(md2));

  const sigBlock =
    `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    signedInfo +
    `<SignatureValue>${sigB64}</SignatureValue>` +
    `<KeyInfo><X509Data><X509Certificate>${certB64}</X509Certificate></X509Data></KeyInfo>` +
    `</Signature>`;

  return xmlStr.replace(/(<\/\w[^>]*>)\s*$/, sigBlock + "\n$1");
}

// ─── Extrai PEM para mTLS ─────────────────────────────────────────────────────
function extrairPem(certBase64, certSenha) {
  const pfxB64 = certBase64.replace(/^data:[^;]+;base64,/, "");
  const pfxDer = forge.util.decode64(pfxB64);
  const pfx    = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(pfxDer), certSenha);
  const certBag = pfx.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag][0];
  const keyBag  = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
  return {
    cert: forge.pki.certificateToPem(certBag.cert),
    key:  forge.pki.privateKeyToPem(keyBag.key),
  };
}

// ─── GZip + Base64 ────────────────────────────────────────────────────────────
function gzipB64(xmlStr) {
  return new Promise((resolve, reject) =>
    zlib.gzip(Buffer.from(xmlStr, "utf8"), (err, buf) =>
      err ? reject(err) : resolve(buf.toString("base64"))
    )
  );
}

// ─── Chama API REST com mTLS ──────────────────────────────────────────────────
function chamarAPI(xmlGzB64, hostname, certPem, keyPem) {
  const body = JSON.stringify({ xml: xmlGzB64 });
  const buf  = Buffer.from(body, "utf8");

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname, path: API_PATH, method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "Content-Length": buf.length },
      cert: certPem, key: keyPem, timeout: 30000,
    }, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        console.log("[nfse] Status HTTP:", res.statusCode);
        console.log("[nfse] Resposta:", data.slice(0, 500));
        resolve({ status: res.statusCode, body: data });
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Timeout")); });
    req.write(buf);
    req.end();
  });
}

// ─── Parse resposta ────────────────────────────────────────────────────────────
function parsear(body) {
  try {
    const j = JSON.parse(body);
    if (j.chaveAcesso || j.numero || j.numeroNFSe)
      return { sucesso: true, numeroNFSe: j.numero || j.numeroNFSe || "", chaveAcesso: j.chaveAcesso || "", linkNFSe: j.linkNFSe || "" };
    const msg = j.mensagem || j.message || j.descricao || (j.erros?.[0]?.descricao) || JSON.stringify(j).slice(0, 200);
    return { sucesso: false, erro: msg };
  } catch {
    const num = body.match(/<Numero>(\d+)<\/Numero>/)?.[1];
    const msg = body.match(/<Mensagem>([^<]+)<\/Mensagem>/)?.[1];
    if (num) return { sucesso: true, numeroNFSe: num };
    return { sucesso: false, erro: msg || "Resposta inesperada: " + body.slice(0, 200) };
  }
}

// ─── Handler ──────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST")    return res.status(405).json({ error: "Method not allowed" });

  let body;
  try { body = await parseBody(req); }
  catch (e) { return res.status(400).json({ sucesso: false, erro: "Body inválido: " + e.message }); }

  const { xmlDPS, certificado, ambiente } = body;

  console.log("[nfse] xmlDPS presente:", !!xmlDPS, "cert presente:", !!certificado?.base64);

  if (!xmlDPS)              return res.status(400).json({ sucesso: false, erro: "xmlDPS obrigatório" });
  if (!certificado?.base64) return res.status(400).json({ sucesso: false, erro: "Certificado não informado" });
  if (!certificado?.senha)  return res.status(400).json({ sucesso: false, erro: "Senha não informada" });

  let pem;
  try { pem = extrairPem(certificado.base64, certificado.senha); }
  catch (e) { return res.status(400).json({ sucesso: false, erro: "Erro no certificado: " + e.message }); }

  let xmlAssinado;
  try { xmlAssinado = assinarXML(xmlDPS, certificado.base64, certificado.senha); }
  catch (e) { return res.status(400).json({ sucesso: false, erro: "Erro ao assinar: " + e.message }); }

  let xmlGzB64;
  try { xmlGzB64 = await gzipB64(xmlAssinado); }
  catch (e) { return res.status(500).json({ sucesso: false, erro: "Erro GZip: " + e.message }); }

  const hostname = API_URLS[ambiente] || API_URLS.producao;
  let resp;
  try { resp = await chamarAPI(xmlGzB64, hostname, pem.cert, pem.key); }
  catch (e) { return res.status(502).json({ sucesso: false, erro: "Erro de conexão com portal: " + e.message }); }

  return res.status(200).json(parsear(resp.body));
};
