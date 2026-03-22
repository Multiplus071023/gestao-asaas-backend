// api/nfse.js — Integração Portal Nacional NFS-e (REST API mTLS + RSA-SHA256)
const https  = require("https");
const zlib   = require("zlib");
const forge  = require("node-forge");

const API_URLS = {
  producao:    "sefin.nfse.gov.br",
  homologacao: "sefin.producaorestrita.nfse.gov.br",
};
const API_PATH = "/SefinNacional/nfse";

// ─── Parse body ────────────────────────────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve, reject) => {
    if (req.body && typeof req.body === "object") return resolve(req.body);
    let data = "";
    req.on("data", c => data += c);
    req.on("end", () => {
      try { resolve(JSON.parse(data || "{}")); }
      catch (e) { reject(new Error("Body JSON inválido")); }
    });
    req.on("error", reject);
  });
}

// ─── Assina DPS: digest do elemento infDPS, Signature após </infDPS> ──────────
function assinarDPS(xmlStr, certBase64, certSenha) {
  const pfxB64 = certBase64.replace(/^data:[^;]+;base64,/, "");
  const pfxDer = forge.util.decode64(pfxB64);
  const pfx    = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(pfxDer), certSenha);

  const certBag = pfx.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag][0];
  const keyBag  = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
  const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(certBag.cert)).getBytes();
  const certB64 = forge.util.encode64(certDer);

  // Extrai ID do infDPS
  const idMatch  = xmlStr.match(/infDPS Id="([^"]+)"/);
  const infDpsId = idMatch ? idMatch[1] : "";

  // Extrai elemento <infDPS>...</infDPS> para calcular digest
  const infDpsMatch   = xmlStr.match(/<infDPS[\s\S]*?<\/infDPS>/);
  const infDpsContent = infDpsMatch ? infDpsMatch[0] : xmlStr;

  // Digest SHA-256 do elemento infDPS
  const md = forge.md.sha256.create();
  md.update(forge.util.encodeUtf8(infDpsContent));
  const digestB64 = forge.util.encode64(md.digest().getBytes());

  // SignedInfo referenciando infDPS por ID
  const signedInfo =
    `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    `<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>` +
    `<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
    `<Reference URI="#${infDpsId}">` +
    `<Transforms>` +
    `<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` +
    `<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>` +
    `</Transforms>` +
    `<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
    `<DigestValue>${digestB64}</DigestValue>` +
    `</Reference>` +
    `</SignedInfo>`;

  // Assina SignedInfo com RSA-SHA256
  const md2 = forge.md.sha256.create();
  md2.update(forge.util.encodeUtf8(signedInfo));
  const sigB64 = forge.util.encode64(keyBag.key.sign(md2));

  const sigBlock =
    `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    signedInfo +
    `<SignatureValue>${sigB64}</SignatureValue>` +
    `<KeyInfo><X509Data><X509Certificate>${certB64}</X509Certificate></X509Data></KeyInfo>` +
    `</Signature>`;

  // Injeta Signature após </infDPS>, dentro de </DPS>
  return xmlStr.replace("</infDPS>", "</infDPS>\n" + sigBlock);
}

// ─── Extrai PEM para mTLS ──────────────────────────────────────────────────────
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

// ─── Sanitiza + GZip + Base64 ─────────────────────────────────────────────────
function sanitizarXML(str) {
  str = str.replace(/^\uFEFF/, "");
  str = str.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
  return str;
}

function gzipB64(str) {
  const limpo = sanitizarXML(str);
  let buf = Buffer.from(limpo, "utf8");
  if (buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) buf = buf.slice(3);
  return new Promise((res, rej) =>
    zlib.gzip(buf, (e, b) => e ? rej(e) : res(b.toString("base64")))
  );
}

// ─── POST: campo dpsXmlGZipB64 em JSON ────────────────────────────────────────
function chamarAPI(xmlGzB64, hostname, certPem, keyPem) {
  const body = JSON.stringify({ dpsXmlGZipB64: xmlGzB64 });
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
        console.log("[nfse] HTTP:", res.statusCode, "| Body:", data.slice(0, 500));
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
    if (j.chaveAcesso || j.numero || j.numeroNFSe || j.nfseXmlGZipB64)
      return { sucesso: true, numeroNFSe: j.numero || j.numeroNFSe || "", chaveAcesso: j.chaveAcesso || "", nfseXml: j.nfseXmlGZipB64 || "" };
    const msg = j.mensagem || j.message || j.descricao ||
      (j.erros && j.erros[0]?.Descricao) || JSON.stringify(j).slice(0, 300);
    return { sucesso: false, erro: msg };
  } catch {
    const num = body.match(/<Numero>(\d+)<\/Numero>/)?.[1];
    if (num) return { sucesso: true, numeroNFSe: num };
    return { sucesso: false, erro: "Resposta: " + body.slice(0, 300) };
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
  catch (e) { return res.status(400).json({ sucesso: false, erro: "Body inválido" }); }

  const { xmlDPS, certificado, ambiente } = body;
  console.log("[nfse] xmlDPS:", !!xmlDPS, "| cert:", !!certificado?.base64, "| amb:", ambiente);

  if (!xmlDPS)              return res.status(400).json({ sucesso: false, erro: "xmlDPS obrigatório" });
  if (!certificado?.base64) return res.status(400).json({ sucesso: false, erro: "Certificado não informado" });
  if (!certificado?.senha)  return res.status(400).json({ sucesso: false, erro: "Senha não informada" });

  let pem;
  try { pem = extrairPem(certificado.base64, certificado.senha); }
  catch (e) { return res.status(400).json({ sucesso: false, erro: "Erro no certificado: " + e.message }); }

  let xmlAssinado;
  try {
    xmlAssinado = assinarDPS(xmlDPS, certificado.base64, certificado.senha);
    console.log("[nfse] === XML ENVIADO ===");
    console.log(xmlAssinado);
    console.log("[nfse] === FIM XML ===");
  }
  catch (e) { return res.status(400).json({ sucesso: false, erro: "Erro ao assinar: " + e.message }); }

  let gzB64;
  try { gzB64 = await gzipB64(xmlAssinado); }
  catch (e) { return res.status(500).json({ sucesso: false, erro: "Erro GZip: " + e.message }); }

  const hostname = API_URLS[ambiente] || API_URLS.producao;
  let resp;
  try { resp = await chamarAPI(gzB64, hostname, pem.cert, pem.key); }
  catch (e) { return res.status(502).json({ sucesso: false, erro: "Erro de conexão: " + e.message }); }

  return res.status(200).json(parsear(resp.body));
};
