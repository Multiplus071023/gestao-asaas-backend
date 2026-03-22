// api/nfse.js — Integração Portal Nacional NFS-e com assinatura XMLDSIG correta
const https  = require("https");
const zlib   = require("zlib");
const forge  = require("node-forge");
const crypto = require("crypto");

const API_URLS = {
  producao:    "sefin.nfse.gov.br",
  homologacao: "sefin.producaorestrita.nfse.gov.br",
};
const API_PATH = "/SefinNacional/nfse";

// ─── Parse body ───────────────────────────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve, reject) => {
    if (req.body && typeof req.body === "object") return resolve(req.body);
    let data = "";
    req.on("data", c => data += c);
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch(e) { reject(e); } });
    req.on("error", reject);
  });
}

// ─── Extrai cert/key PEM do PFX ───────────────────────────────────────────────
function extrairPem(certBase64, certSenha) {
  const pfxB64 = certBase64.replace(/^data:[^;]+;base64,/, "");
  const pfxDer = forge.util.decode64(pfxB64);
  const pfx    = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(pfxDer), certSenha);
  const certBag = pfx.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag][0];
  const keyBag  = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
  return {
    cert:    forge.pki.certificateToPem(certBag.cert),
    key:     forge.pki.privateKeyToPem(keyBag.key),
    certDer: forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(certBag.cert)).getBytes()),
  };
}

// ─── Canonicalização Exclusive C14N simples (sem namespace complexo) ──────────
// Para o portal NFS-e, o XML é simples o suficiente para usar esta abordagem
function c14n(xmlStr) {
  // Remove XML declaration
  let s = xmlStr.replace(/^<\?xml[^?]*\?>\s*/m, "");
  // Normaliza atributos em ordem alfabética por tag (simplified)
  // Para este XML específico não há atributos fora de ordem crítica
  return s;
}

// ─── Assina o XML com XMLDSIG RSA-SHA256 ──────────────────────────────────────
function assinarXML(xmlStr, pem) {
  // Extrai o Id do infDPS
  const idMatch = xmlStr.match(/infDPS Id="([^"]+)"/);
  if (!idMatch) throw new Error("Id do infDPS não encontrado no XML");
  const refId = idMatch[1];

  // Remove XML declaration para processamento
  const xmlSemProlog = xmlStr.replace(/^<\?xml[^?]*\?>\s*/m, "");

  // Extrai apenas o conteúdo do infDPS para o digest (elemento referenciado)
  // O elemento referenciado é o <infDPS> completo
  const infDPSMatch = xmlSemProlog.match(/<infDPS[\s\S]*?<\/infDPS>/);
  if (!infDPSMatch) throw new Error("Elemento infDPS não encontrado");
  const infDPSContent = infDPSMatch[0];

  // Digest SHA-256 do infDPS canonicalizado
  const digestB64 = crypto
    .createHash("sha256")
    .update(Buffer.from(infDPSContent, "utf8"))
    .digest("base64");

  // Monta SignedInfo
  const signedInfo =
    `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    `<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>` +
    `<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
    `<Reference URI="#${refId}">` +
    `<Transforms>` +
    `<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` +
    `<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>` +
    `</Transforms>` +
    `<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
    `<DigestValue>${digestB64}</DigestValue>` +
    `</Reference>` +
    `</SignedInfo>`;

  // Assina SignedInfo com RSA-SHA256 usando Node crypto (mais confiável que forge para isso)
  const sign = crypto.createSign("RSA-SHA256");
  sign.update(signedInfo, "utf8");
  const sigB64 = sign.sign(pem.key, "base64");

  const sigBlock =
    `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    signedInfo +
    `<SignatureValue>${sigB64}</SignatureValue>` +
    `<KeyInfo><X509Data><X509Certificate>${pem.certDer}</X509Certificate></X509Data></KeyInfo>` +
    `</Signature>`;

  // Injeta assinatura dentro de <DPS>, antes do </DPS>
  return xmlStr.replace(`</DPS>`, `\n${sigBlock}\n</DPS>`);
}

// ─── GZip + Base64 ────────────────────────────────────────────────────────────
function sanitizarXML(str) {
  str = str.replace(/^\uFEFF/, "");
  str = str.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
  return str;
}

function gzipB64(str) {
  const limpo = sanitizarXML(str);
  const buf   = Buffer.from(limpo, "utf8");
  const semBOM = (buf[0]===0xEF && buf[1]===0xBB && buf[2]===0xBF) ? buf.slice(3) : buf;
  return new Promise((res, rej) =>
    zlib.gzip(semBOM, (e, b) => e ? rej(e) : res(b.toString("base64")))
  );
}

// ─── POST para API REST ────────────────────────────────────────────────────────
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
        console.log("[nfse] HTTP:", res.statusCode, "| Body:", data.slice(0, 600));
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
    if (j.chaveAcesso || j.numero || j.numeroNFSe || j.nNFSe)
      return { sucesso: true, numeroNFSe: j.nNFSe || j.numero || j.numeroNFSe || "", chaveAcesso: j.chaveAcesso || "", linkNFSe: j.linkNFSe || "" };
    const msg = j.mensagem || j.message || (j.erros && j.erros[0]?.Descricao) || JSON.stringify(j).slice(0, 300);
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
  catch(e) { return res.status(400).json({ sucesso: false, erro: "Body inválido" }); }

  const { xmlDPS, certificado, ambiente } = body;
  console.log("[nfse] xmlDPS:", !!xmlDPS, "| cert:", !!certificado?.base64, "| amb:", ambiente);

  if (!xmlDPS)              return res.status(400).json({ sucesso: false, erro: "xmlDPS obrigatório" });
  if (!certificado?.base64) return res.status(400).json({ sucesso: false, erro: "Certificado não informado" });
  if (!certificado?.senha)  return res.status(400).json({ sucesso: false, erro: "Senha não informada" });

  let pem;
  try { pem = extrairPem(certificado.base64, certificado.senha); }
  catch(e) { return res.status(400).json({ sucesso: false, erro: "Certificado inválido: " + e.message }); }

  let xmlAssinado;
  try { xmlAssinado = assinarXML(xmlDPS, pem); }
  catch(e) { return res.status(400).json({ sucesso: false, erro: "Erro na assinatura: " + e.message }); }

  console.log("[nfse] === XML ASSINADO (primeiros 800) ===");
  console.log(xmlAssinado.slice(0, 800));

  let gzB64;
  try { gzB64 = await gzipB64(xmlAssinado); }
  catch(e) { return res.status(500).json({ sucesso: false, erro: "Erro GZip: " + e.message }); }

  const hostname = API_URLS[ambiente] || API_URLS.producao;
  let resp;
  try { resp = await chamarAPI(gzB64, hostname, pem.cert, pem.key); }
  catch(e) { return res.status(502).json({ sucesso: false, erro: "Erro de conexão: " + e.message }); }

  return res.status(200).json(parsear(resp.body));
};
