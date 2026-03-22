// api/nfse.js — Portal Nacional NFS-e com assinatura XMLDSIG manual
// Implementação manual garante canonical form correto sem depender de xml-crypto
const https  = require("https");
const zlib   = require("zlib");
const crypto = require("crypto");
const forge  = require("node-forge");

const API_URLS = {
  producao:    "sefin.nfse.gov.br",
  homologacao: "sefin.producaorestrita.nfse.gov.br",
};
const API_PATH = "/SefinNacional/nfse";

function parseBody(req) {
  return new Promise((resolve, reject) => {
    if (req.body && typeof req.body === "object") return resolve(req.body);
    let d = "";
    req.on("data", c => d += c);
    req.on("end", () => { try { resolve(JSON.parse(d || "{}")); } catch(e) { reject(e); } });
    req.on("error", reject);
  });
}

function extrairPem(certBase64, certSenha) {
  const pfxB64 = certBase64.replace(/^data:[^;]+;base64,/, "");
  const pfxDer = forge.util.decode64(pfxB64);
  const pfx    = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(pfxDer), certSenha);
  const allCerts = pfx.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  const keyBags  = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || [];
  if (!keyBags.length) throw new Error("Chave privada não encontrada");
  const privateKey  = keyBags[0].key;
  const privPem     = forge.pki.privateKeyToPem(privateKey);
  const pubFromPriv = forge.pki.publicKeyToPem(forge.pki.rsa.setPublicKey(privateKey.n, privateKey.e));
  let matchedCert   = allCerts.find(b => forge.pki.publicKeyToPem(b.cert.publicKey) === pubFromPriv)?.cert || allCerts[0]?.cert;
  if (!matchedCert) throw new Error("Certificado não encontrado");
  console.log("[nfse] Cert:", matchedCert.subject.getField("CN")?.value);
  const certDer = forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(matchedCert)).getBytes());
  return { key: privPem, certDer, cert: forge.pki.certificateToPem(matchedCert) };
}

// ─── Exclusive C14N manual: serializa elemento com namespaces próprios ────────
// Para o DPS, o infDPS herda xmlns do DPS pai — exc-c14n propaga apenas o usado
function excC14nInfDPS(xmlStr, refId) {
  // Extrai o conteúdo do infDPS (sem a tag externa DPS)
  const m = xmlStr.match(/<infDPS[\s\S]*?<\/infDPS>/);
  if (!m) throw new Error("infDPS não encontrado");
  let s = m[0];
  // Adiciona xmlns herdado do DPS (exclusive C14N propaga namespace usado pelo elemento)
  const nsMatch = xmlStr.match(/xmlns="([^"]+)"/);
  const ns = nsMatch ? nsMatch[1] : "http://www.sped.fazenda.gov.br/nfse";
  // C14N: atributos em ordem lexicográfica (Id < xmlns)
  // Remove xmlns se já tiver para reinserir na ordem correta
  s = s.replace(/<infDPS xmlns="[^"]*" /, "<infDPS ");
  s = s.replace(/<infDPS Id="/, `<infDPS Id="`);
  // Insere xmlns APÓS Id (ordem lexicográfica: Id vem antes de xmlns)
  s = s.replace(/(<infDPS Id="[^"]+")/, `$1 xmlns="${ns}"`);
  return s;
}

// ─── Assinatura XMLDSIG manual ────────────────────────────────────────────────
function assinarXML(xmlStr, pem) {
  const xmlSemProlog = xmlStr.replace(/^<\?xml[^?]*\?>\s*/m, "").trim();
  const idMatch      = xmlStr.match(/infDPS Id="([^"]+)"/);
  if (!idMatch) throw new Error("Id do infDPS não encontrado");
  const refId = idMatch[1];

  // 1. Digest do infDPS canonicalizado (exc-c14n com namespace herdado)
  const canonInfDPS = excC14nInfDPS(xmlSemProlog, refId);
  const digest      = crypto.createHash("sha256").update(canonInfDPS, "utf8").digest("base64");
  console.log("[nfse] CanonicalInfDPS:", canonInfDPS.slice(0, 100));
  console.log("[nfse] DigestValue:", digest);
    const signedInfo =
    `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    `<CanonicalizationMethod Algorithm="${c14nAlg}"/>` +
    `<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>` +
    `<Reference URI="#${refId}">` +
    `<Transforms>` +
    `<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` +
    `<Transform Algorithm="${c14nAlg}"/>` +
    `</Transforms>` +
    `<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
    `<DigestValue>${digest}</DigestValue>` +
    `</Reference>` +
    `</SignedInfo>`;

  // 3. Assina SignedInfo com RSA-SHA1
  const sign  = crypto.createSign("RSA-SHA1");
  sign.update(signedInfo, "utf8");
  const sigValue = sign.sign(pem.key, "base64");

  // 4. Monta bloco Signature
  const sigBlock =
    `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    signedInfo +
    `<SignatureValue>${sigValue}</SignatureValue>` +
    `<KeyInfo><X509Data><X509Certificate>${pem.certDer}</X509Certificate></X509Data></KeyInfo>` +
    `</Signature>`;

  // 5. Insere Signature após </infDPS>, antes de </DPS>
  const result = xmlSemProlog.replace("</DPS>", `\n${sigBlock}\n</DPS>`);
  return `<?xml version="1.0" encoding="UTF-8"?>\n` + result;
}

function sanitizarXML(str) {
  return str.replace(/^\uFEFF/, "").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
}

function gzipB64(str) {
  const buf = Buffer.from(sanitizarXML(str), "utf8");
  const b   = (buf[0]===0xEF && buf[1]===0xBB && buf[2]===0xBF) ? buf.slice(3) : buf;
  return new Promise((res, rej) => zlib.gzip(b, (e, x) => e ? rej(e) : res(x.toString("base64"))));
}

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
      res.on("end", () => { console.log("[nfse] HTTP:", res.statusCode, "| Body:", data.slice(0, 600)); resolve({ status: res.statusCode, body: data }); });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Timeout")); });
    req.write(buf); req.end();
  });
}

function parsear(body) {
  try {
    const j = JSON.parse(body);
    if (j.chaveAcesso || j.numero || j.numeroNFSe || j.nNFSe)
      return { sucesso: true, numeroNFSe: j.nNFSe || j.numero || j.numeroNFSe || "", chaveAcesso: j.chaveAcesso || "" };
    const msg = j.mensagem || j.message || (j.erros && j.erros[0]?.Descricao) || JSON.stringify(j).slice(0, 300);
    return { sucesso: false, erro: msg };
  } catch {
    const num = body.match(/<Numero>(\d+)<\/Numero>/)?.[1];
    if (num) return { sucesso: true, numeroNFSe: num };
    return { sucesso: false, erro: "Resposta: " + body.slice(0, 300) };
  }
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST")    return res.status(405).json({ error: "Method not allowed" });

  let body;
  try { body = await parseBody(req); } catch(e) { return res.status(400).json({ sucesso: false, erro: "Body inválido" }); }

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
  catch(e) { console.error("[nfse] Erro assinatura:", e.message); return res.status(400).json({ sucesso: false, erro: "Erro na assinatura: " + e.message }); }

  console.log("[nfse] XML assinado OK, length:", xmlAssinado.length);

  let gzB64;
  try { gzB64 = await gzipB64(xmlAssinado); }
  catch(e) { return res.status(500).json({ sucesso: false, erro: "Erro GZip: " + e.message }); }

  const hostname = API_URLS[ambiente] || API_URLS.producao;
  let resp;
  try { resp = await chamarAPI(gzB64, hostname, pem.cert, pem.key); }
  catch(e) { return res.status(502).json({ sucesso: false, erro: "Erro de conexão: " + e.message }); }

  return res.status(200).json(parsear(resp.body));
};
