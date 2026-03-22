// api/nfse.js — Portal Nacional NFS-e com xml-crypto v6 (API correta)
const https  = require("https");
const zlib   = require("zlib");
const forge  = require("node-forge");
const { SignedXml } = require("xml-crypto");

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
  const certBag = pfx.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag][0];
  const keyBag  = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
  return {
    cert:    forge.pki.certificateToPem(certBag.cert),
    key:     forge.pki.privateKeyToPem(keyBag.key),
    certDer: forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(certBag.cert)).getBytes()),
  };
}

// ─── Assina com xml-crypto v6 ──────────────────────────────────────────────────
function assinarXML(xmlStr, pem) {
  // Remove XML prolog para xml-crypto processar
  const xmlSemProlog = xmlStr.replace(/^<\?xml[^?]*\?>\s*/m, "").trim();

  // Extrai o Id do infDPS
  const idMatch = xmlStr.match(/infDPS Id="([^"]+)"/);
  if (!idMatch) throw new Error("Id do infDPS não encontrado");
  const refId = idMatch[1];

  // Monta SignedXml com as configurações corretas para o portal nacional
  const sig = new SignedXml({
    privateKey: pem.key,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
    idAttribute: "Id",  // IMPORTANTE: atributo Id com I maiúsculo
  });

  // Adiciona referência ao infDPS
  sig.addReference({
    xpath: `//*[@Id="${refId}"]`,
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
    ],
    uri: `#${refId}`,
    isEmptyUri: false,
  });

  // KeyInfo com certificado X509
  sig.keyInfoProvider = {
    getKeyInfo: () =>
      `<X509Data><X509Certificate>${pem.certDer}</X509Certificate></X509Data>`,
    getKey: () => Buffer.from(pem.key),
  };

  // Assina — coloca a assinatura DENTRO do elemento infDPS, após seu conteúdo
  sig.computeSignature(xmlSemProlog, {
    location: {
      reference: "//*[local-name(.)='infDPS']",
      action: "after",  // coloca APÓS </infDPS>, dentro de <DPS>
    },
  });

  const signed = sig.getSignedXml();
  console.log("[nfse] XML assinado (200 chars):", signed.slice(0, 200));
  return `<?xml version="1.0" encoding="UTF-8"?>\n` + signed;
}

function sanitizarXML(str) {
  str = str.replace(/^\uFEFF/, "");
  str = str.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
  return str;
}

function gzipB64(str) {
  const buf = Buffer.from(sanitizarXML(str), "utf8");
  const semBOM = (buf[0]===0xEF && buf[1]===0xBB && buf[2]===0xBF) ? buf.slice(3) : buf;
  return new Promise((res, rej) =>
    zlib.gzip(semBOM, (e, b) => e ? rej(e) : res(b.toString("base64")))
  );
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
  catch(e) {
    console.error("[nfse] Erro assinatura:", e.message, e.stack);
    return res.status(400).json({ sucesso: false, erro: "Erro na assinatura: " + e.message });
  }
  // Log estrutura do XML assinado
  const sigPos = xmlAssinado.indexOf("<Signature");
  const infClose = xmlAssinado.indexOf("</infDPS>");
  const dpsClose = xmlAssinado.indexOf("</DPS>");
  console.log("[nfse] Estrutura assinatura: </infDPS>@"+infClose+" <Signature@"+sigPos+" </DPS>@"+dpsClose);
  console.log("[nfse] DigestValue:", xmlAssinado.match(/<DigestValue>([^<]{20})/)?.[1]);
  console.log("[nfse] xml-crypto version:", require("xml-crypto/package.json").version);
  console.log("[nfse] === XML ASSINADO COMPLETO ===");
  console.log(xmlAssinado);
  console.log("[nfse] === FIM XML ASSINADO ===");

  let gzB64;
  try { gzB64 = await gzipB64(xmlAssinado); }
  catch(e) { return res.status(500).json({ sucesso: false, erro: "Erro GZip: " + e.message }); }

  const hostname = API_URLS[ambiente] || API_URLS.producao;
  let resp;
  try { resp = await chamarAPI(gzB64, hostname, pem.cert, pem.key); }
  catch(e) { return res.status(502).json({ sucesso: false, erro: "Erro de conexão: " + e.message }); }

  return res.status(200).json(parsear(resp.body));
};
