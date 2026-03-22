// api/nfse.js — Portal Nacional NFS-e
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

  // Extrai TODOS os certificados
  const allCertBags = pfx.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  // Extrai chave privada
  const keyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || [];
  if (!keyBags.length) throw new Error("Chave privada não encontrada no certificado");
  const privateKey = keyBags[0].key;
  const privPem    = forge.pki.privateKeyToPem(privateKey);

  console.log("[nfse] PFX contém", allCertBags.length, "certificados");

  // Encontra o certificado que corresponde à chave privada
  // Compara a chave pública do cert com a derivada da chave privada
  let matchedCert = null;
  const publicKeyFromPriv = forge.pki.rsa.setPublicKey(privateKey.n, privateKey.e);
  const pubFromPrivPem    = forge.pki.publicKeyToPem(publicKeyFromPriv);

  for (const bag of allCertBags) {
    const certPubPem = forge.pki.publicKeyToPem(bag.cert.publicKey);
    if (certPubPem === pubFromPrivPem) {
      matchedCert = bag.cert;
      console.log("[nfse] Certificado encontrado:", bag.cert.subject.getField("CN")?.value);
      break;
    }
  }

  // Fallback: usa o primeiro se não encontrar par
  if (!matchedCert) {
    console.warn("[nfse] AVISO: Par chave/cert não encontrado, usando cert[0]");
    matchedCert = allCertBags[0].cert;
  }

  const certDer = forge.util.encode64(
    forge.asn1.toDer(forge.pki.certificateToAsn1(matchedCert)).getBytes()
  );

  return {
    cert:    forge.pki.certificateToPem(matchedCert),
    key:     privPem,
    certDer,
  };
}

function assinarXML(xmlStr, pem) {
  const xmlSemProlog = xmlStr.replace(/^<\?xml[^?]*\?>\s*/m, "").trim();
  const idMatch = xmlStr.match(/infDPS Id="([^"]+)"/);
  if (!idMatch) throw new Error("Id do infDPS não encontrado");
  const refId = idMatch[1];

  // Exclusive C14N avoids namespace inheritance from parent DPS element
  // (plain C14N would cause SignedInfo digest mismatch because portal inherits DPS xmlns)
  const sig = new SignedXml({
    privateKey: pem.key,
    signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    idAttribute: "Id",
  });

  sig.addReference({
    xpath: `//*[@Id="${refId}"]`,
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
    uri: `#${refId}`,
    isEmptyUri: false,
  });

  sig.keyInfoProvider = {
    getKeyInfo: () =>
      `<X509Data><X509Certificate>${pem.certDer}</X509Certificate></X509Data>`,
    getKey: () => Buffer.from(pem.key),
  };

  sig.computeSignature(xmlSemProlog, {
    location: { reference: "//*[local-name(.)='infDPS']", action: "after" },
  });

  return `<?xml version="1.0" encoding="UTF-8"?>\n` + sig.getSignedXml();
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
    console.error("[nfse] Erro assinatura:", e.message);
    return res.status(400).json({ sucesso: false, erro: "Erro na assinatura: " + e.message });
  }

  let gzB64;
  try { gzB64 = await gzipB64(xmlAssinado); }
  catch(e) { return res.status(500).json({ sucesso: false, erro: "Erro GZip: " + e.message }); }

  const hostname = API_URLS[ambiente] || API_URLS.producao;
  let resp;
  try { resp = await chamarAPI(gzB64, hostname, pem.cert, pem.key); }
  catch(e) { return res.status(502).json({ sucesso: false, erro: "Erro de conexão: " + e.message }); }

  return res.status(200).json(parsear(resp.body));
};
