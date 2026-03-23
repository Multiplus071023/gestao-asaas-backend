// api/nfse.js — Portal Nacional NFS-e com C14N correto via xml-crypto
const https  = require("https");
const zlib   = require("zlib");
const crypto = require("crypto");
const forge  = require("node-forge");
const { ExclusiveCanonicalization } = require("xml-crypto");
const { DOMParser } = require("@xmldom/xmldom");

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

// Normaliza XML: remove quebras de linha e converte acentos para entidades XML
function normalizarXML(str) {
  // Remove quebras de linha e tabs (não permitidos em XML inline)
  str = str.replace(/\r\n/g, "").replace(/\r/g, "").replace(/\n/g, "").replace(/\t/g, " ");
  // Substitui espaços múltiplos por um único espaço
  str = str.replace(/ {2,}/g, " ");
  // Converte caracteres acentuados para entidades XML numéricas
  const acentos = {
    "à":"&#224;","á":"&#225;","â":"&#226;","ã":"&#227;","ä":"&#228;",
    "è":"&#232;","é":"&#233;","ê":"&#234;","ë":"&#235;",
    "ì":"&#236;","í":"&#237;","î":"&#238;","ï":"&#239;",
    "ò":"&#242;","ó":"&#243;","ô":"&#244;","õ":"&#245;","ö":"&#246;",
    "ù":"&#249;","ú":"&#250;","û":"&#251;","ü":"&#252;",
    "ç":"&#231;","ñ":"&#241;",
    "À":"&#192;","Á":"&#193;","Â":"&#194;","Ã":"&#195;","Ä":"&#196;",
    "È":"&#200;","É":"&#201;","Ê":"&#202;","Ë":"&#203;",
    "Ì":"&#204;","Í":"&#205;","Î":"&#206;","Ï":"&#207;",
    "Ò":"&#210;","Ó":"&#211;","Ô":"&#212;","Õ":"&#213;","Ö":"&#214;",
    "Ù":"&#217;","Ú":"&#218;","Û":"&#219;","Ü":"&#220;",
    "Ç":"&#199;","Ñ":"&#209;",
  };
  // Só converte dentro de valores de tags (não dentro dos atributos de estrutura)
  // Substitui apenas fora de tags XML
  str = str.replace(/>[^<]*/g, m => {
    let result = m;
    for (const [char, entity] of Object.entries(acentos)) {
      result = result.split(char).join(entity);
    }
    return result;
  });
  return str;
}

function assinarXML(xmlStr, pem) {
  // Normaliza antes de assinar: remove quebras e converte acentos
  xmlStr = normalizarXML(xmlStr);
  console.log("[nfse] XML normalizado (100):", xmlStr.slice(0, 100));
  // Log opSimpNac value
  const opSimpMatch = xmlStr.match(/<opSimpNac>([^<]+)<\/opSimpNac>/);
  console.log("[nfse] opSimpNac no XML:", opSimpMatch?.[1] || "NÃO ENCONTRADO");
  const xmlSemProlog = xmlStr.replace(/^<\?xml[^?]*\?>\s*/m, "").trim();
  const idMatch = xmlStr.match(/infDPS Id="([^"]+)"/);
  if (!idMatch) throw new Error("Id do infDPS não encontrado");
  const refId = idMatch[1];

  // 1. Canonical form do infDPS usando xml-crypto ExclusiveCanonicalization
  const parser = new DOMParser();
  const doc    = parser.parseFromString(xmlSemProlog, "text/xml");
  const infDPSNode = doc.getElementsByTagName("infDPS")[0];
  if (!infDPSNode) throw new Error("infDPS não encontrado no DOM");

  const c14n     = new ExclusiveCanonicalization();
  const canonical = c14n.process(infDPSNode, {});
  console.log("[nfse] Canonical (100):", canonical.slice(0, 100));

  // 2. Digest SHA-256
  const digest = crypto.createHash("sha256").update(canonical, "utf8").digest("base64");
  console.log("[nfse] DigestValue:", digest);

  // 3. SignedInfo
  const c14nAlg = "http://www.w3.org/2001/10/xml-exc-c14n#";
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

  // 4. Canonicaliza SignedInfo antes de assinar (C14N expande self-closing tags)
  const siDoc   = new DOMParser().parseFromString(signedInfo, "text/xml");
  const canonSI = new ExclusiveCanonicalization().process(siDoc.documentElement, {});
  console.log("[nfse] CanonSI (100):", canonSI.slice(0, 100));

  // Assina o SignedInfo canonicalizado com RSA-SHA1
  const sign = crypto.createSign("RSA-SHA1");
  sign.update(canonSI, "utf8");
  const sigValue = sign.sign(pem.key, "base64");

  // 5. Monta Signature e insere após </infDPS>
  const sigBlock =
    `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    signedInfo +
    `<SignatureValue>${sigValue}</SignatureValue>` +
    `<KeyInfo><X509Data><X509Certificate>${pem.certDer}</X509Certificate></X509Data></KeyInfo>` +
    `</Signature>`;

  return `<?xml version="1.0" encoding="UTF-8"?>\n` +
    xmlSemProlog.replace("</DPS>", `\n${sigBlock}\n</DPS>`);
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
      res.on("end", () => {
        console.log("[nfse] HTTP:", res.statusCode, "| Body:", data.slice(0,300));
        resolve({ status: res.statusCode, body: data });
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Timeout")); });
    req.write(buf); req.end();
  });
}

function parsear(body) {
  try {
    const j = JSON.parse(body);
    // HTTP 201 = sucesso. Portal retorna chaveAcesso (50 chars) e nfseXmlGZipB64
    if (j.chaveAcesso || j.idDps || j.nNFSe || j.numero || j.numeroNFSe) {
      // Extrai número da NFS-e do idDps (formato: NFS + chave 50 chars)
      // ou da chaveAcesso diretamente
      const chave = j.chaveAcesso || "";
      // O número da NFS-e fica nos dígitos 28-34 da chave de acesso (7 dígitos)
      const nNFSe = j.nNFSe || j.numero || j.numeroNFSe ||
        (chave.length >= 34 ? String(+chave.slice(27, 34)) : chave.slice(0,10)) || "";
      return {
        sucesso: true,
        numeroNFSe: nNFSe,
        chaveAcesso: chave,
        nfseXmlGZipB64: j.nfseXmlGZipB64 || "",
        idDps: j.idDps || "",
      };
    }
    const msg = j.mensagem || j.message || (j.erros && j.erros[0]?.Descricao) || JSON.stringify(j).slice(0,300);
    return { sucesso: false, erro: msg };
  } catch {
    const num = body.match(/<Numero>(\d+)<\/Numero>/)?.[1];
    if (num) return { sucesso: true, numeroNFSe: num };
    return { sucesso: false, erro: "Resposta: " + body.slice(0,300) };
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

  let gzB64;
  try { gzB64 = await gzipB64(xmlAssinado); }
  catch(e) { return res.status(500).json({ sucesso: false, erro: "Erro GZip: " + e.message }); }

  const hostname = API_URLS[ambiente] || API_URLS.producao;
  let resp;
  try { resp = await chamarAPI(gzB64, hostname, pem.cert, pem.key); }
  catch(e) { return res.status(502).json({ sucesso: false, erro: "Erro de conexão: " + e.message }); }

  return res.status(200).json(parsear(resp.body));
};
