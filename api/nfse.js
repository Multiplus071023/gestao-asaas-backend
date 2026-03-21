// api/nfse.js — Vercel Serverless Function para integração Portal Nacional NFS-e
const https = require("https");
const forge = require("node-forge");

const PORTAL_URLS = {
  producao:    "https://www.nfse.gov.br/SistemaIntegrado/Nfse.svc",
  homologacao: "https://hom.nfse.gov.br/SistemaIntegrado/Nfse.svc",
};

// ─── Assina XML com certificado A1 (PKCS#12) ─────────────────────────────────
function assinarXML(xmlStr, certBase64, certSenha) {
  const pfxB64 = certBase64.replace(/^data:[^;]+;base64,/, "");
  const pfxDer = forge.util.decode64(pfxB64);
  const pfxAsn1 = forge.asn1.fromDer(pfxDer);
  const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, certSenha);

  const certBags = pfx.getBags({ bagType: forge.pki.oids.certBag });
  const cert = certBags[forge.pki.oids.certBag][0].cert;

  const keyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const privateKey = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0].key;

  const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const certB64 = forge.util.encode64(certDer);

  // Digest do XML
  const md = forge.md.sha1.create();
  md.update(forge.util.encodeUtf8(xmlStr));
  const digestB64 = forge.util.encode64(md.digest().getBytes());

  // SignedInfo
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
  const sigB64 = forge.util.encode64(privateKey.sign(md2));

  const sigBlock =
    `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    signedInfo +
    `<SignatureValue>${sigB64}</SignatureValue>` +
    `<KeyInfo><X509Data><X509Certificate>${certB64}</X509Certificate></X509Data></KeyInfo>` +
    `</Signature>`;

  // Injeta assinatura antes do último tag de fechamento
  return xmlStr.replace(/(<\/\w[^>]*>)\s*$/, sigBlock + "\n$1");
}

// ─── Envia SOAP ao portal ─────────────────────────────────────────────────────
function enviarSOAP(xmlAssinado, url) {
  const soap =
    `<?xml version="1.0" encoding="utf-8"?>` +
    `<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ` +
    `xmlns:xsd="http://www.w3.org/2001/XMLSchema" ` +
    `xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">` +
    `<soap12:Body><RecepcionarLoteRps xmlns="http://www.abrasf.org.br/nfse.xsd">` +
    `<nfseCabecMsg><![CDATA[<?xml version="1.0" encoding="UTF-8"?>` +
    `<cabecalho versao="2.01" xmlns="http://www.abrasf.org.br/nfse.xsd">` +
    `<versaoDados>2.01</versaoDados></cabecalho>]]></nfseCabecMsg>` +
    `<nfseDadosMsg><![CDATA[${xmlAssinado}]]></nfseDadosMsg>` +
    `</RecepcionarLoteRps></soap12:Body></soap12:Envelope>`;

  const buf = Buffer.from(soap, "utf8");
  const urlObj = new URL(url);

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: "POST",
      headers: {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "Content-Length": buf.length,
      },
      timeout: 20000,
    }, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Timeout ao conectar ao portal")); });
    req.write(buf);
    req.end();
  });
}

// ─── Parse da resposta do portal ─────────────────────────────────────────────
function parsearResposta(xml) {
  const numero  = xml.match(/<Numero>(\d+)<\/Numero>/)?.[1];
  const mensagem = xml.match(/<Mensagem>([^<]+)<\/Mensagem>/)?.[1];
  const codigo  = xml.match(/<Codigo>(\d+)<\/Codigo>/)?.[1];
  const link    = xml.match(/<LinkDownloadNFSe>([^<]+)<\/LinkDownloadNFSe>/)?.[1] || "";

  if (numero) return { sucesso: true, numeroNFSe: numero, linkNFSe: link };
  return { sucesso: false, erro: mensagem || "Resposta não reconhecida do portal", codigo, xmlResposta: xml.slice(0, 500) };
}

// ─── Handler ──────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST")    return res.status(405).json({ error: "Method not allowed" });

  const { xmlRPS, certificado, ambiente } = req.body || {};

  if (!xmlRPS)              return res.status(400).json({ sucesso: false, erro: "xmlRPS é obrigatório" });
  if (!certificado?.base64) return res.status(400).json({ sucesso: false, erro: "Certificado não informado" });
  if (!certificado?.senha)  return res.status(400).json({ sucesso: false, erro: "Senha do certificado não informada" });

  // 1. Assinar
  let xmlAssinado;
  try {
    xmlAssinado = assinarXML(xmlRPS, certificado.base64, certificado.senha);
  } catch (e) {
    console.error("[nfse] Erro ao assinar XML:", e.message);
    return res.status(400).json({ sucesso: false, erro: "Erro ao assinar certificado: " + e.message });
  }

  // 2. Enviar ao portal
  const url = PORTAL_URLS[ambiente] || PORTAL_URLS.producao;
  let resposta;
  try {
    resposta = await enviarSOAP(xmlAssinado, url);
    console.log("[nfse] Portal status:", resposta.status);
    console.log("[nfse] Portal response:", resposta.body.slice(0, 300));
  } catch (e) {
    console.error("[nfse] Erro ao chamar portal:", e.message);
    return res.status(502).json({ sucesso: false, erro: "Erro de conexão com o portal: " + e.message });
  }

  // 3. Parsear e retornar
  const resultado = parsearResposta(resposta.body);
  return res.status(200).json(resultado);
};
