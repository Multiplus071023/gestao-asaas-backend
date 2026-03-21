// api/nfse.js — Vercel Serverless Function para integração Portal Nacional NFS-e
// Adicionar ao projeto Vercel em /api/nfse.js

const https = require("https");
const crypto = require("crypto");
const forge = require("node-forge"); // npm install node-forge

// ─── URLs DO PORTAL NACIONAL NFS-e ────────────────────────────────────────────
const PORTAL_URLS = {
  producao: "https://www.nfse.gov.br/SistemaIntegrado/Nfse.svc",
  homologacao: "https://hom.nfse.gov.br/SistemaIntegrado/Nfse.svc",
};

// ─── ASSINA XML COM CERTIFICADO A1 (PKCS#12) ─────────────────────────────────
function assinarXML(xmlStr, certBase64, certSenha) {
  try {
    // Decodifica o certificado PFX/P12 de base64
    const pfxB64 = certBase64.replace(/^data:[^;]+;base64,/, "");
    const pfxDer = forge.util.decode64(pfxB64);
    const pfxAsn1 = forge.asn1.fromDer(pfxDer);
    const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, certSenha);

    // Extrai chave privada e certificado
    const bags = pfx.getBags({ bagType: forge.pki.oids.certBag });
    const certBag = bags[forge.pki.oids.certBag][0];
    const cert = certBag.cert;

    const keyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
    const privateKey = keyBag.key;

    // Gera ID para o elemento de assinatura
    const signatureId = "Sig_" + Date.now();
    const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const certB64 = forge.util.encode64(certDer);
    const certFingerprint = forge.md.sha1.create();
    certFingerprint.update(certDer);
    const certFp = forge.util.encode64(certFingerprint.digest().getBytes());

    // Canonicaliza o XML (C14N simplificado)
    const xmlToSign = xmlStr.trim();
    const md = forge.md.sha1.create();
    md.update(xmlToSign, "utf8");
    const digestBytes = md.digest().getBytes();
    const digestB64 = forge.util.encode64(digestBytes);

    // Assina com RSA-SHA1
    const md2 = forge.md.sha1.create();
    const signedInfo = `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
      `<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>` +
      `<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>` +
      `<Reference URI="">` +
      `<Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms>` +
      `<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>` +
      `<DigestValue>${digestB64}</DigestValue>` +
      `</Reference></SignedInfo>`;

    md2.update(signedInfo, "utf8");
    const signatureBytes = privateKey.sign(md2);
    const signatureB64 = forge.util.encode64(signatureBytes);

    // Monta o bloco de assinatura
    const signatureBlock = `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="${signatureId}">
  ${signedInfo}
  <SignatureValue>${signatureB64}</SignatureValue>
  <KeyInfo>
    <X509Data>
      <X509Certificate>${certB64}</X509Certificate>
    </X509Data>
  </KeyInfo>
</Signature>`;

    // Injeta a assinatura antes do último fechamento de tag
    const xmlAssinado = xmlStr.replace(/(<\/[^>]+>)\s*$/, signatureBlock + "\n$1");
    return { sucesso: true, xml: xmlAssinado };
  } catch (e) {
    return { sucesso: false, erro: "Erro ao assinar XML: " + e.message };
  }
}

// ─── CHAMA O PORTAL NACIONAL NFS-e VIA SOAP ──────────────────────────────────
async function chamarPortal(xmlAssinado, ambiente) {
  const url = PORTAL_URLS[ambiente] || PORTAL_URLS.producao;

  const soapEnvelope = `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <RecepcionarLoteRps xmlns="http://www.abrasf.org.br/nfse.xsd">
      <nfseCabecMsg>
        <![CDATA[<?xml version="1.0" encoding="UTF-8"?>
<cabecalho versao="2.01" xmlns="http://www.abrasf.org.br/nfse.xsd">
  <versaoDados>2.01</versaoDados>
</cabecalho>]]>
      </nfseCabecMsg>
      <nfseDadosMsg>
        <![CDATA[${xmlAssinado}]]>
      </nfseDadosMsg>
    </RecepcionarLoteRps>
  </soap12:Body>
</soap12:Envelope>`;

  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "Content-Length": Buffer.byteLength(soapEnvelope, "utf8"),
      },
    };

    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.write(soapEnvelope, "utf8");
    req.end();
  });
}

// ─── PARSE DA RESPOSTA DO PORTAL ──────────────────────────────────────────────
function parsearResposta(xmlResposta) {
  const erroMatch = xmlResposta.match(/<Mensagem>([^<]+)<\/Mensagem>/);
  const numeroMatch = xmlResposta.match(/<Numero>(\d+)<\/Numero>/);
  const codigoMatch = xmlResposta.match(/<Codigo>(\d+)<\/Codigo>/);
  const linkMatch = xmlResposta.match(/<LinkDownloadNFSe>([^<]+)<\/LinkDownloadNFSe>/);

  if (erroMatch && !numeroMatch) {
    return { sucesso: false, erro: erroMatch[1], codigo: codigoMatch?.[1] };
  }
  return {
    sucesso: true,
    numeroNFSe: numeroMatch?.[1],
    linkNFSe: linkMatch?.[1] || "",
    xmlResposta,
  };
}

// ─── HANDLER PRINCIPAL ────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    const {
      xmlRPS,           // XML do RPS já montado pelo frontend
      certificado,      // { base64: "...", senha: "..." }
      ambiente,         // "producao" | "homologacao"
    } = req.body;

    if (!xmlRPS) return res.status(400).json({ sucesso: false, erro: "xmlRPS é obrigatório" });
    if (!certificado?.base64) return res.status(400).json({ sucesso: false, erro: "Certificado não informado" });
    if (!certificado?.senha) return res.status(400).json({ sucesso: false, erro: "Senha do certificado não informada" });

    // 1. Assinar XML
    const assinatura = assinarXML(xmlRPS, certificado.base64, certificado.senha);
    if (!assinatura.sucesso) {
      return res.status(400).json({ sucesso: false, erro: assinatura.erro });
    }

    // 2. Enviar ao portal
    const resposta = await chamarPortal(assinatura.xml, ambiente || "producao");

    // 3. Parsear resposta
    const resultado = parsearResposta(resposta.body);
    return res.status(200).json(resultado);

  } catch (e) {
    return res.status(500).json({ sucesso: false, erro: e.message });
  }
};
