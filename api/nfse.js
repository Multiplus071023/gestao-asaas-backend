// api/nfse.js — Integração Portal Nacional NFS-e (REST API mTLS)
// Baseado na documentação oficial: https://www.nfse.gov.br/swagger/contribuintesissqn
// Rota de emissão: POST /nfse (DPS → NFS-e síncrono)

const https  = require("https");
const zlib   = require("zlib");
const forge  = require("node-forge");

// ─── URLs da API REST do Portal Nacional ─────────────────────────────────────
const API_URLS = {
  producao:    "sefin.nfse.gov.br",
  homologacao: "sefin.producaorestrita.nfse.gov.br",
};
const API_PATH = "/SefinNacional/nfse";

// ─── Assina XML com certificado A1 (XMLDSIG + RSA-SHA1) ──────────────────────
function assinarXML(xmlStr, certBase64, certSenha) {
  const pfxB64 = certBase64.replace(/^data:[^;]+;base64,/, "");
  const pfxDer = forge.util.decode64(pfxB64);
  const pfx    = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(pfxDer), certSenha);

  const certBag = pfx.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag][0];
  const keyBag  = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
  const cert       = certBag.cert;
  const privateKey = keyBag.key;

  const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const certB64 = forge.util.encode64(certDer);

  // Digest do conteúdo XML
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
  const sigB64 = forge.util.encode64(privateKey.sign(md2));

  const sigBlock =
    `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    signedInfo +
    `<SignatureValue>${sigB64}</SignatureValue>` +
    `<KeyInfo><X509Data><X509Certificate>${certB64}</X509Certificate></X509Data></KeyInfo>` +
    `</Signature>`;

  return xmlStr.replace(/(<\/\w[^>]*>)\s*$/, sigBlock + "\n$1");
}

// ─── Extrai cert/key do PFX para usar no mTLS ────────────────────────────────
function extrairPemDoP12(certBase64, certSenha) {
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

// ─── Comprime XML em GZip e codifica em Base64 ───────────────────────────────
function gzipBase64(xmlStr) {
  return new Promise((resolve, reject) => {
    zlib.gzip(Buffer.from(xmlStr, "utf8"), (err, compressed) => {
      if (err) return reject(err);
      resolve(compressed.toString("base64"));
    });
  });
}

// ─── Chama a API REST do portal com mTLS ─────────────────────────────────────
function chamarAPI(xmlGzipB64, hostname, certPem, keyPem) {
  const body = JSON.stringify({ xml: xmlGzipB64 });
  const buf  = Buffer.from(body, "utf8");

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname,
      path: API_PATH,
      method: "POST",
      headers: {
        "Content-Type":   "application/json",
        "Accept":         "application/json",
        "Content-Length": buf.length,
      },
      cert: certPem,  // mTLS: certificado do cliente
      key:  keyPem,   // mTLS: chave privada do cliente
      timeout: 30000,
    }, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        console.log("[nfse] Status:", res.statusCode);
        console.log("[nfse] Response:", data.slice(0, 400));
        resolve({ status: res.statusCode, body: data });
      });
    });
    req.on("error",   reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Timeout ao conectar ao portal")); });
    req.write(buf);
    req.end();
  });
}

// ─── Parse da resposta ────────────────────────────────────────────────────────
function parsear(resBody) {
  try {
    const json = JSON.parse(resBody);
    // Resposta de sucesso contém chaveAcesso ou numero
    if (json.chaveAcesso || json.numero) {
      return {
        sucesso: true,
        numeroNFSe:   json.numero     || json.numeroNFSe || "",
        chaveAcesso:  json.chaveAcesso || "",
        linkNFSe:     json.linkNFSe   || "",
        xmlNFSe:      json.xml        || "",
      };
    }
    // Resposta de erro
    const msg = json.mensagem || json.message || json.descricao ||
                (json.erros && json.erros[0]?.descricao) || JSON.stringify(json);
    return { sucesso: false, erro: msg };
  } catch {
    // Tenta XML legado
    const num  = resBody.match(/<Numero>(\d+)<\/Numero>/)?.[1];
    const msg  = resBody.match(/<Mensagem>([^<]+)<\/Mensagem>/)?.[1];
    const link = resBody.match(/<LinkDownloadNFSe>([^<]+)<\/LinkDownloadNFSe>/)?.[1] || "";
    if (num) return { sucesso: true, numeroNFSe: num, linkNFSe: link };
    return { sucesso: false, erro: msg || "Resposta não reconhecida: " + resBody.slice(0, 200) };
  }
}

// ─── Handler principal ────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST")    return res.status(405).json({ error: "Method not allowed" });

  const { xmlDPS, certificado, ambiente } = req.body || {};

  if (!xmlDPS)              return res.status(400).json({ sucesso: false, erro: "xmlDPS obrigatório" });
  if (!certificado?.base64) return res.status(400).json({ sucesso: false, erro: "Certificado não informado" });
  if (!certificado?.senha)  return res.status(400).json({ sucesso: false, erro: "Senha do certificado não informada" });

  // 1. Extrai cert/key PEM para mTLS
  let pem;
  try {
    pem = extrairPemDoP12(certificado.base64, certificado.senha);
  } catch (e) {
    console.error("[nfse] Erro certificado:", e.message);
    return res.status(400).json({ sucesso: false, erro: "Erro no certificado: " + e.message });
  }

  // 2. Assina o XML
  let xmlAssinado;
  try {
    xmlAssinado = assinarXML(xmlDPS, certificado.base64, certificado.senha);
  } catch (e) {
    console.error("[nfse] Erro assinatura:", e.message);
    return res.status(400).json({ sucesso: false, erro: "Erro ao assinar: " + e.message });
  }

  // 3. GZip + Base64
  let xmlGzipB64;
  try {
    xmlGzipB64 = await gzipBase64(xmlAssinado);
  } catch (e) {
    return res.status(500).json({ sucesso: false, erro: "Erro ao comprimir XML: " + e.message });
  }

  // 4. Envia ao portal via mTLS
  const hostname = API_URLS[ambiente] || API_URLS.producao;
  let resposta;
  try {
    resposta = await chamarAPI(xmlGzipB64, hostname, pem.cert, pem.key);
  } catch (e) {
    console.error("[nfse] Erro conexão:", e.message);
    return res.status(502).json({ sucesso: false, erro: "Erro de conexão: " + e.message });
  }

  const resultado = parsear(resposta.body);
  return res.status(200).json(resultado);
};
