// api/nfse-cancelar.js — Cancelamento de NFS-e Portal Nacional
const https  = require("https");
const zlib   = require("zlib");
const forge  = require("node-forge");
const crypto = require("crypto");
const { ExclusiveCanonicalization } = require("xml-crypto");
const { DOMParser } = require("@xmldom/xmldom");

const API_URLS = {
  producao:    "sefin.nfse.gov.br",
  homologacao: "sefin.producaorestrita.nfse.gov.br",
};

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
  const certDer = forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(matchedCert)).getBytes());
  return { key: privPem, certDer, cert: forge.pki.certificateToPem(matchedCert) };
}

function assinarXML(xmlStr, pem) {
  const xmlSemProlog = xmlStr.replace(/^<\?xml[^?]*\?>\s*/m, "").trim();
  const idMatch = xmlStr.match(/infEvt Id="([^"]+)"/);
  if (!idMatch) throw new Error("Id do CanNFSe não encontrado");
  const refId = idMatch[1];

  const parser = new DOMParser();
  const doc    = parser.parseFromString(xmlSemProlog, "text/xml");
  const node   = doc.getElementsByTagName("infEvt")[0];
  if (!node) throw new Error("infEvt não encontrado no DOM");

  const c14n      = new ExclusiveCanonicalization();
  const canonical = c14n.process(node, {});
  const digest    = crypto.createHash("sha256").update(canonical, "utf8").digest("base64");

  const c14nAlg   = "http://www.w3.org/2001/10/xml-exc-c14n#";
  const signedInfo =
    `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    `<CanonicalizationMethod Algorithm="${c14nAlg}"/>` +
    `<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>` +
    `<Reference URI="#${refId}">` +
    `<Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` +
    `<Transform Algorithm="${c14nAlg}"/></Transforms>` +
    `<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
    `<DigestValue>${digest}</DigestValue></Reference></SignedInfo>`;

  const siDoc   = new DOMParser().parseFromString(signedInfo, "text/xml");
  const canonSI = new ExclusiveCanonicalization().process(siDoc.documentElement, {});
  const sign    = crypto.createSign("RSA-SHA1");
  sign.update(canonSI, "utf8");
  const sigValue = sign.sign(pem.key, "base64");

  const sigBlock =
    `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
    signedInfo +
    `<SignatureValue>${sigValue}</SignatureValue>` +
    `<KeyInfo><X509Data><X509Certificate>${pem.certDer}</X509Certificate></X509Data></KeyInfo>` +
    `</Signature>`;

  return `<?xml version="1.0" encoding="UTF-8"?>\n` +
    xmlSemProlog.replace("</PedEvtNFSe>", `\n${sigBlock}\n</PedEvtNFSe>`);
}

function gzipB64(str) {
  const buf = Buffer.from(str.replace(/^\uFEFF/, ""), "utf8");
  return new Promise((res, rej) => zlib.gzip(buf, (e, x) => e ? rej(e) : res(x.toString("base64"))));
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST")    return res.status(405).json({ error: "Method not allowed" });

  let body;
  try { body = await parseBody(req); } catch(e) { return res.status(400).json({ sucesso: false, erro: "Body inválido" }); }

  const { chaveAcesso, motivo, certificado, ambiente } = body;
  if (!chaveAcesso) return res.status(400).json({ sucesso: false, erro: "chaveAcesso obrigatória" });
  if (!certificado?.base64) return res.status(400).json({ sucesso: false, erro: "Certificado não informado" });

  let pem;
  try { pem = extrairPem(certificado.base64, certificado.senha); }
  catch(e) { return res.status(400).json({ sucesso: false, erro: "Certificado inválido: " + e.message }); }

  // Extrai CNPJ e cMun da chave de acesso (50 chars)
  // cMun(7)+tpAmb(1)+tpInsc(1)+CNPJ(14)+nNFSe(13)+...
  const cMun = chaveAcesso.slice(0, 7);
  const CNPJ = chaveAcesso.slice(9, 23);
  const nNFSe = chaveAcesso.slice(23, 36);
  const tpAmb = ambiente === "homologacao" ? "2" : "1";
  const idCan = `ID${chaveAcesso}`;  // spec: literal "ID" + 50 chars chave = 52 chars

  const _now = new Date();
  const _off = _now.getTimezoneOffset();
  const _loc = new Date(_now.getTime() - _off * 60000);
  const dhEvt = _loc.toISOString().slice(0, 19) + "-03:00";
  const xmlCan = `<?xml version="1.0" encoding="UTF-8"?>
<PedEvtNFSe versao="1.00" xmlns="http://www.sped.fazenda.gov.br/nfse">
  <infEvt Id="${idCan}">
    <tpAmb>${tpAmb}</tpAmb>
    <verAplic>GestaoAsaas_1.0</verAplic>
    <dhEvt>${dhEvt}</dhEvt>
    <CNPJ>${CNPJ}</CNPJ>
    <chNFSe>${chaveAcesso}</chNFSe>
    <tpEvt>1</tpEvt>
    <nSeqEvt>1</nSeqEvt>
    <detEvt>
      <tpEvtCan>1</tpEvtCan>
      <xJust>${(motivo||"Erro na emissão").slice(0,255)}</xJust>
    </detEvt>
  </infEvt>
</PedEvtNFSe>`;

  console.log("[cancel] xmlCan:", xmlCan.slice(0, 400));
  let xmlAssinado;
  try { xmlAssinado = assinarXML(xmlCan, pem); }
  catch(e) { return res.status(400).json({ sucesso: false, erro: "Erro na assinatura: " + e.message }); }
  console.log("[cancel] xmlAssinado (200):", xmlAssinado.slice(0, 200));

  let gzB64;
  try { gzB64 = await gzipB64(xmlAssinado); }
  catch(e) { return res.status(500).json({ sucesso: false, erro: "Erro GZip: " + e.message }); }

  const hostname = API_URLS[ambiente] || API_URLS.producao;
  const reqBody  = JSON.stringify({ pedEvtNFSeXmlGZipB64: gzB64 });
  console.log("[cancel] JSON body size:", reqBody.length, "| field: pedEvtNFSeXmlGZipB64");
  const buf      = Buffer.from(reqBody, "utf8");

  return new Promise((resolve) => {
    const apiReq = https.request({
      hostname, path: `/sefinnacional/nfse/${chaveAcesso}/eventos`, method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "Content-Length": buf.length },
      cert: pem.cert, key: pem.key, timeout: 30000,
    }, (apiRes) => {
      let data = "";
      apiRes.on("data", c => data += c);
      apiRes.on("end", () => {
        console.log("[cancel] HTTP:", apiRes.statusCode, "| Body:", data.slice(0, 800));
        try {
          const j = JSON.parse(data);
          if (apiRes.statusCode === 200 || apiRes.statusCode === 201) {
            resolve(res.status(200).json({ sucesso: true }));
          } else {
            const msg = (j.erros && j.erros[0]?.Descricao) || j.mensagem || data.slice(0, 200);
            resolve(res.status(200).json({ sucesso: false, erro: msg }));
          }
        } catch {
          resolve(res.status(200).json({ sucesso: false, erro: data.slice(0, 200) }));
        }
      });
    });
    apiReq.on("error", e => resolve(res.status(502).json({ sucesso: false, erro: e.message })));
    apiReq.on("timeout", () => { apiReq.destroy(); resolve(res.status(504).json({ sucesso: false, erro: "Timeout" })); });
    apiReq.write(buf);
    apiReq.end();
  });
};
