// api/nfse-pdf.js — Vercel Serverless Function
// Baixa o PDF de uma NFS-e do Portal Nacional usando certificado A1
// Deploy: cole este arquivo em /api/nfse-pdf.js no seu projeto Vercel

const https = require("https");
const forge = require("node-forge");

// Converte certificado PFX base64 → { cert, key } em PEM
function pfxToPem(pfxBase64, senha) {
  const pfxDer = Buffer.from(pfxBase64, "base64");
  const pfxAsn1 = forge.asn1.fromDer(pfxDer.toString("binary"));
  const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, senha);

  let certPem = "", keyPem = "";

  for (const safeContent of pfx.safeContents) {
    for (const safeBag of safeContent.safeBags) {
      if (safeBag.type === forge.pki.oids.certBag) {
        certPem = forge.pki.certificateToPem(safeBag.cert);
      } else if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag ||
                 safeBag.type === forge.pki.oids.keyBag) {
        keyPem = forge.pki.privateKeyToPem(safeBag.key);
      }
    }
  }
  return { cert: certPem, key: keyPem };
}

module.exports = async function handler(req, res) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ erro: "Método não permitido" });

  try {
    const { chaveAcesso, certificado, ambiente } = req.body;

    if (!chaveAcesso || chaveAcesso.length !== 50) {
      return res.status(400).json({ erro: "chaveAcesso inválida (deve ter 50 dígitos)" });
    }
    if (!certificado?.base64 || !certificado?.senha) {
      return res.status(400).json({ erro: "Certificado não informado" });
    }

    // Extrai cert/key do PFX
    const { cert, key } = pfxToPem(certificado.base64, certificado.senha);

    // URL do portal (produção ou homologação)
    const prod = !ambiente || ambiente === "producao";
    const host = prod ? "sefin.nfse.gov.br" : "hom-sefin.nfse.gov.br";
    const path = `/api/core/v1/nfse/${chaveAcesso}/pdf`;

    // Faz a requisição com mTLS
    const pdfBuffer = await new Promise((resolve, reject) => {
      const options = {
        hostname: host,
        port: 443,
        path,
        method: "GET",
        cert,
        key,
        rejectUnauthorized: true,
        headers: {
          "Accept": "application/pdf",
          "Content-Type": "application/json",
        },
      };

      const reqPortal = https.request(options, (resp) => {
        if (resp.statusCode !== 200) {
          let body = "";
          resp.on("data", d => body += d);
          resp.on("end", () => reject(new Error("Portal retornou " + resp.statusCode + ": " + body.slice(0, 200))));
          return;
        }
        const chunks = [];
        resp.on("data", chunk => chunks.push(chunk));
        resp.on("end", () => resolve(Buffer.concat(chunks)));
      });

      reqPortal.on("error", reject);
      reqPortal.setTimeout(20000, () => { reqPortal.destroy(); reject(new Error("Timeout na requisição ao portal")); });
      reqPortal.end();
    });

    // Retorna o PDF
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="NFSe_${chaveAcesso.slice(27, 34)}.pdf"`);
    res.setHeader("Content-Length", pdfBuffer.length);
    return res.status(200).send(pdfBuffer);

  } catch (e) {
    console.error("[nfse-pdf]", e.message);
    return res.status(500).json({ erro: e.message });
  }
};
