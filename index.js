const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const xmlEncryption = require('xml-encryption');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

const IDP_ENTITY_ID = 'https://sso-uat1.akadigital.net/metadata';
const IDP_SSO_URL = 'https://sso-uat1.akadigital.net/sso';

const AF_ENTITY_ID = 'https://hq1.appsflyer.com';
const AF_ACS_URL = 'https://hq1.appsflyer.com/auth/sso/saml/callback';

console.log('[Init] Khởi động Server IdP (Hỗ trợ Ký số & Mã hóa AppsFlyer)...');

// 1. Endpoint Metadata
app.get('/metadata', (req, res) => {
  try {
    const certPath = path.join(__dirname, 'cert.pem');
    const certificate = fs.readFileSync(certPath, 'utf8');
    const certClean = certificate.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/[\r\n]+/g, '');

    res.type('application/xml');
    res.send(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" 
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#" 
                     entityID="${IDP_ENTITY_ID}">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>${certClean}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${IDP_SSO_URL}"/>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${IDP_SSO_URL}"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>`);
  } catch (err) {
    res.status(500).send('Lỗi đọc metadata: ' + err.message);
  }
});

// 2. Giao diện Login
app.get('/sso', (req, res) => {
  const { SAMLRequest, RelayState } = req.query;
  res.send(`
    <form method="POST" action="/sso" style="margin: 100px auto; width: 360px; font-family: sans-serif; padding: 20px; border: 1px solid #ccc; border-radius: 8px;">
      <h3 style="text-align: center;">AKA Digital SSO</h3>
      <input type="hidden" name="SAMLRequest" value="${SAMLRequest || ''}" />
      <input type="hidden" name="RelayState" value="${RelayState || ''}" />
      <div style="margin-bottom: 15px;">
        <label>Tài khoản đăng nhập:</label><br/>
        <input type="text" name="email" value="truc.nguyen@akadigital.vn" style="width: 100%; padding: 8px; margin-top: 5px; box-sizing: border-box;" required />
      </div>
      <button type="submit" style="width: 100%; padding: 10px; background: #000; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">Xác thực & Vào AppsFlyer</button>
    </form>
  `);
});

// 3. Xử lý tạo SAML Response, Ký số, Mã hóa và gửi về AppsFlyer
app.post('/sso', async (req, res) => {
  const { SAMLRequest, RelayState, email } = req.body;
  const userEmail = (email || 'truc.nguyen@akadigital.vn').trim();

  try {
    const privateKeyPath = path.join(__dirname, 'key.pem');
    const certificatePath = path.join(__dirname, 'cert.pem');
    const afEncryptionKeyPath = path.join(__dirname, 'ca.pem');
    
    const privateKeyRaw = fs.readFileSync(privateKeyPath, 'utf8');
    const certificate = fs.readFileSync(certificatePath, 'utf8');
    const afEncryptionKey = fs.readFileSync(afEncryptionKeyPath, 'utf8');

    let acsUrl = AF_ACS_URL;
    let inResponseTo = '_' + crypto.randomBytes(16).toString('hex');

    if (SAMLRequest) {
      try {
        const buffer = Buffer.from(SAMLRequest, 'base64');
        let requestXml = '';
        try { requestXml = zlib.inflateRawSync(buffer).toString('utf8'); } 
        catch (e) { requestXml = buffer.toString('utf8'); }

        const acsMatch = requestXml.match(/AssertionConsumerServiceURL="([^"]+)"/);
        if (acsMatch && acsMatch[1]) acsUrl = acsMatch[1];

        const idMatch = requestXml.match(/ID="([^"]+)"/);
        if (idMatch && idMatch[1]) inResponseTo = idMatch[1];
      } catch (err) {
        console.error('Không parse được SAMLRequest, dùng ACS URL mặc định');
      }
    }

    const now = Date.now() - 180000; // Bù trừ clock skew 3 phút
    const issueInstant = new Date(now).toISOString();
    const responseId = '_' + crypto.randomBytes(16).toString('hex');
    const assertionId = '_' + crypto.randomBytes(16).toString('hex');
    const notOnOrAfter = new Date(now + 600000).toISOString();
    const certClean = certificate.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/[\r\n]+/g, '');

    // Tạo Assertion XML chuẩn
    const assertionXml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}">
    <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
    <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${userEmail}</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData InResponseTo="${inResponseTo}" NotOnOrAfter="${notOnOrAfter}" Recipient="${acsUrl}"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${issueInstant}" NotOnOrAfter="${notOnOrAfter}">
        <saml:AudienceRestriction>
            <saml:Audience>${AF_ENTITY_ID}</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${assertionId}">
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
        </saml:AuthnContext>
    </saml:AuthnStatement>
</saml:Assertion>`;

    // Ký số Assertion
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(assertionXml);
    signer.end();
    const signatureValue = signer.sign(privateKeyRaw, 'base64');

    const signedAssertion = assertionXml.replace(
      `</saml:Assertion>`,
      `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#${assertionId}">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>${crypto.createHash('sha256').update(assertionXml).digest('base64')}</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>${signatureValue}</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>${certClean}</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature></saml:Assertion>`
    );

    // Mã hóa Assertion đã ký bằng Encryption key của AppsFlyer
    const encryptedAssertionXml = await new Promise((resolve, reject) => {
      xmlEncryption.encrypt(signedAssertion, {
        rsa_encryption: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
        aes_encryption: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
        public_key: afEncryptionKey,
        key_info_include_cert: true
      }, (err, encrypted) => {
        if (err) reject(err);
        else resolve(encrypted);
      });
    });

    // Gói EncryptedAssertion vào Response chính
    const samlResponseXml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="${responseId}" Version="2.0" IssueInstant="${issueInstant}" Destination="${acsUrl}" InResponseTo="${inResponseTo}">
    <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:EncryptedAssertion>
        ${encryptedAssertionXml}
    </saml:EncryptedAssertion>
</samlp:Response>`;

    const samlResponseBase64 = Buffer.from(samlResponseXml).toString('base64');

    res.send(`
      <html>
        <body onload="document.forms[0].submit()">
          <form method="POST" action="${acsUrl}">
            <input type="hidden" name="SAMLResponse" value="${samlResponseBase64}" />
            <input type="hidden" name="RelayState" value="${RelayState || ''}" />
          </form>
          <p style="text-align:center; margin-top: 50px;">Đang gửi thông tin mã hóa bảo mật cho <b>${userEmail}</b> tới AppsFlyer...</p>
        </body>
      </html>
    `);

  } catch (error) {
    console.error('[SAML Encryption & Signing Error]:', error);
    res.status(500).send('Lỗi xử lý SAML Response: ' + error.message);
  }
});

app.listen(1060, () => {
  console.log('>>> Server IdP Full Encryption & Signature chạy thành công trên port 1060');
});