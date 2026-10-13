const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

console.log('[Init] Khởi động Server IdP (Tự động bóc tách Dynamic Audience & Issuer)...');

// 1. Endpoint Metadata tự động nhận diện domain/URL hiện tại của server
app.get('/metadata', (req, res) => {
  try {
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.get('host');
    const baseUrl = `${protocol}://${host}`;
    const idpEntityId = `${baseUrl}/metadata`;
    const idpSsoUrl = `${baseUrl}/sso`;

    const certPath = path.join(__dirname, 'cert.pem');
    const certificate = fs.readFileSync(certPath, 'utf8');
    const certClean = certificate.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/[\r\n]+/g, '');

    res.type('application/xml');
    res.send(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" 
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#" 
                     entityID="${idpEntityId}">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>${certClean}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${idpSsoUrl}"/>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${idpSsoUrl}"/>
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

// 3. Xử lý tạo SAML Response với Dynamic Issuer và Dynamic Audience
app.post('/sso', async (req, res) => {
  const { SAMLRequest, RelayState, email } = req.body;
  const userEmail = (email || 'truc.nguyen@akadigital.vn').trim();

  try {
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.get('host');
    const baseUrl = `${protocol}://${host}`;
    const idpEntityId = `${baseUrl}/metadata`;

    const privateKeyPath = path.join(__dirname, 'key.pem');
    const certificatePath = path.join(__dirname, 'cert.pem');
    
    const privateKeyRaw = fs.readFileSync(privateKeyPath, 'utf8');
    const certificate = fs.readFileSync(certificatePath, 'utf8');

    let acsUrl = 'https://hq1.appsflyer.com/auth/sso/saml/callback';
    let audience = 'https://hq1.appsflyer.com'; // Giá trị mặc định phòng hờ
    let inResponseTo = '_' + crypto.randomBytes(16).toString('hex');

    // Tự động phân tích SAMLRequest để lấy chính xác thông tin từ AppsFlyer gửi sang
    if (SAMLRequest) {
      try {
        const buffer = Buffer.from(SAMLRequest, 'base64');
        let requestXml = '';
        try { requestXml = zlib.inflateRawSync(buffer).toString('utf8'); } 
        catch (e) { requestXml = buffer.toString('utf8'); }

        // Bóc tách ACS URL
        const acsMatch = requestXml.match(/AssertionConsumerServiceURL="([^"]+)"/);
        if (acsMatch && acsMatch[1]) acsUrl = acsMatch[1];

        // Bóc tách ID request để gán vào InResponseTo
        const idMatch = requestXml.match(/ID="([^"]+)"/);
        if (idMatch && idMatch[1]) inResponseTo = idMatch[1];

        // Tự động bóc tách Issuer của AppsFlyer để làm Audience (Khỏi cần khai báo cứng)
        const issuerMatch = requestXml.match(/<saml:Issuer[^>]*>(.*?)<\/saml:Issuer>/) || requestXml.match(/<Issuer[^>]*>(.*?)<\/Issuer>/);
        if (issuerMatch && issuerMatch[1]) {
          audience = issuerMatch[1].trim();
        }
      } catch (err) {
        console.error('Không parse được SAMLRequest, sử dụng giá trị mặc định');
      }
    }

    const now = Date.now() - 180000; // Bù trừ clock skew 3 phút
    const issueInstant = new Date(now).toISOString();
    const responseId = '_' + crypto.randomBytes(16).toString('hex');
    const assertionId = '_' + crypto.randomBytes(16).toString('hex');
    const notOnOrAfter = new Date(now + 600000).toISOString();
    const certClean = certificate.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/[\r\n]+/g, '');

    // Tạo Assertion XML chuẩn với Audience tự động bóc tách
const assertionXml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}">
    <saml:Issuer>${idpEntityId}</saml:Issuer>
    <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${userEmail}</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData InResponseTo="${inResponseTo}" NotOnOrAfter="${notOnOrAfter}" Recipient="${acsUrl}"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${issueInstant}" NotOnOrAfter="${notOnOrAfter}">
        <saml:AudienceRestriction>
            <saml:Audience>${audience}</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${assertionId}">
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
        </saml:AuthnContext>
    </saml:AuthnStatement>
</saml:Assertion>`;
      
      const unsignedResponseXml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="${responseId}" Version="2.0" IssueInstant="${issueInstant}" Destination="${acsUrl}" InResponseTo="${inResponseTo}">
    <saml:Issuer>${idpEntityId}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    ${assertionXml}
</samlp:Response>`;

    // Ký số trực tiếp bằng module crypto chuẩn (RSA-SHA256)
const signer = crypto.createSign('RSA-SHA256');
    signer.update(unsignedResponseXml);
    signer.end();
    const signatureValue = signer.sign(privateKeyRaw, 'base64');

    // Gói Response chính
const samlResponseXml = unsignedResponseXml.replace(
      `</saml:Issuer>`,
      `</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#${responseId}">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>${crypto.createHash('sha256').update(unsignedResponseXml).digest('base64')}</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>${signatureValue}</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>${certClean}</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>`
    );

    const samlResponseBase64 = Buffer.from(samlResponseXml).toString('base64');

    res.send(`
      <html>
        <body onload="document.forms[0].submit()">
          <form method="POST" action="${acsUrl}">
            <input type="hidden" name="SAMLResponse" value="${samlResponseBase64}" />
            <input type="hidden" name="RelayState" value="${RelayState || ''}" />
          </form>
          <p style="text-align:center; margin-top: 50px;">Đang gửi thông tin xác thực cho <b>${userEmail}</b> tới AppsFlyer...</p>
        </body>
      </html>
    `);

  } catch (error) {
    console.error('[SAML Signing Error]:', error);
    res.status(500).send('Lỗi xử lý SAML Response: ' + error.message);
  }
});

app.listen(1060, () => {
  console.log('>>> Server IdP (Fully Dynamic) chạy thành công trên port 1060');
});