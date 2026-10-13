const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const zlib = require('zlib');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

try {
  const privateKey = fs.readFileSync('./key.pem', 'utf8');
  const certificate = fs.readFileSync('./cert.pem', 'utf8');

  const IDP_ENTITY_ID = 'https://sso-uat1.akadigital.net/metadata';
  const IDP_SSO_URL = 'https://sso-uat1.akadigital.net/sso';

  console.log('[Init] Khởi động AKA Digital SAML IdP chuẩn xác...');

  // 1. Endpoint Metadata cho AppsFlyer đọc
  app.get('/metadata', (req, res) => {
    const certClean = certificate
      .replace(/-----(BEGIN|END) CERTIFICATE-----/g, '')
      .replace(/[\r\n]+/g, '');

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
  });

  // 2. Giao diện Login yêu cầu nhập tài khoản @akadigital.vn
  app.get('/sso', (req, res) => {
    const { SAMLRequest, RelayState } = req.query;
    res.send(`
      <form method="POST" action="/sso" style="margin: 100px auto; width: 320px; font-family: sans-serif; padding: 20px; border: 1px solid #ccc; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
        <h3 style="text-align: center; margin-bottom: 20px;">AKA Digital SSO</h3>
        <input type="hidden" name="SAMLRequest" value="${SAMLRequest || ''}" />
        <input type="hidden" name="RelayState" value="${RelayState || ''}" />
        <div style="margin-bottom: 15px;">
          <label style="font-size: 14px; color: #555;">Tên tài khoản nội bộ:</label><br/>
          <div style="display: flex; align-items: center; margin-top: 5px;">
            <input type="text" name="username" value="admin" style="flex: 1; padding: 8px; border: 1px solid #ccc; border-radius: 4px;" required />
            <span style="margin-left: 8px; font-weight: bold; color: #333;">@akadigital.vn</span>
          </div>
        </div>
        <button type="submit" style="width: 100%; padding: 10px; background: #000; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">Đăng nhập AppsFlyer</button>
      </form>
    `);
  });

  // 3. Xử lý giải mã yêu cầu từ AppsFlyer và trả về SAML Response
  app.post('/sso', async (req, res) => {
    const { SAMLRequest, RelayState, username } = req.body;
    const userEmail = `${(username || 'admin').trim()}@akadigital.vn`;

    try {
      let acsUrl = 'https://hq1.appsflyer.com/auth/sso-metadata?acc-id=acc-fbb1a88f';
      const APPSFLYER_ENTITY_ID = 'https://hq1.appsflyer.com';
      let inResponseTo = '_' + crypto.randomBytes(16).toString('hex');

      // Giải mã SAMLRequest từ AppsFlyer gửi sang qua phương thức Deflate / Base64
      if (SAMLRequest) {
        try {
          const buffer = Buffer.from(SAMLRequest, 'base64');
          let requestXml = '';
          try { 
            requestXml = zlib.inflateRawSync(buffer).toString('utf8'); 
          } catch (e) { 
            requestXml = buffer.toString('utf8'); 
          }

          const acsMatch = requestXml.match(/AssertionConsumerServiceURL="([^"]+)"/);
          if (acsMatch && acsMatch[1]) acsUrl = acsMatch[1];

          const idMatch = requestXml.match(/ID="([^"]+)"/);
          if (idMatch && idMatch[1]) inResponseTo = idMatch[1];
        } catch (err) {
          console.error('Không parse được SAMLRequest, sử dụng ACS URL mặc định');
        }
      }

      const issueInstant = new Date().toISOString();
      const responseId = '_' + crypto.randomBytes(16).toString('hex');
      const assertionId = '_' + crypto.randomBytes(16).toString('hex');
      const notOnOrAfter = new Date(Date.now() + 600000).toISOString(); // Hiệu lực 10 phút

      // Tạo XML Response chuẩn SAML 2.0 phản hồi về AppsFlyer
      const samlResponseXml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" IssueInstant="${issueInstant}" Destination="${acsUrl}" InResponseTo="${inResponseTo}">
    <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}">
        <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${userEmail}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData InResponseTo="${inResponseTo}" NotOnOrAfter="${notOnOrAfter}" Recipient="${acsUrl}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="${issueInstant}" NotOnOrAfter="${notOnOrAfter}">
            <saml:AudienceRestriction>
                <saml:Audience>${APPSFLYER_ENTITY_ID}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${assertionId}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
    </saml:Assertion>
</samlp:Response>`;

      // Encode Base64 chuỗi SAML Response để Auto-submit form về AppsFlyer
      const samlResponseBase64 = Buffer.from(samlResponseXml).toString('base64');

      res.send(`
        <html>
          <body onload="document.forms[0].submit()">
            <form method="POST" action="${acsUrl}">
              <input type="hidden" name="SAMLResponse" value="${samlResponseBase64}" />
              <input type="hidden" name="RelayState" value="${RelayState || ''}" />
            </form>
            <p style="text-align:center; margin-top: 50px; font-family: sans-serif;">Đang xác thực tài khoản <b>${userEmail}</b> và chuyển hướng về AppsFlyer...</p>
          </body>
        </html>
      `);

    } catch (error) {
      console.error('[SAML Processing Error]:', error);
      res.status(500).send('Lỗi xử lý SAML: ' + error.message);
    }
  });

  app.listen(1060, () => {
    console.log('>>> AKA Digital SAML IdP đang chạy thành công trên port 1060');
  });

} catch (setupError) {
  console.error('[Fatal Error]:', setupError);
}