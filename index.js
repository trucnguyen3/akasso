const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const { SAML } = require('@node-saml/node-saml');
const zlib = require('zlib');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

try {
  const privateKey = fs.readFileSync('./key.pem', 'utf8');
  const certificate = fs.readFileSync('./cert.pem', 'utf8');

  // Đổi sang đúng subdomain mới lập
  const IDP_ENTITY_ID = 'https://sso-uat1.akadigital.net/metadata';
  const IDP_SSO_URL = 'https://sso-uat1.akadigital.net/sso';

  console.log('[Init] Đang cấu hình SAML IdP...');

  const samlIdp = new SAML({
    issuer: IDP_ENTITY_ID,
    idpCert: certificate,
    privateKey: privateKey,
    digestAlgorithm: 'sha256',
    signatureAlgorithm: 'rsa-sha256',
    callbackUrl: IDP_SSO_URL,
  });

  // 1. Endpoint Metadata
  app.get('/metadata', (req, res) => {
    try {
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
    } catch (err) {
      console.error('[Error] /metadata:', err);
      res.status(500).send('Internal Error');
    }
  });

  // 2. Giao diện Login
  app.get('/sso', (req, res) => {
    const { SAMLRequest, RelayState } = req.query;
    res.send(`
      <form method="POST" action="/sso" style="margin: 100px auto; width: 320px; font-family: sans-serif; padding: 20px; border: 1px solid #ccc; border-radius: 8px;">
        <h3 style="text-align: center;">AKA Digital SSO</h3>
        <input type="hidden" name="SAMLRequest" value="${SAMLRequest || ''}" />
        <input type="hidden" name="RelayState" value="${RelayState || ''}" />
        <div style="margin-bottom: 15px;">
          <label>Tên tài khoản:</label><br/>
          <div style="display: flex; align-items: center; margin-top: 5px;">
            <input type="text" name="username" value="admin" style="flex: 1; padding: 8px;" required />
            <span style="margin-left: 5px; font-weight: bold;">@akadigital.vn</span>
          </div>
        </div>
        <button type="submit" style="width: 100%; padding: 10px; background: #000; color: #fff; border: none; border-radius: 4px; cursor: pointer;">Đăng nhập AppsFlyer</button>
      </form>
    `);
  });

  // 3. Xử lý trả SAML Token
app.post('/sso', async (req, res) => {
    const { SAMLRequest, RelayState, username } = req.body;
    const userEmail = `${(username || 'admin').trigger ? username : (username || 'admin').trim()}@akadigital.vn`;

    try {
      // 1. Giải mã SAMLRequest gửi từ AppsFlyer (Deflate -> Base64 -> XML string)
      let requestXml = '';
      if (SAMLRequest) {
        const buffer = Buffer.from(SAMLRequest, 'base64');
        try {
          // Thử giải nén dạng raw deflate (chuẩn SAML Redirect binding)
          requestXml = zlib.inflateRawSync(buffer).toString('utf8');
        } catch (e) {
          // Nếu không phải raw thì thử inflate thường hoặc gán chuỗi thô
          try {
            requestXml = zlib.inflateSync(buffer).toString('utf8');
          } catch (err2) {
            requestXml = buffer.toString('utf8');
          }
        }
      }

      // 2. Lấy ACS URL và Request ID (InResponseTo) từ chuỗi XML của AppsFlyer
      // AppsFlyer thường gửi AssertionConsumerServiceURL và ID trong AuthnRequest
      let acsUrl = 'https://saml.appsflyer.com/sso/saml'; // Fallback URL chuẩn của AppsFlyer nếu không quét được
      let inResponseTo = 'id_' + Date.now();

      if (requestXml) {
        const acsMatch = requestXml.match(/AssertionConsumerServiceURL="([^"]+)"/);
        if (acsMatch && acsMatch[1]) acsUrl = acsMatch[1];

        const idMatch = requestXml.match(/ID="([^"]+)"/);
        if (idMatch && idMatch[1]) inResponseTo = idMatch[1];
      }

      const options = {
        issuer: IDP_ENTITY_ID,
        profile: {
          nameID: userEmail,
          nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
          email: userEmail,
        },
        acsUrl: acsUrl,
        inResponseTo: inResponseTo,
        relayState: RelayState || '',
      };

      // 3. Tạo chữ ký SAML Response gửi trả lại AppsFlyer
      samlIdp.getSamlResponse(options, (err, samlResponse) => {
        if (err) {
          console.error('[Error generating SAML Response]:', err);
          return res.status(500).send('Lỗi tạo token SAML: ' + err.message);
        }

        res.send(`
          <html>
            <body onload="document.forms[0].submit()">
              <form method="POST" action="${acsUrl}">
                <input type="hidden" name="SAMLResponse" value="${samlResponse}" />
                <input type="hidden" name="RelayState" value="${RelayState || ''}" />
              </form>
              <p style="text-align:center; margin-top: 50px;">Đang xác thực tài khoản <b>${userEmail}</b> và chuyển hướng về AppsFlyer...</p>
            </body>
          </html>
        `);
      });
    } catch (error) {
      console.error('[SAML Processing Error]:', error);
      res.status(500).send('Lỗi xử lý SAML Request: ' + error.message);
    }
  });

  app.listen(1060, () => {
    console.log('>>> AKA Digital SAML IdP đang chạy thành công trên port 1060');
  });

} catch (setupError) {
  console.error('[Fatal Error khi khởi tạo ứng dụng]:', setupError);
}