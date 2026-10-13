const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const { SAML } = require('@node-saml/node-saml');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

try {
  const privateKey = fs.readFileSync('./key.pem', 'utf8');
  const certificate = fs.readFileSync('./cert.pem', 'utf8');

  const IDP_ENTITY_ID = 'https://uat1.akadigital.net/sso-idp/metadata';
  const IDP_SSO_URL = 'https://uat1.akadigital.net/sso-idp/sso';

  console.log('[Init] Đang cấu hình SAML IdP...');

  const samlIdp = new SAML({
    issuer: IDP_ENTITY_ID,
    idpCert: certificate,     // Đổi từ 'cert' thành 'idpCert'
    privateKey: privateKey,    // Giữ nguyên privateKey để ký Assertion
    digestAlgorithm: 'sha256',
    signatureAlgorithm: 'rsa-sha256',
    callbackUrl: IDP_SSO_URL,
  });

  // 1. Endpoint Metadata
  app.get('/metadata', (req, res) => {
    try {
      const certClean = certificate
        .replace(/-----(BEGIN|END) CERTIFICATE-----/g, '')
        .replace(/[\r\n]+/g, ''); // Xóa toàn bộ ký tự xuống dòng

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
    console.log('[Request] Nhận được GET /sso, SAMLRequest:', SAMLRequest ? 'Có' : 'Không có');
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
    const userEmail = `${(username || 'admin').trim()}@akadigital.vn`;
    console.log(`[Process] Đang tạo SAML response cho user: ${userEmail}`);

    try {
      const extractedRequest = await samlIdp.parseLoginRequest({
        query: { SAMLRequest }
      });
      console.log('[Process] Parse Login Request thành công, ACS URL:', extractedRequest.acsUrl);

      const options = {
        issuer: IDP_ENTITY_ID,
        profile: {
          nameID: userEmail,
          nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
          email: userEmail,
        },
        acsUrl: extractedRequest.acsUrl,
        inResponseTo: extractedRequest.id,
        relayState: RelayState,
      };

      samlIdp.getSamlResponse(options, (err, samlResponse) => {
        if (err) {
          console.error('[Error] getSamlResponse failed:', err);
          return res.status(500).send('Lỗi tạo token: ' + err.message);
        }

        console.log('[Success] Tạo SAML Response thành công, đang gửi về AppsFlyer...');
        res.send(`
          <html>
            <body onload="document.forms[0].submit()">
              <form method="POST" action="${extractedRequest.acsUrl}">
                <input type="hidden" name="SAMLResponse" value="${samlResponse}" />
                <input type="hidden" name="RelayState" value="${RelayState || ''}" />
              </form>
              <p style="text-align:center; margin-top: 50px;">Đang xác thực tài khoản <b>${userEmail}</b> và chuyển hướng về AppsFlyer...</p>
            </body>
          </html>
        `);
      });
    } catch (error) {
      console.error('[Error catch POST /sso]:', error);
      res.status(500).send('Lỗi xử lý SAML Request: ' + error.message);
    }
  });

  app.listen(1060, () => {
    console.log('>>> AKA Digital SAML IdP đang chạy thành công trên port 1060');
  });

} catch (setupError) {
  console.error('[Fatal Error khi khởi tạo ứng dụng]:', setupError);
}