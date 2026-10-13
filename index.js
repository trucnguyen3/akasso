const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const samlIdp = require('saml-idp');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

const IDP_ENTITY_ID = 'https://sso-uat1.akadigital.net/metadata';
const IDP_SSO_URL = 'https://sso-uat1.akadigital.net/sso';

// Cấu hình cert & key cho saml-idp
const cert = fs.readFileSync('./cert.pem', 'utf8');
const key = fs.readFileSync('./key.pem', 'utf8');

// Thiết lập route Metadata tiêu chuẩn
app.get('/metadata', (req, res) => {
  res.type('application/xml');
  res.send(samlIdp.getMetadata({
    issuer: IDP_ENTITY_ID,
    cert: cert,
    ssoUrl: IDP_SSO_URL
  }));
});

// Giao diện đăng nhập giả lập cho tài khoản @akadigital.vn
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

// Xử lý sinh SAML Response đã ký số đầy đủ gửi về AppsFlyer
app.post('/sso', (req, res) => {
  const { SAMLRequest, RelayState, username } = req.body;
  const userEmail = `${(username || 'admin').trim()}@akadigital.vn`;

  // Sử dụng thư viện saml-idp để tự động tạo và ký response chuẩn xác
  samlIdp.parseLoginRequest(SAMLRequest, (err, parseResult) => {
    const acsUrl = parseResult && parseResult.acsUrl ? parseResult.acsUrl : 'https://saml.appsflyer.com/sso/saml';
    const inResponseTo = parseResult && parseResult.id ? parseResult.id : '_id';

    const options = {
      issuer: IDP_ENTITY_ID,
      cert: cert,
      key: key,
      acsUrl: acsUrl,
      inResponseTo: inResponseTo,
      relayState: RelayState,
      email: userEmail,
      nameID: userEmail,
      nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      sessionIndex: '_' + Date.now(),
    };

    samlIdp.getSamlResponse(options, (err, samlResponse) => {
      if (err) {
        return res.status(500).send('Lỗi tạo chữ ký SAML: ' + err.message);
      }

      res.send(`
        <html>
          <body onload="document.forms[0].submit()">
            <form method="POST" action="${acsUrl}">
              <input type="hidden" name="SAMLResponse" value="${samlResponse}" />
              <input type="hidden" name="RelayState" value="${RelayState || ''}" />
            </form>
            <p style="text-align:center; margin-top: 50px;">Đang xác thực và chuyển hướng về AppsFlyer...</p>
          </body>
        </html>
      `);
    });
  });
});

app.listen(1060, () => {
  console.log('>>> AKA Digital SAML IdP (signed) đang chạy trên port 1060');
});