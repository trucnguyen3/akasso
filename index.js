const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const { SAML } = require('@node-saml/node-saml');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

const privateKey = fs.readFileSync('./key.pem', 'utf8');
const certificate = fs.readFileSync('./cert.pem', 'utf8');

// Endpoint kĩ thuật của IdP server
const IDP_ENTITY_ID = 'https://uat1.akadigital.net/sso-idp/metadata';
const IDP_SSO_URL = 'https://uat1.akadigital.net/sso-idp/sso';

const samlIdp = new SAML({
  issuer: IDP_ENTITY_ID,
  cert: certificate,
  key: privateKey,
  digestAlgorithm: 'sha256',
  signatureAlgorithm: 'rsa-sha256',
});

// 1. Endpoint Metadata
app.get('/metadata', (req, res) => {
  const certClean = certificate.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s/g, '');
  res.type('application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${IDP_ENTITY_ID}">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>${certClean}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${IDP_SSO_URL}"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>`);
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

// 3. Xử lý trả SAML Token chứa Email @akadigital.vn về lại AppsFlyer
app.post('/sso', async (req, res) => {
  const { SAMLRequest, RelayState, username } = req.body;
  const userEmail = `${username.trim()}@akadigital.vn`;

  try {
    const extractedRequest = await samlIdp.parseLoginRequest({
      query: { SAMLRequest }
    });

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
      if (err) return res.status(500).send('Lỗi tạo token: ' + err.message);

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
    res.status(500).send('Lỗi xử lý SAML Request: ' + error.message);
  }
});

app.listen(1060, () => {
  console.log('AKA Digital SAML IdP running on port 1060');
});