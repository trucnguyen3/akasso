const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const zlib = require('zlib');
const crypto = require('crypto');
const { SignedXml } = require('xml-crypto');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

try {
  const privateKey = fs.readFileSync('./key.pem', 'utf8');
  const certificate = fs.readFileSync('./cert.pem', 'utf8');

  const IDP_ENTITY_ID = 'https://sso-uat1.akadigital.net/metadata';
  const IDP_SSO_URL = 'https://sso-uat1.akadigital.net/sso';

  console.log('[Init] Khởi động AKA Digital Secure SAML IdP...');

  // 1. Endpoint Metadata
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

  // 3. Xử lý tạo SAML Response & Ký số
  app.post('/sso', async (req, res) => {
    const { SAMLRequest, RelayState, username } = req.body;
    const userEmail = `${(username || 'admin').trim()}@akadigital.vn`;

    try {
      let acsUrl = 'https://saml.appsflyer.com/sso/saml';
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
          console.error('Không parse được SAMLRequest, dùng giá trị mặc định');
        }
      }

      const issueInstant = new Date().toISOString();
      const responseId = '_' + crypto.randomBytes(16).toString('hex');
      const assertionId = '_' + crypto.randomBytes(16).toString('hex');
      const certClean = certificate.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/[\r\n]+/g, '');

      // Tạo Assertion XML chuẩn để tiến hành ký số
      const assertionXml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}">
    <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
    <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${userEmail}</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData InResponseTo="${inResponseTo}" NotOnOrAfter="${new Date(Date.now() + 300000).toISOString()}" Recipient="${acsUrl}"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${issueInstant}" NotOnOrAfter="${new Date(Date.now() + 300000).toISOString()}">
        <saml:AudienceRestriction>
            <saml:Audience>${IDP_ENTITY_ID}</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${assertionId}">
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransform</saml:AuthnContextClassRef>
        </saml:AuthnContext>
    </saml:AuthnStatement>
</saml:Assertion>`;

      // Thực hiện ký số điện tử vào Assertion bằng xml-crypto
      const sig = new SignedXml();
      sig.signingKey = privateKey;
      sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
      sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
      
      // Tham chiếu đến ID của Assertion để ký
      sig.addReference(
        `//*[local-name(p)='Assertion']/@ID`,
        [
          'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
          'http://www.w3.org/2001/10/xml-exc-c14n#'
        ],
        'http://www.w3.org/2001/04/xmlenc#sha256'
      );

      sig.keyInfoProvider = {
        getKeyInfo: () => `<ds:X509Data><ds:X509Certificate>${certClean}</ds:X509Certificate></ds:X509Data>`
      };

      sig.computeSignature(assertionXml);
      const signedAssertion = sig.getSignatureXml();

      // Gộp Assertion đã ký vào Response chính
      const finalAssertion = assertionXml.replace('</saml:Assertion>', `${signedAssertion}</saml:Assertion>`);

      const samlResponseXml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="${responseId}" Version="2.0" IssueInstant="${issueInstant}" Destination="${acsUrl}" InResponseTo="${inResponseTo}">
    <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    ${finalAssertion}
</samlp:Response>`;

      const samlResponseBase64 = Buffer.from(samlResponseXml).toString('base64');

      res.send(`
        <html>
          <body onload="document.forms[0].submit()">
            <form method="POST" action="${acsUrl}">
              <input type="hidden" name="SAMLResponse" value="${samlResponseBase64}" />
              <input type="hidden" name="RelayState" value="${RelayState || ''}" />
            </form>
            <p style="text-align:center; margin-top: 50px;">Đang đăng nhập thành công tài khoản <b>${userEmail}</b>, đang chuyển hướng về AppsFlyer...</p>
          </body>
        </html>
      `);

    } catch (error) {
      console.error('[SAML Signing Error]:', error);
      res.status(500).send('Lỗi ký số SAML: ' + error.message);
    }
  });

  app.listen(1060, () => {
    console.log('>>> AKA Digital Secure SAML IdP đang chạy thành công trên port 1060');
  });

} catch (setupError) {
  console.error('[Fatal Error]:', setupError);
}