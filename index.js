'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { SignedXml } = require('xml-crypto');

const app = express();

app.use(bodyParser.urlencoded({
  extended: false,
  limit: '1mb'
}));

const PORT = Number(process.env.PORT || 1060);
const DEFAULT_EMAIL = process.env.DEFAULT_SSO_EMAIL || '';

const IDP_PUBLIC_URL = (
  process.env.IDP_PUBLIC_URL || ''
).replace(/\/+$/, '');

const APPSFLYER_ACS_URL =
  process.env.APPSFLYER_ACS_URL || '';

const APPSFLYER_SP_ENTITY_ID =
  process.env.APPSFLYER_SP_ENTITY_ID || '';

const PRIVATE_KEY_PATH = path.join(__dirname, 'key.pem');
const CERTIFICATE_PATH = path.join(__dirname, 'cert.pem');

// ========================================
// 1. Escape XML / HTML
// ========================================

function xmlEscape(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function htmlEscape(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ========================================
// 2. Public URL
// ========================================

function getPublicBaseUrl(req) {
  if (IDP_PUBLIC_URL) {
    return IDP_PUBLIC_URL;
  }

  // Khuyến nghị set IDP_PUBLIC_URL khi chạy sau reverse proxy.
  return `${req.protocol}://${req.get('host')}`;
}

// ========================================
// 3. Read certificate
// ========================================

function readCertificate() {
  const certificate = fs.readFileSync(
    CERTIFICATE_PATH,
    'utf8'
  );

  const certClean = certificate
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');

  if (!certClean) {
    throw new Error('cert.pem is empty or invalid');
  }

  return {
    certificate,
    certClean
  };
}

// ========================================
// 4. Parse SAMLRequest
// ========================================

function decodeSamlRequest(encodedRequest) {
  if (
    !encodedRequest ||
    typeof encodedRequest !== 'string'
  ) {
    throw new Error(
      'Missing SAMLRequest. SP-initiated SSO requires an AuthnRequest.'
    );
  }

  // Query parameters có thể biến dấu + thành dấu cách.
  const normalized = encodedRequest.replace(/ /g, '+');
  const buffer = Buffer.from(normalized, 'base64');

  let requestXml;

  try {
    // HTTP-Redirect binding: raw DEFLATE + Base64
    requestXml = zlib
      .inflateRawSync(buffer)
      .toString('utf8');
  } catch {
    // HTTP-POST binding: Base64-encoded XML
    requestXml = buffer.toString('utf8');
  }

  if (
    !/<(?:[A-Za-z_][\w.-]*:)?AuthnRequest\b/.test(
      requestXml
    )
  ) {
    throw new Error(
      'SAMLRequest could not be decoded into AuthnRequest XML.'
    );
  }

  const rootMatch = requestXml.match(
    /<(?:[A-Za-z_][\w.-]*:)?AuthnRequest\b([^>]*)>/
  );

  const rootAttributes = rootMatch
    ? rootMatch[1]
    : '';

  const idMatch = rootAttributes.match(
    /\bID\s*=\s*["']([^"']+)["']/
  );

  const acsMatch = rootAttributes.match(
    /\bAssertionConsumerServiceURL\s*=\s*["']([^"']+)["']/
  );

  const issuerMatch = requestXml.match(
    /<(?:[A-Za-z_][\w.-]*:)?Issuer\b[^>]*>([\s\S]*?)<\/(?:[A-Za-z_][\w.-]*:)?Issuer\s*>/
  );

  if (!idMatch || !issuerMatch) {
    throw new Error(
      'Cannot extract AuthnRequest ID or SP Issuer.'
    );
  }

  return {
    requestId: idMatch[1],
    requestXml,
    requestedAcsUrl: acsMatch
      ? acsMatch[1]
      : '',
    issuer: issuerMatch[1].trim()
  };
}

// ========================================
// 5. Validate URLs
// ========================================

function validateHttpsUrl(value, label) {
  let parsed;

  try {
    parsed = new URL(value);
  } catch {
    throw new Error(
      `${label} is missing or invalid. ` +
      'Configure it from AppsFlyer SP metadata.'
    );
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(`${label} must use HTTPS.`);
  }

  return parsed.toString();
}

// ========================================
// 6. IdP Metadata
// ========================================

app.get('/metadata', (req, res) => {
  try {
    const baseUrl = getPublicBaseUrl(req);

    const idpEntityId = `${baseUrl}/metadata`;
    const idpSsoUrl = `${baseUrl}/sso`;

    const { certClean } = readCertificate();

    const metadata = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="${xmlEscape(idpEntityId)}">

  <md:IDPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>${certClean}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>

    <md:NameIDFormat>
      urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
    </md:NameIDFormat>

    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="${xmlEscape(idpSsoUrl)}"/>

    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="${xmlEscape(idpSsoUrl)}"/>

  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;

    res.type('application/xml').send(metadata);

  } catch (error) {
    console.error(
      '[Metadata Error]',
      error.message
    );

    res.status(500).send(
      'Unable to generate IdP metadata. Check cert.pem.'
    );
  }
});

// ========================================
// 7. Health check
// ========================================

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

// ========================================
// 8. Login form
// ========================================

// DEMO ONLY:
// Form này chỉ nhận email, không xác thực danh tính.
// Không sử dụng làm IdP production nếu chưa tích hợp
// authentication thật của công ty.

app.get('/sso', (req, res) => {
console.log('[SSO GET DEBUG]', {
  originalUrl: req.originalUrl,
  queryKeys: Object.keys(req.query),
  referer: req.get('referer') || '(none)',
  method: req.method
});
    
  const SAMLRequest =
    typeof req.query.SAMLRequest === 'string'
      ? req.query.SAMLRequest
      : '';

  const RelayState =
    typeof req.query.RelayState === 'string'
      ? req.query.RelayState
            : '';
    
    if (!SAMLRequest) {
  console.error(
    '[SSO GET] Missing SAMLRequest. Check SAML binding and IdP SSO URL.'
  );

  return res.status(400).send(
    'Missing SAMLRequest. Please start SSO from AppsFlyer.'
  );
}

  res.type('html').send(`<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AKA Digital SSO</title>
</head>
<body>
  <form method="POST"
        action="/sso"
        style="margin:100px auto;width:360px;max-width:90%;
               font-family:sans-serif;padding:20px;
               border:1px solid #ccc;border-radius:8px">

    <h3 style="text-align:center">AKA Digital SSO</h3>

    <input type="hidden"
           name="SAMLRequest"
           value="${htmlEscape(SAMLRequest)}">

    <input type="hidden"
           name="RelayState"
           value="${htmlEscape(RelayState)}">

    <div style="margin-bottom:15px">
      <label for="email">Tài khoản đăng nhập:</label><br>

      <input id="email"
             type="email"
             name="email"
             value="${htmlEscape(DEFAULT_EMAIL)}"
             style="width:100%;padding:8px;margin-top:5px;
                    box-sizing:border-box"
             required>
    </div>

    <button type="submit"
            style="width:100%;padding:10px;background:#000;
                   color:#fff;border:0;border-radius:4px;
                   cursor:pointer;font-weight:bold">
      Xác thực &amp; Vào AppsFlyer
    </button>

  </form>
</body>
</html>`);
});

// ========================================
// 9. Handle SAML login
// ========================================

app.post('/sso', async (req, res) => {
  try {
    const { SAMLRequest, RelayState } = req.body;

    const userEmail = String(
      req.body.email || ''
    ).trim();

    if (
      !userEmail ||
      !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(
        userEmail
      )
    ) {
      return res.status(400).send(
        'Invalid email address.'
      );
    }

    // Parse AuthnRequest from AppsFlyer.
    const parsed = decodeSamlRequest(SAMLRequest);

    console.info('[SAML] AuthnRequest parsed', {
      requestId: parsed.requestId,
      hasAcsUrl: Boolean(parsed.requestedAcsUrl),
      issuer: parsed.issuer
    });

    // Ưu tiên giá trị trong AuthnRequest.
    // Nếu không có ACS URL thì dùng cấu hình đã xác minh.
    const acsCandidate =
      parsed.requestedAcsUrl ||
      APPSFLYER_ACS_URL;

    const audienceCandidate =
      parsed.issuer ||
      APPSFLYER_SP_ENTITY_ID;

    const acsUrl = validateHttpsUrl(
      acsCandidate,
      'AppsFlyer ACS URL'
    );

    if (!audienceCandidate) {
      throw new Error(
        'AppsFlyer SP Entity ID is missing. ' +
        'Set APPSFLYER_SP_ENTITY_ID from verified SP metadata.'
      );
    }

    const audience = String(
      audienceCandidate
    ).trim();

    const baseUrl = getPublicBaseUrl(req);
    const idpEntityId = `${baseUrl}/metadata`;

    const privateKeyRaw = fs.readFileSync(
      PRIVATE_KEY_PATH,
      'utf8'
    );

    const { certificate, certClean } =
      readCertificate();

    // Kiểm tra private key có parse được.
    crypto.createPrivateKey({
      key: privateKeyRaw,
      format: 'pem'
    });

    // ========================================
    // 10. Build SAML Response
    // ========================================

    const now = Date.now();

    const issueInstant =
      new Date(now).toISOString();

    const notOnOrAfter =
      new Date(now + 5 * 60 * 1000).toISOString();

    const responseId =
      `_${crypto.randomBytes(16).toString('hex')}`;

    const assertionId =
      `_${crypto.randomBytes(16).toString('hex')}`;

    const emailXml = xmlEscape(userEmail);
    const idpEntityXml = xmlEscape(idpEntityId);
    const acsXml = xmlEscape(acsUrl);
    const audienceXml = xmlEscape(audience);
    const requestIdXml = xmlEscape(parsed.requestId);

    const responseIdXml =
      xmlEscape(responseId);

    const assertionIdXml =
      xmlEscape(assertionId);

    const xmlUnsigned = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="${responseIdXml}"
    Version="2.0"
    IssueInstant="${issueInstant}"
    Destination="${acsXml}"
    InResponseTo="${requestIdXml}">

  <saml:Issuer>${idpEntityXml}</saml:Issuer>

  <samlp:Status>
    <samlp:StatusCode
        Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>

  <saml:Assertion
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:xs="http://www.w3.org/2001/XMLSchema"
      ID="${assertionIdXml}"
      Version="2.0"
      IssueInstant="${issueInstant}">

    <saml:Issuer>${idpEntityXml}</saml:Issuer>

    <saml:Subject>
      <saml:NameID
          Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${emailXml}</saml:NameID>

      <saml:SubjectConfirmation
          Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">

        <saml:SubjectConfirmationData
            InResponseTo="${requestIdXml}"
            NotOnOrAfter="${notOnOrAfter}"
            Recipient="${acsXml}"/>

      </saml:SubjectConfirmation>
    </saml:Subject>

    <saml:Conditions
        NotBefore="${issueInstant}"
        NotOnOrAfter="${notOnOrAfter}">

      <saml:AudienceRestriction>
        <saml:Audience>${audienceXml}</saml:Audience>
      </saml:AudienceRestriction>

    </saml:Conditions>

    <saml:AuthnStatement
        AuthnInstant="${issueInstant}"
        SessionIndex="${assertionIdXml}">

      <saml:AuthnContext>
        <saml:AuthnContextClassRef>
          urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        </saml:AuthnContextClassRef>
      </saml:AuthnContext>

    </saml:AuthnStatement>

    <saml:AttributeStatement>
      <saml:Attribute
          Name="email"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">

        <saml:AttributeValue xsi:type="xs:string">${emailXml}</saml:AttributeValue>

      </saml:Attribute>
    </saml:AttributeStatement>

  </saml:Assertion>
</samlp:Response>`;

    // ========================================
    // 11. Sign SAML Response
    // ========================================

    // API này dành cho các phiên bản xml-crypto mới.
    // Kiểm tra version bằng: npm ls xml-crypto

    const sig = new SignedXml({
      privateKey: privateKeyRaw,
      publicCert: certificate,

      canonicalizationAlgorithm:
        'http://www.w3.org/2001/10/xml-exc-c14n#',

      signatureAlgorithm:
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    });

    // QUAN TRỌNG:
    // responseId giữ nguyên dấu "_" khi tham chiếu XML ID.
    sig.addReference({
      xpath: "/*[local-name(.)='Response']",
      uri: responseId,

      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#'
      ],

      digestAlgorithm:
        'http://www.w3.org/2001/04/xmlenc#sha256'
    });

    sig.computeSignature(xmlUnsigned, {
      location: {
        reference:
          "/*[local-name(.)='Response']/*[local-name(.)='Issuer']",
        action: 'after'
      }
    });

    const samlResponseXml =
      sig.getSignedXml();

    const samlResponseBase64 =
      Buffer.from(
        samlResponseXml,
        'utf8'
      ).toString('base64');

    // Không log toàn bộ SAMLResponse hoặc private key.
    console.info('[SAML] Response generated', {
      responseId,
      inResponseTo: parsed.requestId,
      destination: acsUrl,
      audience,
      nameId: userEmail,
      signatureAlgorithm: 'rsa-sha256'
    });

    // ========================================
    // 12. POST Response to AppsFlyer ACS
    // ========================================

    res.type('html').send(`<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <title>Redirecting to AppsFlyer</title>
</head>

<body onload="document.forms[0].submit()">

  <form method="POST"
        action="${htmlEscape(acsUrl)}">

    <input type="hidden"
           name="SAMLResponse"
           value="${htmlEscape(samlResponseBase64)}">

    <input type="hidden"
           name="RelayState"
           value="${htmlEscape(RelayState || '')}">

  </form>

  <p style="text-align:center;margin-top:50px">
    Đang gửi thông tin xác thực tới AppsFlyer...
  </p>

</body>
</html>`);

  } catch (error) {
    console.error('[SAML] Processing failed', {
      name: error.name,
      message: error.message,
      stack: error.stack
    });

    res.status(500).send(
      'Lỗi xử lý SAML. Kiểm tra server log để biết chi tiết. ' +
      htmlEscape(error.message)
    );
  }
});

// ========================================
// 13. Start server
// ========================================

app.listen(PORT, () => {
  console.log(
    `[Init] SAML IdP demo listening on port ${PORT}`
  );

  console.log(
    '[Init] Verify IDP_PUBLIC_URL, APPSFLYER_ACS_URL, ' +
    'and APPSFLYER_SP_ENTITY_ID against actual metadata.'
  );
});