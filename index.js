
'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { SignedXml } = require('xml-crypto');

// ========================================
// 1. Load .env without requiring dotenv
// ========================================

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return;

  const content = fs.readFileSync(filePath, 'utf8');

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();

    if (!line || line.startsWith('#')) continue;

    const separator = line.indexOf('=');
    if (separator < 1) continue;

    const key = line.slice(0, separator).trim();
    let value = line.slice(separator + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    } else {
      value = value.replace(/\s+#.*$/, '').trim();
    }

    // Keep variables supplied by the OS or process manager.
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

loadEnvFile(path.join(__dirname, '.env'));

// ========================================
// 2. App configuration
// ========================================

const app = express();

app.set("trust proxy", "loopback");

app.use(express.urlencoded({
  extended: false,
  limit: '1mb'
}));

app.use(express.json({
  limit: '1mb'
}));

const PORT = Number(process.env.PORT || 1060);
const DEFAULT_EMAIL = String(
  process.env.DEFAULT_SSO_EMAIL || ''
).trim();

// Set this to the base URL, without /metadata or /sso.
const IDP_PUBLIC_URL = String(
  process.env.IDP_PUBLIC_URL || ''
).replace(/\/+$/, '');

const APPSFLYER_ACS_URL = String(
  process.env.APPSFLYER_ACS_URL || ''
).trim();

const APPSFLYER_SP_ENTITY_ID = String(
  process.env.APPSFLYER_SP_ENTITY_ID || ''
).trim();

const PRIVATE_KEY_PATH = path.join(__dirname, 'key.pem');
const CERTIFICATE_PATH = path.join(__dirname, 'cert.pem');


const allowedIps = new Set(
  (process.env.SSO_ALLOWED_IPS || "")
    .split(",")
    .map(ip => ip.trim())
    .filter(Boolean)
);

function normalizeIp(ip = "") {
  return ip.replace(/^::ffff:/, "");
}

app.use("/sso", (req, res, next) => {
  const clientIp = normalizeIp(req.ip);

  console.log("Client IP:", clientIp);

  if (!allowedIps.has(clientIp)) {
    console.warn(`[SSO BLOCKED] IP=${clientIp}`);
    return res.status(403).send(
      "SSO access denied: please connect to the company Wi-Fi."
    );
  }

  next();
});

// ========================================
// 3. Escape XML and HTML
// ========================================

function xmlEscape(value) {
  return String(value ?? '')
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
// 4. Public URL
// ========================================

function getPublicBaseUrl(req) {
  if (IDP_PUBLIC_URL) {
    return IDP_PUBLIC_URL;
  }

  return `${req.protocol}://${req.get('host')}`;
}

// ========================================
// 5. Certificate
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
// 6. Decode SAMLRequest
// ========================================

function decodeSamlRequest(encodedRequest) {
  if (
    !encodedRequest ||
    typeof encodedRequest !== 'string'
  ) {
    throw new Error('Missing SAMLRequest.');
  }

  const normalized = encodedRequest.replace(/ /g, '+');
  const buffer = Buffer.from(normalized, 'base64');

  let requestXml;

  try {
    // HTTP-Redirect binding: Base64 + raw DEFLATE.
    requestXml = zlib
      .inflateRawSync(buffer)
      .toString('utf8');
  } catch {
    // HTTP-POST binding: Base64-encoded XML.
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
// 7. Validate URLs
// ========================================

function validateHttpsUrl(value, label) {
  let parsed;

  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} is missing or invalid.`);
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(`${label} must use HTTPS.`);
  }

  return parsed.toString();
}

// ========================================
// 8. Loading page: automatically POST
// ========================================

function renderAutoSubmitPage({
  action,
  fields,
  title,
  message
}) {
  const hiddenFields = Object.entries(fields)
    .map(([name, value]) => {
      return `<input type="hidden" name="${htmlEscape(name)}" value="${htmlEscape(value)}">`;
    })
    .join('\n');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${htmlEscape(title)}</title>
  <style>
    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: Arial, sans-serif;
      color: #252525;
      background: #fff;
    }

    .loading {
      padding: 24px;
      text-align: center;
    }

    .spinner {
      width: 40px;
      height: 40px;
      margin: 0 auto 18px;
      border: 4px solid #e8e8e8;
      border-top-color: #2563eb;
      border-radius: 50%;
      animation: spin .8s linear infinite;
    }

    .title {
      font-size: 16px;
      font-weight: 600;
    }

    .hint {
      margin-top: 8px;
      color: #666;
      font-size: 13px;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    @media (prefers-reduced-motion: reduce) {
      .spinner { animation: none; }
    }
  </style>
</head>
<body>
  <main class="loading" role="status" aria-live="polite">
    <div class="spinner" aria-hidden="true"></div>
    <div class="title">${htmlEscape(title)}</div>
    <div class="hint">${htmlEscape(message)}</div>
  </main>

  <form id="ssoForm" method="POST" action="${htmlEscape(action)}">
    ${hiddenFields}
    <noscript>
      <button type="submit">Continue</button>
    </noscript>
  </form>

  <script>
    window.addEventListener('load', function () {
      document.getElementById('ssoForm').submit();
    });
  </script>
</body>
</html>`;
}

// ========================================
// 9. IdP Metadata
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
    console.error('[Metadata Error]', error.message);

    res.status(500).send(
      'Unable to generate IdP metadata. Check cert.pem.'
    );
  }
});

// ========================================
// 10. Health check
// ========================================

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

// ========================================
// 11. SSO entry point
// ========================================

// HTTP-Redirect binding: SAMLRequest is in the query string.
app.get('/sso', (req, res) => {
  const SAMLRequest =
    typeof req.query.SAMLRequest === 'string'
      ? req.query.SAMLRequest
      : '';

  const RelayState =
    typeof req.query.RelayState === 'string'
      ? req.query.RelayState
      : '';

  if (!SAMLRequest) {
    return res.status(400).send(
      'Missing SAMLRequest. Please start SSO from AppsFlyer.'
    );
  }

const escapeHtml = (value = '') =>
    String(value).replace(/[&<>"']/g, char => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[char]);

  return res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in to AppsFlyer</title>
</head>
<body style="font:16px Arial,sans-serif;max-width:420px;margin:80px auto;padding:24px">
  <h2>Sign in to AppsFlyer</h2>
  <form method="POST" action="/sso">
    <input type="hidden" name="SAMLRequest"
      value="${escapeHtml(SAMLRequest)}">
    <input type="hidden" name="RelayState"
      value="${escapeHtml(RelayState)}">

    <label for="email">Work email</label>
    <input id="email" type="email" name="email" required
      autocomplete="username"
      placeholder="you@company.com"
      style="display:block;box-sizing:border-box;width:100%;padding:12px;margin:8px 0 16px">

    <button type="submit" style="padding:12px 20px">
      Continue
    </button>
  </form>
</body>
</html>`);
});

// ========================================
// 12. Handle SAML login
// ========================================

app.post('/sso', async (req, res) => {
  const { SAMLRequest, RelayState } = req.body || {};

  const userEmail = String(
    req.body?.email || ''
  ).trim();

  console.info('[POST /sso]', {
    hasSAMLRequest: typeof SAMLRequest === 'string' && Boolean(SAMLRequest),
    hasRelayState: typeof RelayState === 'string' && Boolean(RelayState),
    hasEmail: Boolean(userEmail)
  });

  try {
    if (
      !SAMLRequest ||
      typeof SAMLRequest !== 'string'
    ) {
      return res.status(400).send(
        'Missing SAMLRequest. Please start SSO from AppsFlyer.'
      );
    }

    // Fallback if POST was started directly without email.
    if (!userEmail) {
      if (!DEFAULT_EMAIL) {
        return res.status(500).send(
          'Missing DEFAULT_SSO_EMAIL configuration.'
        );
      }

      return res.type('html').send(
        renderAutoSubmitPage({
          action: '/sso',
          fields: {
            SAMLRequest,
            RelayState: typeof RelayState === 'string' ? RelayState : '',
            email: DEFAULT_EMAIL
          },
          title: 'Signing in to AppsFlyer...',
          message: 'Please wait while we process your sign-in.'
        })
      );
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(userEmail)) {
      return res.status(400).send('Invalid email address.');
    }

    const parsed = decodeSamlRequest(SAMLRequest);

    console.info('[SAML] AuthnRequest parsed', {
      requestId: parsed.requestId,
      hasAcsUrl: Boolean(parsed.requestedAcsUrl),
      issuer: parsed.issuer
    });

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
        'AppsFlyer SP Entity ID is missing. Set APPSFLYER_SP_ENTITY_ID.'
      );
    }

    const audience = String(audienceCandidate).trim();

    const baseUrl = getPublicBaseUrl(req);
    const idpEntityId = `${baseUrl}/metadata`;

    const privateKeyRaw = fs.readFileSync(
      PRIVATE_KEY_PATH,
      'utf8'
    );

    const { certificate } = readCertificate();

    // Verify private key is readable.
    crypto.createPrivateKey({
      key: privateKeyRaw,
      format: 'pem'
    });

    const now = Date.now();

    const issueInstant = new Date(now).toISOString();
    const notOnOrAfter = new Date(
      now + 5 * 60 * 1000
    ).toISOString();

    const responseId =
      `_${crypto.randomBytes(16).toString('hex')}`;

    const assertionId =
      `_${crypto.randomBytes(16).toString('hex')}`;

    const emailXml = xmlEscape(userEmail);
    const idpEntityXml = xmlEscape(idpEntityId);
    const acsXml = xmlEscape(acsUrl);
    const audienceXml = xmlEscape(audience);
    const requestIdXml = xmlEscape(parsed.requestId);
    const responseIdXml = xmlEscape(responseId);
    const assertionIdXml = xmlEscape(assertionId);

    // Fail fast instead of generating empty Issuer elements.
    if (!idpEntityId || !acsUrl || !audience) {
      throw new Error(
        'Missing IdP Entity ID, ACS URL, or SP Audience.'
      );
    }

    console.info('[SSO CONFIG]', {
      idpEntityId,
      acsUrl,
      audience
    });

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
    // 13. Sign SAML Response
    // ========================================

    const sig = new SignedXml({
      privateKey: privateKeyRaw,
      publicCert: certificate,

      canonicalizationAlgorithm:
        'http://www.w3.org/2001/10/xml-exc-c14n#',

      signatureAlgorithm:
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    });

    sig.addReference({
      xpath: "/*[local-name(.)='Response']",
      uri: `#${responseId}`,

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

    const samlResponseXml = sig.getSignedXml();

    const samlResponseBase64 = Buffer
      .from(samlResponseXml, 'utf8')
      .toString('base64');

    console.info('[SAML] Response generated', {
      responseId,
      inResponseTo: parsed.requestId,
      destination: acsUrl,
      audience,
      nameId: userEmail,
      signatureAlgorithm: 'rsa-sha256'
    });

    // ========================================
    // 14. Auto-POST SAMLResponse to AppsFlyer
    // ========================================

    return res.type('html').send(
      renderAutoSubmitPage({
        action: acsUrl,
        fields: {
          SAMLResponse: samlResponseBase64,
          RelayState: typeof RelayState === 'string'
            ? RelayState
            : ''
        },
        title: 'Redirecting to AppsFlyer...',
        message: 'Please wait while we finish signing you in.'
      })
    );

  } catch (error) {
    console.error('[SAML] Processing failed', {
      name: error.name,
      message: error.message,
      stack: error.stack
    });

    return res.status(500).type('text').send(
      `SAML processing failed: ${error.message}`
    );
  }
});

// ========================================
// 15. Start server
// ========================================

app.listen(PORT, () => {
  console.log(`[Init] SAML IdP listening on port ${PORT}`);
  console.log(
    '[Init] IDP_PUBLIC_URL:',
    IDP_PUBLIC_URL || '(request host fallback)'
  );
  console.log(
    '[Init] DEFAULT_SSO_EMAIL configured:',
    Boolean(DEFAULT_EMAIL)
  );
  console.log(
    '[Init] Confirm the IdP Entity ID, ACS URL, SP Entity ID and certificate against AppsFlyer configuration.'
  );
});
