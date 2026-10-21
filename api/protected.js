const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PAGE_CONFIG = {
  onboarding: {
    envName: 'ONBOARDING_ACCESS_CODE',
    templatePath: 'api/_private/onboarding.html',
    publicPath: '/onboarding.html',
    title: '입사자 안내',
    description: '안내 메일에 함께 보내드린 코드를 입력하면 첫 출근에 필요한 내용을 보실 수 있어요.',
  },
  interview: {
    envName: 'INTERVIEW_ACCESS_CODE',
    templatePath: 'api/_private/interview.html',
    publicPath: '/interview.html',
    title: '면접 예정자 안내',
    description: '안내 메일에 함께 보내드린 코드를 입력하면 면접 준비에 필요한 내용을 보실 수 있어요.',
  },
};

const SESSION_SECONDS = 4 * 60 * 60;

function parseCookies(header) {
  return String(header || '')
    .split(';')
    .reduce((cookies, item) => {
      const separator = item.indexOf('=');
      if (separator === -1) return cookies;
      const name = item.slice(0, separator).trim();
      const value = item.slice(separator + 1).trim();
      if (name) cookies[name] = value;
      return cookies;
    }, {});
}

function cookieName(target) {
  return `webling_${target}_access`;
}

function signature(target, expires, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(`webling-access-v2:${target}:${expires}`)
    .digest('hex');
}

function createSession(target, secret) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  return `${expires}.${signature(target, expires, secret)}`;
}

function hasValidSession(target, token, secret) {
  if (!token || !secret) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;

  const expires = Number(parts[0]);
  if (!Number.isSafeInteger(expires) || expires <= Math.floor(Date.now() / 1000)) return false;

  const expected = signature(target, expires, secret);
  const suppliedBuffer = Buffer.from(parts[1]);
  const expectedBuffer = Buffer.from(expected);
  return suppliedBuffer.length === expectedBuffer.length
    && crypto.timingSafeEqual(suppliedBuffer, expectedBuffer);
}

function codesMatch(submitted, expected) {
  const submittedBuffer = Buffer.from(String(submitted || '').trim().toLowerCase());
  const expectedBuffer = Buffer.from(String(expected || '').trim().toLowerCase());
  return submittedBuffer.length === expectedBuffer.length
    && crypto.timingSafeEqual(submittedBuffer, expectedBuffer);
}

async function readSubmittedCode(req) {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
    return req.body.code || '';
  }

  let raw = '';
  if (typeof req.body === 'string') raw = req.body;
  else if (Buffer.isBuffer(req.body)) raw = req.body.toString('utf8');
  else {
    for await (const chunk of req) raw += chunk.toString('utf8');
  }

  return new URLSearchParams(raw).get('code') || '';
}

function renderLogin(page, target, showError = false) {
  const error = showError
    ? '<p class="error" role="alert">안내 코드가 일치하지 않습니다. 메일에 적힌 코드를 다시 확인해 주세요.</p>'
    : '<p class="error" aria-hidden="true"></p>';

  return `<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>${page.title} | WEBLING INSIDE</title>
  <style>
    :root { color-scheme: light; font-family: Arial, "Noto Sans KR", sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; color: #222; background: #fff; }
    main { width: 100%; max-width: 420px; text-align: center; }
    .logo { margin: 0 0 28px; font-size: 20px; font-weight: 800; letter-spacing: .18em; }
    h1 { margin: 0 0 10px; font-size: 22px; }
    .description { margin: 0 0 28px; color: #666; font-size: 15px; line-height: 1.7; }
    form { display: grid; gap: 12px; }
    input { width: 100%; padding: 14px 16px; border: 1px solid #d9d9d9; border-radius: 8px; font: inherit; text-align: center; }
    input:focus { border-color: #1c77a6; outline: 2px solid rgba(28,119,166,.16); }
    button { width: 100%; padding: 14px 16px; border: 0; border-radius: 8px; color: #fff; background: #222; font: inherit; font-weight: 700; cursor: pointer; }
    button:hover { background: #1c77a6; }
    .error { min-height: 20px; margin: 0; color: #d14343; font-size: 14px; }
    .help { margin-top: 20px; color: #666; font-size: 13px; line-height: 1.7; }
    a { color: #1c77a6; }
  </style>
</head>
<body>
  <main>
    <p class="logo">WEBLING</p>
    <h1>${page.title}</h1>
    <p class="description">${page.description}</p>
    <form method="post" action="/api/protected?target=${target}">
      <input type="password" name="code" placeholder="안내 코드를 입력해 주세요" autocomplete="current-password" aria-label="안내 코드" required autofocus>
      <button type="submit">확인</button>
      ${error}
    </form>
    <p class="help">코드를 못 받으셨거나 입력이 되지 않는다면<br><a href="mailto:recruiter2@snaps.com">recruiter2@snaps.com</a>으로 문의해 주세요.</p>
  </main>
</body>
</html>`;
}

function setPrivateHeaders(res) {
  res.setHeader('Cache-Control', 'private, no-store, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
}

module.exports = async function handler(req, res) {
  const target = typeof req.query.target === 'string' ? req.query.target : '';
  const page = PAGE_CONFIG[target];

  if (!page) {
    res.statusCode = 404;
    return res.end('Not found');
  }

  const accessCode = process.env[page.envName];
  if (!accessCode) {
    setPrivateHeaders(res);
    res.statusCode = 503;
    return res.end('Access settings are not ready.');
  }

  if (req.method === 'POST') {
    const submittedCode = await readSubmittedCode(req);
    if (!codesMatch(submittedCode, accessCode)) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      setPrivateHeaders(res);
      res.statusCode = 401;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.end(renderLogin(page, target, true));
    }

    const token = createSession(target, accessCode);
    res.setHeader('Set-Cookie', `${cookieName(target)}=${token}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Lax`);
    res.statusCode = 303;
    res.setHeader('Location', page.publicPath);
    return res.end();
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.statusCode = 405;
    res.setHeader('Allow', 'GET, HEAD, POST');
    return res.end('Method not allowed');
  }

  const cookies = parseCookies(req.headers.cookie);
  if (!hasValidSession(target, cookies[cookieName(target)], accessCode)) {
    setPrivateHeaders(res);
    res.statusCode = 401;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.end(req.method === 'HEAD' ? '' : renderLogin(page, target));
  }

  const filePath = path.join(process.cwd(), page.templatePath);
  const html = fs.readFileSync(filePath, 'utf8');
  setPrivateHeaders(res);
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.end(req.method === 'HEAD' ? '' : html);
};
