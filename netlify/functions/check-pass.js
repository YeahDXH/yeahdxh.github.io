const crypto = require('crypto');

// Only allow requests from your GitHub Pages origin to reduce cross-site abuse.
// If you want to allow other origins (for local testing), add them here or set to '*'.
const ALLOWED_ORIGIN = 'https://yeahdxh.github.io';

exports.handler = async (event) => {
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: {
        ...headers,
        'Access-Control-Allow-Methods': 'POST, OPTIONS'
      },
      body: ''
    };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ ok: false, error: 'Method not allowed' })
    };
  }

  try {
    const { pass } = JSON.parse(event.body || '{}');
    if (!pass) {
      return { statusCode: 400, headers, body: JSON.stringify({ ok: false }) };
    }

    // Compute SHA-256 of submitted passcode
    const hash = crypto.createHash('sha256').update(pass, 'utf8').digest('hex');

    // Compare to the secret stored in the environment (PASS_HASH). Do NOT commit the secret to the repo.
    const stored = (process.env.PASS_HASH || '').trim();

    if (!stored || stored.length !== hash.length) {
      // Either secret not set or lengths mismatch — treat as unauthorized
      return { statusCode: 401, headers, body: JSON.stringify({ ok: false }) };
    }

    // Constant-time comparison to avoid timing attacks
    const ok = crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(stored, 'hex'));

    return { statusCode: ok ? 200 : 401, headers, body: JSON.stringify({ ok }) };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false }) };
  }
};
