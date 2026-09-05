const crypto = require('crypto');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: false, error: 'Method not allowed' })
    };
  }

  try {
    const { pass } = JSON.parse(event.body || '{}');
    if (!pass) {
      return { statusCode: 400, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: false }) };
    }

    // Compute SHA-256 of submitted passcode
    const hash = crypto.createHash('sha256').update(pass, 'utf8').digest('hex');

    // Compare to the secret stored in the environment (PASS_HASH). Do NOT commit the secret to the repo.
    const stored = process.env.PASS_HASH || '';

    if (stored.length !== hash.length || stored.length === 0) {
      // Either secret not set or lengths mismatch — treat as unauthorized
      return { statusCode: 401, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: false }) };
    }

    // Constant-time comparison to avoid timing attacks
    const ok = crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(stored, 'hex'));

    return { statusCode: ok ? 200 : 401, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok }) };
  } catch (err) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: false }) };
  }
};
