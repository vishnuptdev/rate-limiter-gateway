'use strict';

// Express middleware that asks RateGuard's check API for a decision before the
// route handler runs. Requires Node 18+ (global fetch, AbortSignal.timeout) and
// works with Express 4 and 5.
//
//   const { rateGuard } = require('./express-middleware');
//   app.use('/api', rateGuard({
//     url: 'http://rateguard:8080',          // or RATEGUARD_URL
//     token: process.env.RATEGUARD_TOKEN,    // API token with scope "check" (rgt_...)
//   }));
//
// Behaviour:
// - Allowed: the decision headers (RateLimit-*) are set on the response and the
//   request continues.
// - Denied: responds 429 with Retry-After and the decision details.
// - Fail-open: if RateGuard errors or does not answer within 50 ms, the request
//   continues. A bad token also fails open, so watch the warnings in your logs.
//
// The consumer's API key is read from the request header (default X-API-Key) and
// sent in the check body as "api_key". Set `trust proxy` in Express if the app
// sits behind a load balancer, so req.ip is the real client address.

const DEFAULT_TIMEOUT_MS = 50;

function rateGuard(opts = {}) {
  const base = (opts.url || process.env.RATEGUARD_URL || 'http://localhost:8080').replace(/\/+$/, '');
  const checkUrl = `${base}/_rlg/v1/check`;
  const token = opts.token || process.env.RATEGUARD_TOKEN;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const apiKeyHeader = (opts.apiKeyHeader || 'X-API-Key').toLowerCase();

  if (!token) {
    throw new Error('rateGuard: an API token with scope "check" is required (opts.token or RATEGUARD_TOKEN)');
  }

  return async function rateGuardMiddleware(req, res, next) {
    const body = {
      method: req.method,
      path: req.originalUrl.split('?')[0],
      host: req.hostname,
      api_key: req.get(apiKeyHeader) || undefined,
      ip: req.ip,
      cost: 1,
    };

    let decision;
    try {
      const resp = await fetch(checkUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!resp.ok) {
        throw new Error(`check API returned HTTP ${resp.status}`);
      }
      decision = await resp.json();
    } catch (err) {
      console.warn(`rateguard: check failed, failing open: ${err.message}`);
      return next();
    }

    for (const [name, value] of Object.entries(decision.headers || {})) {
      res.set(name, value);
    }

    if (decision.allowed === false) {
      res.status(429).json({
        error: 'rate_limited',
        message: 'Rate limit exceeded',
        policy: decision.policy_id,
        limit: decision.limit,
        remaining: decision.remaining,
        retry_after_s: decision.retry_after_s,
        reset_s: decision.reset_s,
      });
      return;
    }

    return next();
  };
}

module.exports = { rateGuard };
