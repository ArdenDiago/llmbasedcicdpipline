const express = require('express');
const rateLimit = require('express-rate-limit');
const { verifySignature } = require('./validate');
const { buildPayload, dispatchToSandbox } = require('./dispatch');

const PORT = parseInt(process.env.PORT || '3000', 10);
const MAX_PAYLOAD_BYTES =
  parseInt(process.env.MAX_PAYLOAD_MB || '5', 10) * 1024 * 1024;
const RATE_LIMIT_PER_MIN = parseInt(
  process.env.RATE_LIMIT_PER_MIN || '100',
  10,
);
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

const app = express();
app.disable('x-powered-by');

const limiter = rateLimit({
  windowMs: 60 * 1000,
  limit: RATE_LIMIT_PER_MIN,
  standardHeaders: true,
  legacyHeaders: false,
});

app.get('/health', (_req, res) => res.status(200).json({ ok: true }));

app.post(
  '/webhook',
  limiter,
  express.raw({ type: 'application/json', limit: MAX_PAYLOAD_BYTES }),
  async (req, res) => {
    if (!WEBHOOK_SECRET) {
      console.error('[webhook] WEBHOOK_SECRET is not configured');
      return res.status(500).send('Server misconfigured');
    }

    const event = req.header('X-GitHub-Event');
    if (event !== 'push') {
      return res.status(204).end();
    }

    const signature = req.header('X-Hub-Signature-256');
    if (!verifySignature(req.body, signature, WEBHOOK_SECRET)) {
      console.warn(`[webhook] rejected: invalid signature from ${req.ip}`);
      return res.status(401).send('Invalid signature');
    }

    let parsed;
    try {
      parsed = JSON.parse(req.body.toString('utf8'));
    } catch {
      return res.status(400).send('Invalid JSON');
    }

    const payload = buildPayload(parsed);
    const shortSha = (payload.commit_sha || '').slice(0, 7);
    console.log(
      `[webhook] push ${payload.repo_full_name}@${payload.branch} sha=${shortSha} files=${payload.changed_files.length}`,
    );

    res.status(200).send('accepted');

    dispatchToSandbox(payload).catch((err) => {
      console.error(`[dispatch] failed: ${err.message}`);
    });
  },
);

app.use((err, _req, res, _next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).send('Payload too large');
  }
  console.error('[webhook] error:', err);
  res.status(500).send('Internal error');
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[webhook] listening on :${PORT}`);
  });
}

module.exports = app;
