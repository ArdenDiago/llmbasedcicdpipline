const axios = require('axios');

const SANDBOX_URL =
  process.env.SANDBOX_DISPATCH_URL || 'http://agent:3001/dispatch';
const DISPATCH_TIMEOUT_MS = parseInt(
  process.env.SANDBOX_DISPATCH_TIMEOUT_MS || '5000',
  10,
);

function buildPayload(body) {
  const commits = Array.isArray(body.commits) ? body.commits : [];
  const changed = new Set();
  for (const c of commits) {
    for (const f of c.added || []) changed.add(f);
    for (const f of c.modified || []) changed.add(f);
    for (const f of c.removed || []) changed.add(f);
  }
  return {
    repo_url: body.repository && body.repository.clone_url,
    repo_full_name: body.repository && body.repository.full_name,
    branch:
      typeof body.ref === 'string'
        ? body.ref.replace(/^refs\/heads\//, '')
        : null,
    commit_sha: body.after || null,
    pusher: body.pusher && body.pusher.name,
    changed_files: Array.from(changed),
  };
}

async function dispatchToSandbox(payload) {
  return axios.post(SANDBOX_URL, payload, { timeout: DISPATCH_TIMEOUT_MS });
}

module.exports = { buildPayload, dispatchToSandbox, SANDBOX_URL };
