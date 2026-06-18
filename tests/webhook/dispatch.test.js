const path = require('path');
const { buildPayload } = require('../../agent/webhook/dispatch');
const pushEvent = require('./fixtures/push_event.json');

describe('buildPayload', () => {
  test('extracts repo, branch, sha, pusher from push event', () => {
    const p = buildPayload(pushEvent);
    expect(p.repo_full_name).toBe('octocat/Hello-World');
    expect(p.repo_url).toBe('https://github.com/octocat/Hello-World.git');
    expect(p.branch).toBe('main');
    expect(p.commit_sha).toBe('abc123def456abc123def456abc123def4567890');
    expect(p.pusher).toBe('octocat');
  });

  test('dedupes changed files across commits', () => {
    const p = buildPayload(pushEvent);
    expect(p.changed_files.sort()).toEqual(
      ['README.md', 'app/auth.py', 'app/main.py', 'app/old.py'].sort(),
    );
  });

  test('handles missing fields gracefully', () => {
    const p = buildPayload({});
    expect(p.branch).toBeNull();
    expect(p.commit_sha).toBeNull();
    expect(p.changed_files).toEqual([]);
  });

  test('strips refs/heads/ prefix from branch', () => {
    const p = buildPayload({ ref: 'refs/heads/feature/x' });
    expect(p.branch).toBe('feature/x');
  });
});
