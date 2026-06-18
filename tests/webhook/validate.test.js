const crypto = require('crypto');
const { verifySignature } = require('../../agent/webhook/validate');

const SECRET = 'test-secret';

function sign(body, secret = SECRET) {
  return (
    'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex')
  );
}

describe('verifySignature', () => {
  const body = Buffer.from('{"hello":"world"}');

  test('accepts valid signature', () => {
    expect(verifySignature(body, sign(body), SECRET)).toBe(true);
  });

  test('rejects tampered body', () => {
    const sig = sign(body);
    const tampered = Buffer.from('{"hello":"evil"}');
    expect(verifySignature(tampered, sig, SECRET)).toBe(false);
  });

  test('rejects wrong secret', () => {
    expect(verifySignature(body, sign(body, 'other'), SECRET)).toBe(false);
  });

  test('rejects missing header', () => {
    expect(verifySignature(body, undefined, SECRET)).toBe(false);
  });

  test('rejects header without sha256= prefix', () => {
    const raw = crypto
      .createHmac('sha256', SECRET)
      .update(body)
      .digest('hex');
    expect(verifySignature(body, raw, SECRET)).toBe(false);
  });

  test('rejects when secret is empty', () => {
    expect(verifySignature(body, sign(body), '')).toBe(false);
  });
});
