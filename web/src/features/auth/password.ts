// Mirrors internal/auth/password.go. The server enforces the policy.
export const MIN_PASSWORD_LENGTH = 12;

const alphabet = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';

/** Random temporary password using the Web Crypto API (no modulo bias). */
export function generatePassword(length = 20): string {
  const limit = 256 - (256 % alphabet.length);
  const out: string[] = [];
  const buf = new Uint8Array(1);
  while (out.length < length) {
    crypto.getRandomValues(buf);
    const b = buf[0] ?? 255;
    if (b < limit) out.push(alphabet[b % alphabet.length] ?? 'x');
  }
  return out.join('');
}
