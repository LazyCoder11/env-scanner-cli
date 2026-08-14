/**
 * Calculate Shannon Entropy of a string to measure randomness/character distribution.
 * High entropy (> 4.2) usually indicates generated secret keys, passwords, or hashes.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const charCounts: Map<string, number> = new Map();
  for (const char of str) {
    charCounts.set(char, (charCounts.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;

  for (const count of charCounts.values()) {
    const probability = count / len;
    entropy -= probability * Math.log2(probability);
  }

  return Math.round(entropy * 100) / 100;
}

/**
 * Masks a secret string for safe display in logs/terminal (e.g. "sk-proj-****...1234")
 */
export function maskSecret(secret: string): string {
  if (!secret) return '***';
  if (secret.length <= 8) {
    return secret.substring(0, 2) + '****';
  }
  const prefix = secret.substring(0, 7);
  const suffix = secret.substring(secret.length - 4);
  return `${prefix}****...${suffix}`;
}
