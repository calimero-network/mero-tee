import { describe, expect, test } from 'vitest';
import { validateKmsUrl, validateNodeUrl, defaults, parseAllowedHosts } from '../api/url-validation.js';

const kmsPatterns = parseAllowedHosts(undefined, defaults.DEFAULT_KMS_ALLOWED_HOSTS);
const nodePatterns = parseAllowedHosts(undefined, defaults.DEFAULT_NODE_ALLOWED_HOSTS);

describe('validateKmsUrl', () => {
  test('accepts allowed HTTPS host', () => {
    expect(() => validateKmsUrl('https://prod-kms.phala.network', kmsPatterns)).not.toThrow();
  });

  test('accepts localhost with HTTP for dev', () => {
    expect(() => validateKmsUrl('http://localhost:8080', kmsPatterns)).not.toThrow();
    expect(() => validateKmsUrl('http://127.0.0.1:8080', kmsPatterns)).not.toThrow();
  });

  test('rejects non-HTTPS remote hosts', () => {
    expect(() => validateKmsUrl('http://kms.phala.network', kmsPatterns)).toThrow(
      /must use HTTPS/i
    );
  });

  test('rejects disallowed host', () => {
    expect(() => validateKmsUrl('https://evil.example.com', kmsPatterns)).toThrow(
      /host not in allowed list/i
    );
  });
});

describe('validateNodeUrl', () => {
  test('accepts IPv4 node URL over HTTP', () => {
    expect(() => validateNodeUrl('http://34.65.123.45:80', nodePatterns)).not.toThrow();
  });

  test('accepts localhost node URL', () => {
    expect(() => validateNodeUrl('http://localhost:8080', nodePatterns)).not.toThrow();
    expect(() => validateNodeUrl('https://127.0.0.1:8080', nodePatterns)).not.toThrow();
  });

  test('rejects unsupported protocol', () => {
    expect(() => validateNodeUrl('ftp://127.0.0.1:80', nodePatterns)).toThrow(
      /must use HTTP or HTTPS/i
    );
  });

  test('rejects non-allowed hostname', () => {
    expect(() => validateNodeUrl('https://node.example.com', nodePatterns)).toThrow(
      /host not in allowed list/i
    );
  });
});
