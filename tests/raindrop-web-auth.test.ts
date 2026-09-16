import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  areStoredProviderTokensEqual,
  buildWebOauthStorageScript,
  getProviderTokenStorageKey,
  isAllowedRedirectOrigin,
  isExternalRedirectUrl,
  sanitizeWebRedirectTarget,
  toStoredProviderTokens,
} from '../src/lib/raindrop-web-auth';

describe('sanitizeWebRedirectTarget', () => {
  it('accepts same-origin relative paths', () => {
    assert.equal(sanitizeWebRedirectTarget('/raindrop'), '/raindrop');
    assert.equal(
      sanitizeWebRedirectTarget('/raindrop?source=web'),
      '/raindrop?source=web',
    );
  });

  it('accepts allowed external origins', () => {
    assert.equal(
      sanitizeWebRedirectTarget('http://localhost:3000/'),
      'http://localhost:3000/',
    );
    assert.equal(
      sanitizeWebRedirectTarget('http://127.0.0.1:5173/auth/callback'),
      'http://127.0.0.1:5173/auth/callback',
    );
    assert.equal(
      sanitizeWebRedirectTarget('https://arcable.dev/'),
      'https://arcable.dev/',
    );
    assert.equal(
      sanitizeWebRedirectTarget('https://arcable.vercel.app/'),
      'https://arcable.vercel.app/',
    );
  });

  it('rejects external or malformed redirect targets', () => {
    assert.equal(sanitizeWebRedirectTarget('https://example.com'), null);
    assert.equal(sanitizeWebRedirectTarget('//example.com'), null);
    assert.equal(sanitizeWebRedirectTarget('raindrop'), null);
    assert.equal(sanitizeWebRedirectTarget(undefined), null);
    assert.equal(sanitizeWebRedirectTarget('javascript:alert(1)'), null);
  });
});


describe('toStoredProviderTokens', () => {
  it('normalizes token payloads into stored web tokens', () => {
    const tokens = toStoredProviderTokens(
      'raindrop',
      {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
      },
      { now: 1_000 },
    );

    assert.deepEqual(tokens, {
      provider: 'raindrop',
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      expiresAt: 3_601_000,
    });
  });

  it('keeps the existing refresh token when the refresh response omits it', () => {
    const tokens = toStoredProviderTokens(
      'raindrop',
      {
        access_token: 'access-token',
        expires_in: '120',
      },
      {
        fallbackRefreshToken: 'existing-refresh-token',
        now: 5_000,
      },
    );

    assert.deepEqual(tokens, {
      provider: 'raindrop',
      accessToken: 'access-token',
      refreshToken: 'existing-refresh-token',
      expiresAt: 125_000,
    });
  });
});

describe('buildWebOauthStorageScript', () => {
  it('builds a script that persists tokens and redirects', () => {
    const script = buildWebOauthStorageScript(
      'raindrop',
      {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
      },
      '/raindrop',
    );

    assert.ok(script);
    assert.ok(script?.includes(getProviderTokenStorageKey('raindrop')));
    assert.ok(script?.includes('/raindrop'));
    assert.ok(script?.includes('window.localStorage.setItem'));
    assert.ok(script?.includes('window.location.replace'));
  });
});

describe('areStoredProviderTokensEqual', () => {
  it('treats equivalent token payloads as equal even when they are different objects', () => {
    const left = {
      provider: 'raindrop',
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      expiresAt: 3_601_000,
    };
    const right = { ...left };

    assert.equal(areStoredProviderTokensEqual(left, right), true);
  });

  it('detects when any persisted token field changes', () => {
    const base = {
      provider: 'raindrop',
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      expiresAt: 3_601_000,
    };

    assert.equal(
      areStoredProviderTokensEqual(base, {
        ...base,
        accessToken: 'new-access-token',
      }),
      false,
    );
    assert.equal(
      areStoredProviderTokensEqual(base, {
        ...base,
        refreshToken: 'new-refresh-token',
      }),
      false,
    );
    assert.equal(
      areStoredProviderTokensEqual(base, {
        ...base,
        expiresAt: 9_999_000,
      }),
      false,
    );
  });
});
