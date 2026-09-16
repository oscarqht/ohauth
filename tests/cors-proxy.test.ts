import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { NextRequest } from 'next/server';
import { proxy, buildCorsHeaders } from '../src/proxy';

describe('CORS Proxy / Middleware', () => {
  it('handles OPTIONS preflight requests from an origin with 204 and CORS headers', () => {
    const request = new NextRequest('https://oh-auth.vercel.app/auth/raindrop/refresh', {
      method: 'OPTIONS',
      headers: {
        origin: 'http://localhost:3000',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type,authorization',
      },
    });

    const response = proxy(request);

    assert.equal(response.status, 204);
    assert.equal(response.headers.get('access-control-allow-origin'), 'http://localhost:3000');
    assert.equal(response.headers.get('access-control-allow-credentials'), 'true');
    assert.equal(response.headers.get('access-control-allow-headers'), 'content-type,authorization');
    assert.ok(response.headers.get('access-control-allow-methods')?.includes('POST'));
    assert.ok(response.headers.get('access-control-allow-methods')?.includes('OPTIONS'));
    assert.equal(response.headers.get('access-control-max-age'), '86400');
    assert.equal(response.headers.get('vary'), 'Origin');
  });

  it('attaches CORS headers for requests with an Origin header', () => {
    const request = new NextRequest('https://oh-auth.vercel.app/auth/raindrop/refresh', {
      method: 'POST',
      headers: {
        origin: 'https://my-frontend-app.com',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ refresh_token: 'dummy' }),
    });

    const response = proxy(request);

    assert.equal(response.headers.get('access-control-allow-origin'), 'https://my-frontend-app.com');
    assert.equal(response.headers.get('access-control-allow-credentials'), 'true');
    assert.equal(response.headers.get('vary'), 'Origin');
  });

  it('uses wildcard origin when no Origin header is provided', () => {
    const headers = buildCorsHeaders(
      new NextRequest('https://oh-auth.vercel.app/auth/raindrop/refresh', {
        method: 'POST',
      }),
    );

    assert.equal(headers['Access-Control-Allow-Origin'], '*');
    assert.equal(headers['Access-Control-Allow-Credentials'], undefined);
  });
});
