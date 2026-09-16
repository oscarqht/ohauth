import { NextRequest, NextResponse } from 'next/server';
import {
  describeMissingEnv,
  exchangeCodeForTokens,
  getProviderConfig,
  loadProviderEnv,
} from '@/lib/oauth';
import {
  buildWebOauthStorageScript,
  isExternalRedirectUrl,
  sanitizeWebRedirectTarget,
} from '@/lib/raindrop-web-auth';

type RouteContext = {
  params: Promise<{
    provider: string;
  }>;
};

type ResolvedParams = {
  provider?: string;
};

type ParsedState = {
  extensionId?: string;
  show_token?: boolean;
  webRedirectTo?: string;
};

type ProviderOutcome = 'success' | 'failure' | 'unknown';

function getProviderResultImage(
  providerId: string | undefined,
  outcome: ProviderOutcome,
) {
  if (!providerId) return '/img/provider-not-found.png';
  const base = providerId.toLowerCase();
  if (outcome === 'success') {
    if (base === 'google') return '/img/provider-google-success.png';
    if (base === 'raindrop') return '/img/provider-raindrop-success.png';
  }
  if (outcome === 'failure') {
    if (base === 'google') return '/img/provider-google-fail.png';
    if (base === 'raindrop') return '/img/provider-raindrop-fail.png';
  }
  return '/img/provider-not-found.png';
}

function parseState(state: string | null): ParsedState {
  if (!state) return {};
  try {
    const parsed = JSON.parse(state);
    if (parsed && typeof parsed === 'object') {
      const result: ParsedState = {};
      if ('extensionId' in parsed) {
        const extensionId = (parsed as Record<string, unknown>).extensionId;
        if (typeof extensionId === 'string' && extensionId.trim().length > 0) {
          result.extensionId = extensionId;
        }
      }
      if ('show_token' in parsed) {
        result.show_token = Boolean(
          (parsed as Record<string, unknown>).show_token,
        );
      }
      if ('webRedirectTo' in parsed) {
        const redirectTarget = sanitizeWebRedirectTarget(
          (parsed as Record<string, unknown>).webRedirectTo,
        );
        if (redirectTarget) {
          result.webRedirectTo = redirectTarget;
        }
      }
      return result;
    }
  } catch (error) {
    console.error('[callback] Failed to parse state', error);
  }
  return {};
}

function resolveProviderId(request: NextRequest, params?: ResolvedParams) {
  const fromParams = params?.provider;
  if (fromParams) return fromParams;
  const segments = request.nextUrl.pathname.split('/').filter(Boolean);
  return segments[1] ?? undefined; // /auth/{provider}/callback
}

function renderCardPage(
  title: string,
  message: string,
  options: {
    status?: number;
    providerId?: string;
    outcome?: ProviderOutcome;
    showHomeLink?: boolean;
    script?: string;
    token?: unknown;
  } = {},
) {
  const {
    status = 200,
    providerId,
    outcome = 'unknown',
    showHomeLink = false,
    script,
    token,
  } = options;
  const imageSrc = getProviderResultImage(providerId, outcome);
  const homeLink = showHomeLink
    ? '<p class="home"><a href="/">Return home</a></p>'
    : '';
  const scriptTag = script ? `<script>${script}</script>` : '';

  let output = '';
  if (token) {
    const tokenJson = JSON.stringify(token, null, 2);
    // Mask sensitive values in the token JSON
    const maskedJson = tokenJson.replace(
      /("(?:access_token|refresh_token|id_token|token)"\s*:\s*")([^"]+)(")/g,
      '$1••••••••••••••••••••$3'
    );
    output = `<div class="output">
    <button class="copy-btn" onclick="copyToClipboard()">Copy</button>
    <pre><code id="token-display">${maskedJson}</code></pre>
    <pre id="token-actual" style="display: none;">${tokenJson}</pre>
</div>
<script>
function copyToClipboard() {
  const text = document.getElementById('token-actual').textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector('.copy-btn');
    const originalText = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => {
      btn.textContent = originalText;
    }, 2000);
  }).catch(err => {
    console.error('Failed to copy: ', err);
    alert('Failed to copy to clipboard');
  });
}
</script>
`;
  }

  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover" />
    <title>${title}</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #ffffff;
        --fg: #0f172a;
        --card-bg: #ffffff;
        --card-border: #e2e8f0;
        --card-shadow: 0 24px 60px -25px rgba(15, 23, 42, 0.45);
        --muted: #334155;
        --link: #2563eb;
      }
      @media (prefers-color-scheme: dark) {
        :root {
          color-scheme: dark;
          --bg: #0b1220;
          --fg: #e2e8f0;
          --card-bg: #0f172a;
          --card-border: #1e293b;
          --card-shadow: 0 24px 60px -25px rgba(15, 23, 42, 0.75);
          --muted: #cbd5e1;
          --link: #93c5fd;
        }
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        background: var(--bg);
        font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
        color: var(--fg);
        padding: 24px;
      }
      .card {
        width: min(720px, 100%);
        background: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 16px;
        padding: 32px 28px;
        box-shadow: var(--card-shadow);
        text-align: center;
      }
      h1 {
        margin: 0 0 20px;
        font-size: 26px;
        color: var(--fg);
      }
      .image-wrap {
        display: flex;
        justify-content: center;
        margin: 12px 0 20px;
      }
      .image-wrap img {
        max-width: 420px;
        width: 100%;
        height: auto;
        border-radius: 12px;
      }
      .message {
        margin: 0;
        font-size: 16px;
        line-height: 1.6;
        color: var(--muted);
      }
      .home {
        margin-top: 18px;
        font-size: 14px;
      }
      .home a {
        color: var(--link);
        text-decoration: none;
        font-weight: 600;
      }
      .home a:hover { text-decoration: underline; }
      .output {
        margin-top: 20px;
        text-align: left;
        position: relative;
      }
      .copy-btn {
        position: absolute;
        top: 10px;
        right: 10px;
        padding: 5px 10px;
        border-radius: 5px;
        border: 1px solid var(--card-border);
        background: var(--card-bg);
        color: var(--fg);
        cursor: pointer;
      }
      pre {
        background: var(--bg);
        border: 1px solid var(--card-border);
        border-radius: 5px;
        padding: 10px;
        overflow-x: auto;
      }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>${title}</h1>
      <div class="image-wrap">
        <img src="${imageSrc}" alt="${title}" />
      </div>
      <div class="message">${message}</div>
      ${output}
      ${homeLink}
    </div>
    ${scriptTag}
  </body>
</html>`;

  return new NextResponse(html, {
    status,
    headers: { 'content-type': 'text/html; charset=UTF-8' },
  });
}

export async function GET(request: NextRequest, context: RouteContext) {
  const params = await context.params;
  const providerId = resolveProviderId(request, params);
  const provider = providerId ? getProviderConfig(providerId) : null;

  if (!provider) {
    const isDev = process.env.NODE_ENV !== 'production';
    return renderCardPage(
      'Provider not supported',
      `Unsupported provider "${providerId ?? 'undefined'}".`,
      {
        status: 404,
        showHomeLink: isDev,
        providerId,
        outcome: 'unknown',
      },
    );
  }

  const envResult = loadProviderEnv(provider.id);

  if (!envResult.ok) {
    console.error(
      `[callback] Missing credentials for ${provider.id}: ${describeMissingEnv(
        envResult.missing,
      )}`,
    );
    const isDev = process.env.NODE_ENV !== 'production';
    return renderCardPage(
      'Missing credentials',
      `Missing credentials: ${describeMissingEnv(envResult.missing)}.`,
      {
        status: 500,
        showHomeLink: isDev,
        providerId,
        outcome: 'failure',
      },
    );
  }

  const searchParams = request.nextUrl.searchParams;
  const providerError = searchParams.get('error');
  const code = searchParams.get('code');
  const stateParam = searchParams.get('state');
  const state = parseState(stateParam);

  if (providerError) {
    console.error(
      `[callback] Provider returned an error for ${provider.id}: ${providerError}`,
    );
    if (state.webRedirectTo && isExternalRedirectUrl(state.webRedirectTo)) {
      const target = new URL(state.webRedirectTo);
      target.searchParams.set('error', providerError);
      return NextResponse.redirect(target.toString());
    }
    const isDev = process.env.NODE_ENV !== 'production';
    return renderCardPage(
      'Authorization failed',
      `Provider returned an error: ${providerError}`,
      {
        status: 400,
        showHomeLink: isDev,
        providerId,
        outcome: 'failure',
      },
    );
  }

  if (!code) {
    console.error(`[callback] Missing authorization code for ${provider.id}`);
    if (state.webRedirectTo && isExternalRedirectUrl(state.webRedirectTo)) {
      const target = new URL(state.webRedirectTo);
      target.searchParams.set('error', 'Missing authorization code');
      return NextResponse.redirect(target.toString());
    }
    const isDev = process.env.NODE_ENV !== 'production';
    return renderCardPage(
      'Missing authorization code',
      'Authorization code was not provided.',
      {
        status: 400,
        showHomeLink: isDev,
        providerId,
        outcome: 'failure',
      },
    );
  }

  try {
    const tokens = await exchangeCodeForTokens(provider, envResult.env, code);
    console.log(`[callback] Tokens received for ${provider.id}`, tokens);

    const tokenObject =
      tokens && typeof tokens === 'object'
        ? (tokens as Record<string, unknown>)
        : null;
    const tokenStatus =
      tokenObject && typeof tokenObject.status === 'number'
        ? tokenObject.status
        : null;
    const tokenErrorMessage =
      tokenObject && typeof tokenObject.errorMessage === 'string'
        ? tokenObject.errorMessage
        : tokenObject && typeof tokenObject.error === 'string'
        ? (tokenObject.error as string)
        : null;
    const tokenFailed =
      (tokenObject && tokenObject.result === false) ||
      (tokenStatus !== null && tokenStatus >= 400);

    if (tokenFailed || tokenErrorMessage) {
      const message =
        tokenErrorMessage ??
        'The provider returned an error while exchanging the code for tokens.';
      console.error(
        `[callback] Token exchange returned an error payload for ${provider.id}`,
        tokens,
      );
      if (state.webRedirectTo && isExternalRedirectUrl(state.webRedirectTo)) {
        const target = new URL(state.webRedirectTo);
        target.searchParams.set('error', message);
        return NextResponse.redirect(target.toString());
      }
      const isDev = process.env.NODE_ENV !== 'production';
      return renderCardPage('Token exchange failed', message, {
        status: tokenStatus ?? 400,
        showHomeLink: isDev,
        providerId,
        outcome: 'failure',
      });
    }

    const extensionId = state.extensionId;
    if (!extensionId) {
      if (state.webRedirectTo) {
        if (isExternalRedirectUrl(state.webRedirectTo)) {
          const target = new URL(state.webRedirectTo);
          const tokenPayloadObj =
            tokens && typeof tokens === 'object'
              ? (tokens as Record<string, unknown>)
              : {};
          if (tokenPayloadObj.access_token) {
            target.searchParams.set(
              'access_token',
              String(tokenPayloadObj.access_token),
            );
          }
          if (tokenPayloadObj.refresh_token) {
            target.searchParams.set(
              'refresh_token',
              String(tokenPayloadObj.refresh_token),
            );
          }
          if (tokenPayloadObj.expires_in) {
            target.searchParams.set(
              'expires_in',
              String(tokenPayloadObj.expires_in),
            );
          }
          return NextResponse.redirect(target.toString());
        }

        const script = buildWebOauthStorageScript(
          provider.id,
          tokens,
          state.webRedirectTo,
        );

        if (script) {
          return renderCardPage(
            'Authentication complete',
            'Authentication complete. Redirecting back to the workspace.',
            { script, providerId, outcome: 'success' },
          );
        }
      }

      const showToken = state.show_token;
      if (showToken) {
        return renderCardPage(
          'Authentication complete',
          'You can close this page now.',
          { providerId, outcome: 'success', token: tokens },
        );
      }
      return renderCardPage(
        'Authentication complete',
        'You can close this page now.',
        { providerId, outcome: 'success' },
      );
    }

    const tokenPayload =
      tokens && typeof tokens === 'object'
        ? {
            access_token: (tokens as Record<string, unknown>).access_token,
            refresh_token: (tokens as Record<string, unknown>).refresh_token,
            expires_in: (tokens as Record<string, unknown>).expires_in,
          }
        : {};

    const script = `
      (() => {
        const payload = ${JSON.stringify({
          type: 'oauth_success',
          provider: provider.id,
          tokens: tokenPayload,
        })};
        const extensionId = ${JSON.stringify(extensionId)};
        const statusEl = document.getElementById('status');
        // postMessage lets the extension's own content script pick this up
        // even on browsers (e.g. Firefox) that don't support delivering
        // chrome.runtime.sendMessage(extensionId, ...) from a plain web page.
        window.postMessage(payload, window.location.origin);
        if (!window.chrome || !chrome.runtime || !chrome.runtime.sendMessage) {
          if (statusEl) statusEl.textContent = 'You can close this page now.';
          return;
        }
        try {
          chrome.runtime.sendMessage(extensionId, payload, {});
        } catch (err) {
          // Ignored: the postMessage above already covers this case.
        }
      })();
    `;

    return renderCardPage(
      'Authentication complete',
      'Authentication complete. You can close this page now.<span id="status"></span>',
      { script, providerId, outcome: 'success' },
    );
  } catch (error) {
    console.error(`[callback] Token exchange failed for ${provider.id}`, error);
    if (state.webRedirectTo && isExternalRedirectUrl(state.webRedirectTo)) {
      const target = new URL(state.webRedirectTo);
      target.searchParams.set(
        'error',
        'An error occurred while exchanging the authorization code for tokens.',
      );
      return NextResponse.redirect(target.toString());
    }
    const isDev = process.env.NODE_ENV !== 'production';
    return renderCardPage(
      'Token exchange failed',
      'An error occurred while exchanging the authorization code for tokens.',
      {
        status: 500,
        showHomeLink: isDev,
        providerId,
        outcome: 'failure',
      },
    );
  }
}
