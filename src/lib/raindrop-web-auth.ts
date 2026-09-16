export const RAINDROP_PROVIDER_ID = 'raindrop';

export type StoredProviderTokens = {
  provider: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
};

export function getProviderTokenStorageKey(providerId: string) {
  return `oh-auth:provider-tokens:${providerId}`;
}

export function isAllowedRedirectOrigin(originOrUrl: string): boolean {
  try {
    const parsed = new URL(originOrUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    const hostname = parsed.hostname.toLowerCase();
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '0.0.0.0' ||
      hostname.startsWith('192.168.') ||
      hostname.startsWith('10.') ||
      hostname.endsWith('.local') ||
      hostname === 'arcable.dev' ||
      hostname.endsWith('.arcable.dev') ||
      hostname === 'vercel.app' ||
      hostname.endsWith('.vercel.app')
    ) {
      return true;
    }

    const extraAllowed =
      process.env.ALLOWED_REDIRECT_ORIGINS?.split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean) || [];
    if (
      extraAllowed.includes(parsed.origin.toLowerCase()) ||
      extraAllowed.includes(hostname)
    ) {
      return true;
    }

    return false;
  } catch {
    return false;
  }
}

export function isExternalRedirectUrl(urlStr: string): boolean {
  try {
    const parsed = new URL(urlStr);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export function sanitizeWebRedirectTarget(
  value: unknown,
): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  if (trimmed.startsWith('//')) {
    return null;
  }

  if (trimmed.startsWith('/')) {
    return trimmed;
  }

  try {
    const url = new URL(trimmed);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return null;
    }
    if (isAllowedRedirectOrigin(url.origin)) {
      return trimmed;
    }
  } catch {
    return null;
  }

  return null;
}



export function toStoredProviderTokens(
  providerId: string,
  tokenPayload: unknown,
  options: {
    fallbackRefreshToken?: string;
    now?: number;
  } = {},
): StoredProviderTokens | null {
  if (!tokenPayload || typeof tokenPayload !== 'object') {
    return null;
  }

  const payload = tokenPayload as Record<string, unknown>;
  const accessToken = payload.access_token;
  const expiresIn = payload.expires_in;

  if (typeof accessToken !== 'string' || accessToken.trim().length === 0) {
    return null;
  }

  const expiresInSeconds =
    typeof expiresIn === 'number'
      ? expiresIn
      : typeof expiresIn === 'string'
      ? Number(expiresIn)
      : NaN;
  const now = options.now ?? Date.now();
  const safeExpiresInSeconds = Number.isFinite(expiresInSeconds)
    ? Math.max(expiresInSeconds, 60)
    : 60 * 60;

  const refreshToken =
    typeof payload.refresh_token === 'string'
      ? payload.refresh_token
      : options.fallbackRefreshToken ?? '';

  return {
    provider: providerId,
    accessToken,
    refreshToken,
    expiresAt: now + safeExpiresInSeconds * 1000,
  };
}

export function isStoredProviderTokenExpired(
  tokens: StoredProviderTokens | null,
  bufferMs = 60_000,
) {
  if (!tokens) {
    return true;
  }

  return tokens.expiresAt <= Date.now() + bufferMs;
}

export function areStoredProviderTokensEqual(
  left: StoredProviderTokens | null,
  right: StoredProviderTokens | null,
) {
  if (left === right) {
    return true;
  }

  if (!left || !right) {
    return false;
  }

  return (
    left.provider === right.provider &&
    left.accessToken === right.accessToken &&
    left.refreshToken === right.refreshToken &&
    left.expiresAt === right.expiresAt
  );
}

export function buildWebOauthStorageScript(
  providerId: string,
  tokenPayload: unknown,
  redirectTo: string,
) {
  const storedTokens = toStoredProviderTokens(providerId, tokenPayload);
  if (!storedTokens) {
    return null;
  }

  const storageKey = getProviderTokenStorageKey(providerId);

  return `(() => {
    const storageKey = ${JSON.stringify(storageKey)};
    const redirectTo = ${JSON.stringify(redirectTo)};
    const tokens = ${JSON.stringify(storedTokens)};

    try {
      window.localStorage.setItem(storageKey, JSON.stringify(tokens));
    } catch (error) {
      console.error('[callback] Failed to persist web tokens', error);
    }

    window.location.replace(redirectTo);
  })();`;
}
