# Frontend integration (Scried API)

## Where to read the API contract

After deployment, use these URLs (replace the hostname with the Render URL shown on the service page):

- Interactive Swagger UI: `https://<your-api-host>/docs`
- Raw OpenAPI JSON: `https://<your-api-host>/openapi.json`
- API base URL: `https://<your-api-host>/api/v1`
- Readiness check: `https://<your-api-host>/api/v1/health/ready`

The Swagger page is documentation, not the frontend's runtime API. The frontend should call the API base URL. The OpenAPI file describes paths relative to `/api/v1` and includes a bearer-auth scheme.

## Configure a Next.js frontend

Set this in the frontend project's `.env.local` for local development and in the frontend hosting provider for the deployed build:

```dotenv
NEXT_PUBLIC_SCRIED_API_BASE_URL=https://<your-api-host>/api/v1
```

Local example:

```dotenv
NEXT_PUBLIC_SCRIED_API_BASE_URL=http://localhost:8080/api/v1
```

It is safe for the base URL to be public. Never place a JWT signing secret, database URL, Redis URL, email provider key, or any other server secret in a `NEXT_PUBLIC_` variable.

## Minimal TypeScript client

```ts
const API_BASE_URL = process.env.NEXT_PUBLIC_SCRIED_API_BASE_URL;

if (!API_BASE_URL) {
  throw new Error("NEXT_PUBLIC_SCRIED_API_BASE_URL is not configured");
}

type ApiOptions = RequestInit & { accessToken?: string };

export async function scriedFetch<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  if (options.body && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  if (options.accessToken) {
    headers.set("Authorization", `Bearer ${options.accessToken}`);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
    cache: "no-store",
  });

  const contentType = response.headers.get("content-type") ?? "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const message = typeof payload === "object" && payload && "message" in payload
      ? String((payload as { message: unknown }).message)
      : `Scried API request failed (${response.status})`;
    throw new Error(message);
  }
  return payload as T;
}
```

Example listing public opportunities:

```ts
const result = await scriedFetch<{ status: string; data: { items: unknown[]; page: number; page_size: number; total: number } }>(
  "/opportunities?page=1&page_size=20",
);
```

Example authenticated request:

```ts
const result = await scriedFetch("/auth/me", { accessToken });
```

Example login:

```ts
const login = await scriedFetch<{
  status: string;
  data: { access_token: string; refresh_token: string; expires_in: number };
}>("/auth/login", {
  method: "POST",
  body: JSON.stringify({ email, password }),
});
```

Treat the access token as short-lived and the refresh token as a credential. Prefer keeping the access token in memory and the refresh token in a Secure, HttpOnly, SameSite cookie managed by a same-origin backend-for-frontend. The current starter returns tokens in JSON and does **not** yet set an HttpOnly refresh cookie, so do not put refresh tokens into logs, URLs, analytics, or browser localStorage. A direct browser client will need an agreed token-storage strategy before public launch.

## Consent and registration sequence

1. `GET /consent-documents/current` to render the exact currently published privacy notice and terms.
2. Obtain the current `version` field from the response's `data.documents` entries.
3. `POST /auth/register` with `consent_accepted: true` and `consent_version` set to that version. The server stores the wording snapshot; don't send client-authored legal wording as proof of consent.
4. The API creates an email-outbox record for email verification. Actual email delivery isn't configured in this starter until an outbox worker/provider is added. For testing, this is a deployment blocker for a complete self-service sign-up flow.

An admin must publish consent documents through `POST /admin/consent-documents` before students can register. Do not invent production privacy/terms wording for a real launch; have it reviewed and approved first.

## CORS on Render

In the API service's Render environment variables, set `CORS_ALLOWED_ORIGINS` to a comma-separated list of exact origins, with no paths and no trailing slash, for example:

```text
http://localhost:3000,https://scried-web-test.onrender.com
```

Use the actual frontend hostname from its hosting dashboard. Add every required development/staging origin explicitly. Do not use `*`.

## Interactive API testing

Open `/docs`, choose an endpoint, click **Try it out**, provide the request body, and execute. For authenticated endpoints, first call `POST /auth/login`, copy `data.access_token` from the response, click **Authorize**, and enter the token (Swagger adds the `Bearer` scheme for you). Use only test accounts and synthetic data. Do not enable authorization persistence on shared computers.
