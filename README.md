# SkillSwap

The project serves the existing `index.html` from a same-origin Express server. The frontend uses root-relative `/api/...` and `/auth/...` URLs, so run it through this server rather than opening `index.html` as a `file://` URL or serving it from a separate static host.

## Run locally

1. Use Node.js 22.5 or newer.
2. Install dependencies with `npm install`.
3. Copy `.env.example` to `.env`.
4. Set `JWT_SECRET` and `SESSION_SECRET` to long random values, and configure the Google OAuth values below.
5. Start with `npm start`, then visit `http://localhost:3000`.

The server stores registered accounts in `data/skillswap.sqlite`. Passwords are hashed; OAuth credentials, session signing secrets, and JWT signing secrets are read only from environment variables.

## Google OAuth setup

Create an OAuth 2.0 Client ID with application type **Web application** in Google Cloud Console, then set these values in the server's `.env`:

```dotenv
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback
```

In the OAuth client's **Authorized redirect URIs**, add the exact value of `GOOGLE_CALLBACK_URL`, including scheme, host, port, path, and trailing-slash choice. For local development this is:

```text
http://localhost:3000/auth/google/callback
```

For production, use the public HTTPS callback URL and register that exact URL in Google Cloud Console. If you configure **Authorized JavaScript origins**, use the frontend's origin (locally `http://localhost:3000`); this app uses the server-side authorization-code flow, so the redirect URI is the required OAuth URL. Configure the OAuth consent screen and add test users if the app remains in Testing status.

Restart the server after changing `.env`. The server exposes `GET /api/auth/google`, begins the authorization-code flow at `GET /auth/google`, handles Google's callback at `GET /auth/google/callback`, and exchanges a short-lived one-time ticket at `POST /api/auth/google/exchange`. OAuth state is stored in a short-lived server-side session; exchange tickets are held in process memory. The default session store is also in-memory, so use a shared session store and ticket store for a multi-instance deployment.

## Scope

This backend implements account registration, email/password login, token validation, Google OAuth, and authenticated user listing. The other marketplace endpoints referenced by the prototype UI (matches, requests, reviews, requirements, applications, messages, and admin statistics) are not implemented by this authentication-focused server.

## Tests

Run `npm test` to exercise frontend serving, registration/password login, token validation, OAuth state validation, callback handling, one-time ticket exchange, and API error responses. The OAuth test uses a stub provider; a real Google sign-in also requires valid credentials and an OAuth consent-screen test user.
