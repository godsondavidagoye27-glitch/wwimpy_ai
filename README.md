<<<<<<< HEAD
# wimpy-ai
=======
# WIMPY — Local server + OpenAI proxy

This repo contains a single-page WIMPY frontend (`wimpy.html`) and a small Node/Express proxy (`server.js`) that securely forwards chat requests to OpenAI using a server-side API key.

How it works
- The frontend (`wimpy.html`) calls `/api/chat` on the same origin.
- The Express server (`server.js`) attaches your `OPENAI_API_KEY` (from `.env`) and forwards the request to OpenAI's Chat Completions endpoint.

Setup (Windows PowerShell)

1. Copy `.env.example` to `.env` and set either an OpenAI or OpenRouter key:

```powershell
cp .env.example .env
# then edit .env and set either OPENAI_API_KEY or OPENROUTER_API_KEY
# Example (OpenAI):
# OPENAI_API_KEY=sk-...
# Example (OpenRouter):
# OPENROUTER_API_KEY=sk-or-...
```

2. Install dependencies and start the server:

```powershell
npm install
npm start
```

3. Open the app in your browser:

http://localhost:3000/wimpy.html

Notes
- Do NOT store your OpenAI key in `wimpy.html` — the proxy keeps it server-side.
- To enable Google Sign-In you still need to replace `YOUR_GOOGLE_CLIENT_ID` in `wimpy.html` with a valid client id.
 - To enable Google Sign-In you still need to replace `YOUR_GOOGLE_CLIENT_ID` in `wimpy.html` with a valid client id.
 - The server can verify Google ID tokens server-side to protect history endpoints. Set `GOOGLE_CLIENT_ID` in your `.env` to enable.
- For production, consider adding proper token verification, rate limiting, and secure deployment.
 - For production, consider adding proper token verification (done in this prototype), stricter rate limiting, and secure deployment.

Server features added in this update
- Server-side Google ID token verification (requires `GOOGLE_CLIENT_ID` in `.env`).
- History endpoints are tied to verified identity when an ID token is provided (Authorization: Bearer <id_token>). Local fallback remains for anonymous users.
- Pagination and delete endpoints for history: `GET /api/history?limit=50&offset=0`, `DELETE /api/history` (requires verification).
- IP quota stored in SQLite (`ip_quota` table) and basic DB-based per-minute quota. Configure via `MAX_PER_MINUTE` in `.env`.


Want an Electron desktop app?
- I can scaffold an Electron wrapper that serves the same local files and starts the proxy internally.
>>>>>>> 93bbf6c (WIMPY initial commit)
