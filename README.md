# Chat server

Node.js API and WebSocket backend using MongoDB, verified Google sign-in, encrypted message/media content, group chats, and WebRTC call signaling.

App sign-in tokens expire after 30 days. Image uploads are stored without resizing or recompression (maximum upload size: 15 MB), and displayed with their original aspect ratio. Message receipts progress from stored (`Sent`) to recipient-confirmed (`Delivered`) to chat-opened (`Seen`); ending or declining a call ends it for all participants.

## Run locally

1. Install Node.js 20 or newer and make a copy of `.env.example` named `.env`.
2. Configure your MongoDB Atlas cluster hostname, database username/password, and Google OAuth **Web application** client ID in `.env`. In Atlas, allow the development machine's IP in Network Access.
   `MONGO_DNS_SERVERS` is optional; set it to comma-separated DNS server IPs only if Node.js cannot resolve Atlas SRV records on your network.
3. Generate fresh secrets in PowerShell:

   ```powershell
   node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

   Use the first output for `JWT_SECRET` and the second for `ENC_KEY`.
4. Set `ORIGIN` to the frontend's exact origin(s). For LAN/mobile development, allow `http://192.168.1.83:8000` and `http://localhost:8000`, then run:

   ```powershell
   npm install
   npm start
   ```

   For development with automatic restart, run `npm run dev`.

The API listens on port `4000` by default; its WebSocket endpoint is `/ws`. For mobile testing, connect the phone and development computer to the same Wi-Fi network and open `http://192.168.1.83:8000` on the phone. The Vite dev server binds to all network interfaces, and the client uses the current page's hostname for API/WebSocket connections. Google login expects a Google Identity Services ID token in `{ "credential": "..." }` at `POST /api/auth/google`. Send the returned app JWT as `Authorization: Bearer <token>` for HTTP APIs. The first sign-in creates a MongoDB `users` record; complete profile setup at `POST /api/auth/setup`.

## MongoDB data

Mongoose stores users, groups, chats, messages, media, and call records in separate collections. Existing groups and direct conversations are backfilled into the `chats` collection on startup. Message and media payloads are encrypted with AES-256-GCM before being stored; keep `ENC_KEY` backed up securely because losing it makes those payloads unreadable. Changing `JWT_SECRET` signs out existing sessions.

## Security and deployment notes

- Keep `.env` private and never commit database passwords, OAuth secrets, JWT keys, or encryption keys. The Google client secret is not needed to verify Google ID tokens and must never be sent to the browser.
- Use a strong, unique Atlas database password and restrict Atlas Network Access; rotate any database credential that has been shared.
- Google sign-in accepts only verified Google ID tokens for the configured client ID. Do not use the token payload or client-supplied email as proof of identity.
- Calls use the WebSocket server for signaling only. The browser client must implement WebRTC media; add a TURN service for reliable calling across restrictive NATs. Call membership currently lives in server memory, so use a shared signaling/presence layer before running multiple server instances.
