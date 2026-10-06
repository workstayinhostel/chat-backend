# Chat server

Node.js API and WebSocket backend using MongoDB, verified Google sign-in, encrypted message/media content, group chats, and WebRTC call signaling.

App sign-in tokens expire after 30 days. The legacy `/api/upload` endpoint stores encrypted media in MongoDB (maximum upload size: 15 MB). The browser `mediaUtils.js` utility resizes and compresses images before uploading them to Supabase Storage. Message receipts progress from stored (`Sent`) to recipient-confirmed (`Delivered`) to chat-opened (`Seen`); ending or declining a call ends it for all participants.

## Run locally

1. Install Node.js 20 or newer and make a copy of `.env.example` named `.env`.
2. Copy the complete MongoDB connection string from Atlas (**Database → Connect → Drivers**) into `MONGO_URI`, and configure your Google OAuth **Web application** client ID in `.env`. Replace any `<db_username>` / `<db_password>` placeholders with the Atlas database user credentials; percent-encode reserved characters in the username or password. In Atlas, allow the deployment service's outbound IPs (or use the appropriate network access policy) in Network Access.
   On Render, set `MONGO_URI` in the service's Environment settings to the same complete Atlas connection string. If an SRV URI still fails with `querySrv ETIMEOUT _mongodb._tcp...`, use the non-SRV `mongodb://` connection string supplied by Atlas under its **Standard connection string** option; switching to an SRV URI does not bypass a blocked or failing SRV DNS lookup. `MONGO_DNS_SERVERS` is optional for SRV connections where custom DNS resolvers are required.
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

## Supabase image uploads

Set `SUPABASE_URL` and a newly rotated `SUPABASE_SECRET_KEY` in the server environment. The secret key is used only by the server to mint short-lived, user-scoped upload URLs; never put it in frontend configuration. Set `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`, and (if the API is on another origin) `VITE_API_URL` in the frontend build environment. Import `uploadImage` from `mediaUtils.js` and call it with the selected `File`. The HTTP-only `chat_token` cookie authenticates the upload-ticket and completion requests. Serve the API and frontend over HTTPS so the `Secure` cookie is sent for WebSocket upgrades.

Create the `metufy` bucket in Supabase Storage and make it public if clients should receive durable, directly displayable URLs (the completion endpoint returns a public URL). Upload writes use signed upload tokens; do not add an unrestricted anonymous upload policy. Use `uploadConversationImage(file)` for chat images or `uploadProfilePhoto(file)` for profile photos. Objects are stored under `conversations/<user-id>/` and `profiles/<user-id>/` respectively; successful profile photo uploads also update the user's `avatarUrl`. Both helpers return `{ id, fileKey, url, mime, size, folder }`. Compressed images may be any size up to 500,000 bytes; there is no minimum size.

The WebSocket accepts cookie-authenticated `SEND_MESSAGE`, `MARK_READ`, and `WEBRTC_SIGNAL` events and emits `SEND_MESSAGE_ACK`, `MESSAGE`, `MESSAGES_READ`, `PRESENCE`, and `WEBRTC_SIGNAL` events. Existing short-form client events remain supported. Short-form `typing` events are relayed to chat recipients, and the server emits `typing_stop` 500 ms after the sender's latest typing event; clients should clear the indicator when they receive it. Send `{ "t": "typing", "typing": false, ... }` to stop the indicator immediately.

## MongoDB data

Mongoose stores users, groups, chats, messages, media, and call records in separate collections. Existing groups and direct conversations are backfilled into the `chats` collection on startup. Message and media payloads are encrypted with AES-256-GCM before being stored; keep `ENC_KEY` backed up securely because losing it makes those payloads unreadable. Changing `JWT_SECRET` signs out existing sessions.

## Security and deployment notes

- Keep `.env` private and never commit database passwords, OAuth secrets, JWT keys, or encryption keys. The Google client secret is not needed to verify Google ID tokens and must never be sent to the browser.
- Use a strong, unique Atlas database password and restrict Atlas Network Access; rotate any database credential that has been shared.
- Google sign-in accepts only verified Google ID tokens for the configured client ID. Do not use the token payload or client-supplied email as proof of identity.
- Calls use the WebSocket server for signaling only. The browser client must implement WebRTC media; add a TURN service for reliable calling across restrictive NATs. Call membership currently lives in server memory, so use a shared signaling/presence layer before running multiple server instances.
