# AgriLink API

## Start

1. Copy `.env.example` to `.env` and fill in the values.
2. Run `npm install`.
3. Run `npm start`.

The API connects to the `Agri_Link` MongoDB database named in `MONGODB_URI`, creates/updates the owner admin account from `ADMIN_EMAIL` and `ADMIN_PASSWORD` on startup, and exposes `GET /api/health`.

## Deployment

Deploy as a Node service (Render, Railway, or similar), configure the environment values above, then set `FRONTEND_URL` to the static frontend origin. Update the frontend's API URL to the deployed service URL.

SMS is a development log abstraction; no email or Brevo code is included. Market prices are marked as demo until a trusted provider adapter and credentials are supplied.
