# Cloudflare backend

This folder contains the API for the «Ну-ка, все вместе!» website.

## Services

- **Workers** runs the API and validates administrator access.
- **D1** stores the shared archive.
- **R2** stores uploaded images separately from the archive.
- **GitHub Actions** deploys the Worker after the Cloudflare secrets are configured.

The public API is `GET /api/participants`. Administrator endpoints use a short-lived signed bearer token:
- `POST /api/login` with `{"password":"..." }`
- `GET /api/admin/participants`
- `PUT /api/admin/participants` with `{"participants":[...]}`
- `POST /api/admin/upload` as multipart form data with field `file`

## One-time Cloudflare setup

1. Create a Cloudflare account and open **Workers & Pages**.
2. Create a D1 database named `nukavsevmeste-db`.
3. Copy its database ID into `wrangler.toml`, replacing `REPLACE_WITH_CLOUDFLARE_D1_DATABASE_ID`.
4. Create an R2 bucket named `nukavsevmeste-images`.
5. In the repository's **Settings → Secrets and variables → Actions**, add:
   - `CLOUDFLARE_API_TOKEN` — token with permission to deploy Workers and manage D1/R2 resources used by Wrangler.
   - `CLOUDFLARE_ACCOUNT_ID` — your Cloudflare account ID.
6. In Cloudflare Worker settings, add secrets:
   - `ADMIN_PASSWORD` — a new, unique administrator password (do not reuse a GitHub password).
   - `SESSION_SECRET` — a long random secret, at least 32 characters.
7. Set `ALLOWED_ORIGIN` in `wrangler.toml` to the exact origin of the live GitHub Pages site.
8. Apply the schema once from the repository root:
   `npx wrangler d1 execute nukavsevmeste-db --remote --file=worker/schema.sql`
9. Deploy with:
   `npx wrangler deploy`

## GitHub Actions deployment

The workflow at `.github/workflows/deploy-worker.yml` deploys this Worker when backend files or `wrangler.toml` change on the default branch. The D1 schema is a one-time setup step and is not automatically re-applied on every deployment.

## Important

- Do not put API tokens, the administrator password, or the session secret in frontend JavaScript or commit them to Git.
- R2 images are served through the Worker at immutable `/images/...` URLs.
- The API rejects Base64 data URLs in the archive. Upload images first, then save their returned URLs in `photo` and `photos`.
- The existing public pages still read `participants.json` until the frontend migration is completed and the Worker URL is configured. This staged setup does not switch the live website by itself.
- Before importing the real archive, make a backup. The repository's current `participants.json` file was returned by GitHub as empty, so the original archive must be located/exported before any migration. Do not initialize production data from an empty archive if the real data exists elsewhere.
