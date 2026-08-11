### `How change detection works`

- Fetch the documentation page.
- Extract entries (id, title, content hash, category, URL).
- Compare against the previous snapshot for that category.
- If an id is new → added. If the hash differs → modified. If an id disappeared → removed.
- Store the new snapshot and, when diffs exist, prepend a change event to the history.
- Hashes are SHA-256 of a short text excerpt or the API name itself, depending on the extractor. This is enough to notice most documentation updates while keeping the scrape light.

  <img width="1222" height="637" alt="frontmonitor" src="https://github.com/user-attachments/assets/6c8aabbb-61f2-4f73-a3bc-f8c13ef77424" />

### `Monitored sources`

   Category    | URL |
  |-------------|-----|
  | extensions  | https://developer.chrome.com/docs/extensions/reference/api |
  | webstore    | https://developer.chrome.com/docs/webstore/api |
  | devtools    | https://chromedevtools.github.io/devtools-protocol/ |

- Extraction is tailored per source. For the extensions reference it primarily follows the ***`/docs/extensions/reference/api/...` links***.

- For the others it falls back to headings and link patterns. If nothing useful is found, a single page-level hash is stored so the cycle still completes.

### `Requirements`

- Node.js 18 or later

### `Usage`

- Two server implementations are included:

**Zero-dependency (recommended for a first run):**
      
            node server-standalone.js

**Express version (adds helmet, rate limiting, CORS helpers):**

            npm install
            node server.js

Open ***http://localhost:3000***

- The first monitoring cycle builds the baseline snapshots. No change events are emitted until a later cycle finds differences.

- The dashboard’s Tracked APIs tab shows the current inventory immediately after the first successful scrape; the Change History tab remains empty until real diffs appear.

- Default poll interval is 15 minutes. Frontend auto-refresh is 30 seconds.

### `API`

- All responses are JSON.

    | Method | Path | Description |
    |--------|------|-------------|
    | GET | `/health` | Liveness check. Returns `{ status, uptime }`. |
    | GET | `/api/status` | Monitoring flag, categories, last check time, total change events, current API count. |
    | GET | `/api/changes?limit=N` | Recent change events (default 20, max 100). |
    | GET | `/api/snapshot/:category` | Current snapshot for `extensions`, `webstore`, or `devtools`. |
    
- Invalid categories return 404. Rate limiting is applied to `/api/*` on the Express server (60 requests / 15 min per IP).

### `Persistence`

- Snapshots and change history are written to `./data/`:

- `Snapshots.json` — latest API list + hashes per category
- `History.json` — up to 100 most recent change events

- On startup the server reloads these files if present, so restarts do not lose the baseline.

### `Docker`

              docker compose up -d --build

- The compose file maps port 3000, mounts `./data` and `./logs`, and uses a Node-based healthcheck. The image runs as a non-root user.

### `Configuration`

    | Variable | Default | Notes |
    |----------|---------|-------|
    | `PORT` | 3000 | Listen port|
    | `NODE_ENV` | production (in Docker) | |
    | `ALLOWED_ORIGINS` | `*` (or comma-separated list) | CORS origins for the Express server |
    
- Poll interval and cache duration are constants inside the source (`POLL_INTERVAL`, `CACHE_DURATION`). Change them and restart if you need different timing.

### `Notice`

- The tool is under development, is provided "as is," and may have limitations.
