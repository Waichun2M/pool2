# pool2 — second proxy node pool (auto-updating)

Aggregates public subscription sources, keeps only **US / JP / KR / TW**
nodes, TCP-liveness-tests them inside GitHub Actions, and publishes the
survivors as a plain share-link list.

**Fixed consumer URL** (what the edgetunnel panel / clients should read):

```
https://raw.githubusercontent.com/Waichun2M/pool2/main/nodes.txt
```

## How it stays fresh

- `.github/workflows/update.yml` runs **every 6 hours**, on manual
  dispatch, and whenever `aggregate.py` / `sources.txt` change.
- Each run: fetch every source in `sources.txt` → parse
  vless/vmess/trojan/ss/hysteria2 links → dedupe → country filter
  (node-name flags/keywords/cities first, IP geolocation fallback) →
  TCP connect test → cap 400 (US first, JP/KR/TW balanced).
- `status.json` is rewritten every run with fetch/alive/final counts
  per country, so pool health is visible at a glance.

## Anti-wipe rule

If a run ends with fewer than **30** qualified nodes, `nodes.txt` is
**not** overwritten — the previous version stays in place and only
`status.json` records the bad run. A source outage can never empty
the pool.

## Maintaining sources

Edit `sources.txt` (one URL per line, `#` = comment) and push; the
pipeline re-runs automatically. Dead sources are tolerated and are
listed under `sources_failed` in `status.json`.

This pool complements the VPN Gate-based pool (quality, accurate
landing); pool2 is for quantity/coverage of the four regions.
