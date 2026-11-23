# Deployment: ctf.1337.is on Cloudflare

The site is live at **https://ctf.1337.is**, served by a single Cloudflare Worker
named `ctf` on your account. There is **no R2, no database, no build step**.

## How it works

The Worker is a thin proxy in front of this GitHub repo:

```
browser ──▶ ctf.1337.is (Worker "ctf") ──▶ raw.githubusercontent.com/gaulzi/ctftest/<branch>/…
```

- `GET /` → serves `portal/index.html`
- `GET /data.js`, `GET /flags.js` → the portal's data and flag-hash files
- `GET /challenges/…` → the evidence files, sent with `Content-Disposition: attachment` so they download
- Anything under `solutions/` or `generator/` is **refused by the Worker** (403), so the
  answer files are never served from the site. (They are still in the public repo — see below.)
- Responses are cached at Cloudflare's edge for 5 minutes.

The custom domain `ctf.1337.is` was attached to the Worker through the Workers
custom-domains API, which created the DNS record and the TLS certificate automatically.

## The Worker is pinned to a branch

The Worker fetches from branch **`claude/aviation-ctf-learning-i7u8pv`**. If you merge
this to `main` (or rename the branch), update the `BRANCH` constant in the Worker and
redeploy, or the site will 404.

## Updating the site

Because the Worker proxies GitHub, **you update the site just by pushing to the repo.**
Edit challenges or the portal, commit, push — the edge cache clears within 5 minutes
(or purge it from the Cloudflare dashboard for an instant update). No redeploy needed.

To change the Worker itself (routing, caching, the pinned branch), redeploy the script.
With Wrangler on your own machine:

```bash
npm i -g wrangler
wrangler login
# save the Worker source as worker.js, then:
wrangler deploy worker.js --name ctf --compatibility-date 2025-06-01
```

The current Worker source is reproduced in `deploy/worker.js` in this repo for reference.

## A note on the public repo and the flags

This repo is **public**, which is what lets the Worker read the files with no token.
The trade-off: the answer material is also public on github.com directly —
`solutions/FLAGS_SPOILERS.txt` and `generator/build.py` both contain every flag in clear
text, and the evidence files necessarily contain the flags (that is the puzzle).

For a cooperative practice range with your own team this is usually fine — you are not
going to grep your own answers. If you want it locked down, you have two options:

1. **Make the repo private.** Then raw GitHub stops serving anonymously, so the Worker
   needs a read-only GitHub token (store it as a Worker secret and switch the fetch to the
   GitHub Contents API). Ask and this can be wired up.
2. **Keep the repo public but remove the spoilers from it** (delete `solutions/`, and keep
   `generator/build.py` only on a private branch). The site keeps working; only the plain
   answer list goes away.

Either is a quick change — say which you prefer.
