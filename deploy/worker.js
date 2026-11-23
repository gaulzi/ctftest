// Cloudflare Worker for ctf.1337.is
// Thin read-only proxy in front of this GitHub repo. No R2, no secrets.
// Deploy:  wrangler deploy deploy/worker.js --name ctf --compatibility-date 2025-06-01
// Update the site by pushing to the repo; this Worker only changes if routing changes.

const OWNER = "gaulzi", REPO = "ctftest", BRANCH = "claude/aviation-ctf-learning-i7u8pv";
const BASE = "https://raw.githubusercontent.com/" + OWNER + "/" + REPO + "/refs/heads/" + BRANCH + "/";

const CT = {
  html: "text/html; charset=utf-8", js: "text/javascript; charset=utf-8",
  txt: "text/plain; charset=utf-8", log: "text/plain; charset=utf-8",
  csv: "text/csv; charset=utf-8", nmea: "text/plain; charset=utf-8",
  jsonl: "application/x-ndjson", hashes: "text/plain; charset=utf-8",
  pcap: "application/vnd.tcpdump.pcap", png: "image/png",
  bin: "application/octet-stream", zip: "application/zip",
  gz: "application/gzip", pdf: "application/pdf", md: "text/markdown; charset=utf-8"
};

export default {
  async fetch(req) {
    const url = new URL(req.url);
    let p = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
    if (p === "") p = "index.html";

    let repoPath;
    if (p === "index.html" || p === "data.js" || p === "flags.js") repoPath = "portal/" + p;
    else if (p.startsWith("challenges/")) repoPath = p;
    else return new Response("Not found", { status: 404, headers: { "content-type": "text/plain" } });

    // never serve answers or the generator, even though they exist in the repo
    if (repoPath.includes("..") || /solutions|generator/i.test(repoPath))
      return new Response("Forbidden", { status: 403 });

    const gh = await fetch(BASE + repoPath, { cf: { cacheTtl: 300, cacheEverything: true } });
    if (!gh.ok) return new Response("Not found: " + p, { status: gh.status, headers: { "content-type": "text/plain" } });

    const ext = p.split(".").pop().toLowerCase();
    const h = new Headers();
    h.set("content-type", CT[ext] || "application/octet-stream");
    h.set("cache-control", "public, max-age=300");
    if (p.startsWith("challenges/"))
      h.set("content-disposition", 'attachment; filename="' + p.split("/").pop() + '"');
    return new Response(gh.body, { headers: h });
  }
};
