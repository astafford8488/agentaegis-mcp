#!/usr/bin/env bash
# H1 — Subdomain takeover scan
#
# Enumerate all *.agentaegis.org subdomains and check for dangling CNAMEs.
# A dangling CNAME (points at a hostname the attacker can claim) lets an
# attacker serve content on our subdomain.
#
# Known subdomains that should resolve:
#   www.agentaegis.org     → Vercel (marketing)
#   app.agentaegis.org     → Vercel (portal)
#   status.agentaegis.org  → Better Stack
#
# Tooling: dig + subjack (or subzy as alternative)
#
# Install subjack: go install github.com/haccer/subjack@latest
#
# Output: audit/red-team/results/<DATE>-h1-subdomain-takeover.txt

set -euo pipefail

DOMAIN="agentaegis.org"
OUTDIR="$(dirname "$0")/../results"
DATE=$(date +%F)
OUT="$OUTDIR/${DATE}-h1-subdomain-takeover.txt"

mkdir -p "$OUTDIR"

echo "=== Subdomain enumeration for $DOMAIN ===" > "$OUT"
echo "Started: $(date -u +%FT%TZ)" >> "$OUT"
echo "" >> "$OUT"

# 1. Pull subdomains we know about from public sources
echo "--- Known subdomains (manual list) ---" >> "$OUT"
KNOWN_SUBS=(
  "www.$DOMAIN"
  "app.$DOMAIN"
  "status.$DOMAIN"
  "$DOMAIN"
)

for sub in "${KNOWN_SUBS[@]}"; do
  echo "" >> "$OUT"
  echo "### $sub" >> "$OUT"
  echo "" >> "$OUT"
  echo "CNAME chain:" >> "$OUT"
  dig +short CNAME "$sub" >> "$OUT" 2>&1 || echo "  (no CNAME)" >> "$OUT"
  echo "" >> "$OUT"
  echo "A records:" >> "$OUT"
  dig +short A "$sub" >> "$OUT" 2>&1 || echo "  (no A records)" >> "$OUT"
  echo "" >> "$OUT"
  echo "HTTP HEAD:" >> "$OUT"
  curl -sI --max-time 10 "https://$sub" 2>&1 | head -5 >> "$OUT" || echo "  (request failed)" >> "$OUT"
done

# 2. Enumerate via crt.sh certificate transparency
echo "" >> "$OUT"
echo "--- Subdomains via crt.sh (cert transparency) ---" >> "$OUT"
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null \
  | python3 -c "import json, sys; data = json.load(sys.stdin); subs = sorted(set(n for entry in data for n in entry.get('name_value','').split('\n'))); print('\n'.join(subs))" \
  >> "$OUT" 2>/dev/null || echo "(crt.sh unavailable or python3 missing)" >> "$OUT"

# 3. Run subjack if installed
echo "" >> "$OUT"
echo "--- subjack scan ---" >> "$OUT"
if command -v subjack >/dev/null 2>&1; then
  # Build a wordlist of subdomains discovered above
  TMPLIST=$(mktemp)
  printf '%s\n' "${KNOWN_SUBS[@]}" > "$TMPLIST"

  subjack -w "$TMPLIST" -t 10 -timeout 30 -ssl -o "${OUT%.txt}-subjack.json" -v 2>&1 | tee -a "$OUT" || true
  rm "$TMPLIST"
else
  echo "subjack not installed. Install: go install github.com/haccer/subjack@latest" >> "$OUT"
  echo "Manual review: confirm each CNAME above resolves to its claimed provider." >> "$OUT"
fi

# 4. Summary
echo "" >> "$OUT"
echo "=== Summary ===" >> "$OUT"
echo "Manual review needed: confirm each CNAME points at a claimed (non-dangling) provider." >> "$OUT"
echo "Specifically watch for:" >> "$OUT"
echo "  - status.$DOMAIN: should CNAME to Better Stack (e.g., *.betteruptime.com or *.betterstackapp.com)" >> "$OUT"
echo "  - app.$DOMAIN: should CNAME to Vercel (cname.vercel-dns.com)" >> "$OUT"
echo "  - www.$DOMAIN: should CNAME to Vercel (cname.vercel-dns.com)" >> "$OUT"
echo "" >> "$OUT"
echo "If any CNAME resolves to a domain we don't actively own (deleted Better Stack page, abandoned Vercel project, etc), that's a P1 finding." >> "$OUT"
echo "Finished: $(date -u +%FT%TZ)" >> "$OUT"

echo ""
echo "Wrote: $OUT"
echo ""
echo "Quick view:"
tail -20 "$OUT"
