#!/usr/bin/env bash
#
# Regenerates internal/realip/cloudflare_ips.txt from Cloudflare's published
# ranges (https://www.cloudflare.com/ips/).
#
# The list backs TRUSTED_PROXY_PRESET=cloudflare. A stale list is the failure in
# #40: a request arriving through a range that is not listed resolves to the edge
# address instead of the visitor, and the IP whitelist denies it.
#
# Usage: make update-cloudflare-ips   (or ./scripts/update-cloudflare-ips.sh)

set -euo pipefail

target="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/internal/realip/cloudflare_ips.txt"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

fetch() {
	local url="$1"
	local body
	body="$(curl --fail --silent --show-error --max-time 30 "$url")"
	# A truncated or error response must not overwrite a working list.
	if ! grep -qE '^[0-9a-fA-F:.]+/[0-9]+$' <<<"$body"; then
		echo "error: $url returned no CIDR ranges" >&2
		return 1
	fi
	printf '%s\n' "$body"
}

v4="$(fetch https://www.cloudflare.com/ips-v4/)"
v6="$(fetch https://www.cloudflare.com/ips-v6/)"

cat >"$tmp" <<EOF
# Cloudflare edge IP ranges.
#
# Source: https://www.cloudflare.com/ips-v4/ and https://www.cloudflare.com/ips-v6/
# Refreshed: $(date -u +%Y-%m-%d) (run \`make update-cloudflare-ips\` to refresh)
#
# Cloudflare changes this list rarely but does change it. A stale list shows up
# as the failure in #40 — a request through a newly added edge range resolves to
# the edge address instead of the visitor and is denied by the IP whitelist.

# IPv4
$v4

# IPv6
$v6
EOF

mv "$tmp" "$target"
trap - EXIT

echo "Wrote $target"
echo "Review the diff, then run: go test ./internal/realip/"
