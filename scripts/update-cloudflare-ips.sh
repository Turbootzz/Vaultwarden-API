#!/usr/bin/env bash
#
# Regenerates internal/realip/cloudflare_ips.txt from Cloudflare's published
# ranges (https://www.cloudflare.com/ips/).
#
# The list backs TRUSTED_PROXY_PRESET=cloudflare. A stale or truncated list is
# the failure in #40: a request arriving through a range that is not listed
# resolves to the edge address instead of the visitor, and the IP whitelist
# denies it. Every guard below exists so a bad fetch fails loudly rather than
# quietly replacing a working list.
#
# Usage: make update-cloudflare-ips   (or ./scripts/update-cloudflare-ips.sh)
#        --check exits non-zero on drift instead of writing (used by CI).

set -euo pipefail

check_only=false
if [[ "${1:-}" == "--check" ]]; then
	check_only=true
fi

target="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/internal/realip/cloudflare_ips.txt"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Cloudflare has published far more than these for years. The floors only need
# to be high enough that a truncated response cannot pass; they are not a
# prediction of the real count.
readonly MIN_V4=10
readonly MIN_V6=5

# fetch retrieves a range list and refuses anything that is not wholly CIDRs of
# the expected family. A partial body, an edge error page, or the wrong URL all
# fail here rather than being written out.
fetch() {
	local url="$1" family="$2" minimum="$3"
	local body count

	body="$(curl --fail --silent --show-error --max-time 30 "$url")"
	body="$(printf '%s\n' "$body" | sed '/^[[:space:]]*$/d')"

	# Every line, not just one: a truncated body ending mid-list would otherwise
	# pass on the strength of its first line.
	while IFS= read -r line; do
		if [[ ! "$line" =~ ^[0-9a-fA-F:.]+/[0-9]+$ ]]; then
			echo "error: $url returned a non-CIDR line: $line" >&2
			return 1
		fi
		# ':' separates the families; without this a v6 URL that redirects to the
		# v4 list (or vice versa) would swap the two unnoticed.
		if [[ "$family" == "v4" && "$line" == *:* ]]; then
			echo "error: $url returned an IPv6 range where IPv4 was expected: $line" >&2
			return 1
		fi
		if [[ "$family" == "v6" && "$line" != *:* ]]; then
			echo "error: $url returned an IPv4 range where IPv6 was expected: $line" >&2
			return 1
		fi
	done <<<"$body"

	count="$(grep -c . <<<"$body")"
	if ((count < minimum)); then
		echo "error: $url returned only $count ranges, expected at least $minimum (truncated?)" >&2
		return 1
	fi

	printf '%s\n' "$body"
}

v4="$(fetch https://www.cloudflare.com/ips-v4/ v4 "$MIN_V4")"
v6="$(fetch https://www.cloudflare.com/ips-v6/ v6 "$MIN_V6")"

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

if [[ "$check_only" == true ]]; then
	# The Refreshed: date differs on every run and is not drift.
	if diff <(grep -v '^# Refreshed:' "$target") <(grep -v '^# Refreshed:' "$tmp") >/dev/null; then
		echo "internal/realip/cloudflare_ips.txt is up to date"
		exit 0
	fi
	echo "internal/realip/cloudflare_ips.txt is stale — run: make update-cloudflare-ips" >&2
	diff <(grep -v '^# Refreshed:' "$target") <(grep -v '^# Refreshed:' "$tmp") || true
	exit 1
fi

# install, not mv: mktemp creates 0600 and mv would carry that onto a tracked
# source file, which //go:embed then cannot read under a different build user.
install -m 0644 "$tmp" "$target"

echo "Wrote $target"
echo "Review the diff, then run: go test ./internal/realip/"
