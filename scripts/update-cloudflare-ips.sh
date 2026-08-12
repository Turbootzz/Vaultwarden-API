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
allow_shrink=false
for arg in "$@"; do
	case "$arg" in
	--check) check_only=true ;;
	--allow-shrink) allow_shrink=true ;;
	*)
		echo "usage: ${BASH_SOURCE[0]##*/} [--check] [--allow-shrink]" >&2
		exit 2
		;;
	esac
done

target="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/internal/realip/cloudflare_ips.txt"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# embedded_count reports how many ranges of a family the current list holds. The
# floor is derived from it rather than hardcoded: a fixed number is either too
# low to catch a partial truncation (dropping 5 of 15 ranges is still #40) or
# too high to survive Cloudflare legitimately retiring one. ':' picks the family.
embedded_count() {
	local family="$1"
	if [[ ! -f "$target" ]]; then
		echo 0
		return
	fi
	local ranges
	ranges="$(grep -vE '^[[:space:]]*(#|$)' "$target" || true)"
	# A here-string on an empty variable still feeds one empty line, which would
	# count as a range.
	if [[ -z "$ranges" ]]; then
		echo 0
		return
	fi
	if [[ "$family" == "v6" ]]; then
		grep -c ':' <<<"$ranges" || true
	else
		grep -cv ':' <<<"$ranges" || true
	fi
}

# Absolute backstops, in case the embedded list is itself missing or truncated.
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
		echo "error: $url returned $count ranges, fewer than the $minimum already embedded." >&2
		echo "       A truncated response that drops ranges reintroduces #40 for traffic" >&2
		echo "       arriving through them. If Cloudflare really retired a range, rerun" >&2
		echo "       with --allow-shrink." >&2
		return 1
	fi

	printf '%s\n' "$body"
}

# Never accept fewer ranges than are already trusted: every dropped range is one
# whose traffic starts resolving to the edge address and failing the whitelist.
floor_v4=$MIN_V4
floor_v6=$MIN_V6
if [[ "$allow_shrink" == false ]]; then
	have_v4="$(embedded_count v4)"
	have_v6="$(embedded_count v6)"
	# if, not `((...)) && assign`: a false arithmetic test returns non-zero, which
	# under set -e would abort the script rather than skip the assignment.
	if ((have_v4 > floor_v4)); then floor_v4=$have_v4; fi
	if ((have_v6 > floor_v6)); then floor_v6=$have_v6; fi
fi

v4="$(fetch https://www.cloudflare.com/ips-v4/ v4 "$floor_v4")"
v6="$(fetch https://www.cloudflare.com/ips-v6/ v6 "$floor_v6")"

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
