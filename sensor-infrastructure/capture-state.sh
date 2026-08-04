#!/usr/bin/env bash
set -euo pipefail

destination="${1:?usage: netforge-tpot-capture OUTPUT_DIRECTORY}"
install -d -m 0755 "$destination"
date -u +%FT%TZ > "$destination/captured-at.txt"
nft -j list ruleset > "$destination/nftables.json"
ss -H -lntup > "$destination/listening-sockets.txt"
ip -j address show > "$destination/addresses.json"
ip -j route show table all > "$destination/routes.json"
docker ps --no-trunc --format '{{json .}}' > "$destination/containers.jsonl"
docker image inspect $(docker images -q) > "$destination/images.json"
curl --connect-timeout 3 --max-time 5 --output /dev/null --write-out '%{http_code}\n' http://169.254.169.254/latest/meta-data/ > "$destination/metadata-probe.txt" 2>&1 || true
(cd "$destination" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum > manifest.sha256)
