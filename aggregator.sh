#! /usr/bin/env bash
# Author: Sotirios Roussis <s.roussis@synapsecom.gr>

declare -r s_dir="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

declare -r netset_file_temp="$(mktemp)"
declare -r netset_file_output="${s_dir}/blacklist.lst"
declare -Ar netset_sources=(
    ["firehol-level1"]="https://github.com/firehol/blocklist-ipsets/raw/refs/heads/master/firehol_level1.netset"
    ["firehol-spamhaus-drop"]="https://github.com/firehol/blocklist-ipsets/raw/refs/heads/master/spamhaus_drop.netset"
    ["emergingthreats-compromised-ips"]="https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    ["cinsscore-ci-badguys"]="http://cinsscore.com/list/ci-badguys.txt"
    ["blocklist-de-all"]="https://lists.blocklist.de/lists/all.txt"
    ["hagezi-threat-intelligence-feeds"]="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt"
)

function cleanup() {
    rm -rf -- "${netset_file_temp}"
}

# Trap most common termination signals plus EXIT (0) and ERR
trap cleanup EXIT ERR INT TERM HUP QUIT PIPE

for cmd in curl; do
    ! hash "${cmd}" 2>/dev/null && {
        echo "[ERROR] [aggregator] Command not found '${cmd}'." >&2
        exit 1
    }
done

# Fetch all feeds into one file
for name in "${!netset_sources[@]}"; do
    url="${netset_sources["${name}"]}"

    echo "[INFO] [aggregator] Fetching '${name}' .."
    chunk=$(
        curl -fsSL --retry 3 --connect-timeout 5 --max-time 30 \
            -H "Accept: text/plain" \
            -H "Content-Type: text/plain" \
            -H "User-Agent: curl / github.com/Synapsecom/aggregated-blacklist-netset" \
            "${url}"
    ) || {
        # Variable "chunk" now contains curl's error message because -sS leaves it on stderr
        echo "[ERROR] [aggregator] Cannot fetch '${name}': ${chunk}" >&2
        continue
    }

    # Append data to netset output file
    echo "${chunk}" >> "${netset_file_temp}"
done

# Safety check
[ "$(wc -l "${netset_file_temp}" | awk '{print $1}')" -eq 0 ] && {
    echo "[ERROR] [aggregator] No feeds fetched. Aborting .." >&2
    exit 2
}

# Optimize blacklist
bash "${s_dir}/optimizer.sh" "${netset_file_temp}" "${netset_file_output}"
