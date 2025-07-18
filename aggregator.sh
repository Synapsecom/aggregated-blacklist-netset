#! /usr/bin/env bash
# Author: Sotirios Roussis <s.roussis@synapsecom.gr>
# Age public key: age1p52flv0nqr6q4v9l7gsntd6yva4mf9fv0lnudjzskk3j23g9ep8sz3fzl3

declare -r s_dir="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

declare -r netset_file_temp="$(mktemp)"
declare -r netset_file_output="${s_dir}/blacklist.lst"
declare -Ar private_sources=(
    ["whmcs-bots"]='LS0tLS1CRUdJTiBBR0UgRU5DUllQVEVEIEZJTEUtLS0tLQpZV2RsTFdWdVkzSjVjSFJwYjI0dWIzSm5MM1l4Q2kwK0lGZ3lOVFV4T1NCWE1FZzRTVzAzTkc1ck5tczFaSGN5ClJWUndUM2cwWjFNNU1UUnhNM2hQV0doR1RUbFZZbTVPTld0WkNrVkhaMWd4Y1VNMFF6TmhURk0yVldadFowVlkKUTFSa1oxQkxkbUpHYzBoT00xZDRVR0V4UTFCSE9FRUtMUzB0SUdWUVMycDJibm94UTFaV2RTOVZVMnh4Y0UwNQpVVmh0UlRSTlpHTXhhbFY2Ynl0SFNYZHhkREJ1VlVFS1hKclVyL1N1bmtXQUtsZTVkek9PRFBBMW82c2ZnYTNyClFTMGZNWUY3MFlVR1VwUmVpUW5RcEx4MlNBTDI4MFE1U1dWdlQ4WDVlVldKWUowZnd2OE1GZ2VUSFVIbk5LclQKMFpOT1ZZSUtzUUZTVmxyMHlHY05hbTIrR0NreTY3RGpaNXNVZG9ObWxxQ2dqNk0xRmdzakVhUldZRUxQRGw1Vwo0UTRDSmtFV1FVUVhVMFEwUjVBY1RBPT0KLS0tLS1FTkQgQUdFIEVOQ1JZUFRFRCBGSUxFLS0tLS0K'
)
declare -Ar public_sources=(
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

for cmd in age curl; do
    ! hash "${cmd}" 2>/dev/null && {
        echo "[ERROR] [aggregator] Command not found '${cmd}'." >&2
        exit 1
    }
done

# Fetch all feeds into one file
for name in "${!private_sources[@]}"; do
    url="${private_sources["${name}"]}"
    url=$(base64 -d <<< "${url}" | age -d -i "${AGE_PRIVATE_KEY_FILE:-age.key}")

    echo "[INFO] [aggregator] Fetching private source '${name}' .."
    chunk=$(
        curl -fsSL --retry 3 --connect-timeout 5 --max-time 30 \
            -u "ci:${CI_JOB_TOKEN}" \
            -H "Accept: text/plain" \
            -H "Content-Type: text/plain" \
            -H "User-Agent: curl / github.com/Synapsecom/aggregated-blacklist-netset" \
            "${url}"
    ) || {
        # Variable "chunk" now contains curl's error message because -sS leaves it on stderr
        echo "[ERROR] [aggregator] Cannot fetch private source '${name}': ${chunk}" >&2
        continue
    }

    # Append data to netset output file
    echo "${chunk}" >> "${netset_file_temp}"
done

for name in "${!public_sources[@]}"; do
    url="${public_sources["${name}"]}"

    echo "[INFO] [aggregator] Fetching public source '${name}' .."
    chunk=$(
        curl -fsSL --retry 3 --connect-timeout 5 --max-time 30 \
            -H "Accept: text/plain" \
            -H "Content-Type: text/plain" \
            -H "User-Agent: curl / github.com/Synapsecom/aggregated-blacklist-netset" \
            "${url}"
    ) || {
        # Variable "chunk" now contains curl's error message because -sS leaves it on stderr
        echo "[ERROR] [aggregator] Cannot fetch public source '${name}': ${chunk}" >&2
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
