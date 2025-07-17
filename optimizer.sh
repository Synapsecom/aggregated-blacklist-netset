#! /usr/bin/env bash
# Author: Sotirios Roussis <s.roussis@synapsecom.gr>

declare -r s_dir="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

declare -r ipset_file_excludes=$(mktemp)
declare -r ipset_file_input="${1}"
declare -r ipset_file_output="${2}"

function cleanup() {
    rm -rf -- "${ipset_file_excludes}" "${s_dir}/debug.lst"
}

# Trap most common termination signals plus EXIT (0) and ERR
# trap cleanup EXIT ERR INT TERM HUP QUIT PIPE

! [ -n "${ipset_file_input}" ] && {
    echo "[ERROR] [optimizer] Input IPset file is not defined." >&2
    exit 1
}

! [ -f "${ipset_file_input}" ] && {
    echo "[ERROR] [optimizer] No such file '${ipset_file_input}'." >&2
    exit 2
}

for cmd in grepcidr python3; do
    ! hash "${cmd}" 2>/dev/null && {
        echo "[ERROR] [optimizer] Command not found '${cmd}'." >&2
        exit 3
    }
done

! touch "${ipset_file_output}" &>/dev/null && {
    echo "[ERROR] [optimizer] Cannot create file '${ipset_file_output}'. Parent directories may be missing." >&2
    exit 4
}

# CIDRs to exclude (RFC 6890 + multicast + docs)
read -r -d '' ipset_excludes <<'EOF'
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.88.99.0/24
192.168.0.0/16
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
255.255.255.255/32
::/128
::1/128
fc00::/7
fe80::/10
ff00::/8
2001:db8::/32
EOF

# Save the exclusion set to a temp file for grepcidr
printf '%s\n' "${ipset_excludes}" | grep -v '^#' > "${ipset_file_excludes}"

# 1. Strip comments/blank lines
# 2. Remove all excluded networks
# 3. Deduplicate
# 4. Collapse with aggregate
grep -Ev '^\s*(#|$)' "${ipset_file_input}" \
    | grepcidr -v -f "${ipset_file_excludes}" \
    | sort -u \
    | awk 'index($0,"/")==0 { if ($0 ~ /:/) print $0"/128"; else print $0"/32"; next } {print}' \
    | tee "${s_dir}/debug.lst" \
    | python3 "${s_dir}/collapser.py" \
    > "${ipset_file_output}"

# Results
echo "[INFO] [optimizer] Clean and aggregated blacklist IPset written to '${ipset_file_output}'. Includes '$(wc -l "${ipset_file_output}" | awk '{print $1}')' unique entries."
