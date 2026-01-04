#!/bin/bash

declare -a FINDINGS=()
FINDING_ID=0
json_escape() {
    local string="$1"
    string="${string//\\/\\\\}"
    string="${string//\"/\\\"}"
    string="${string//$'\n'/\\n}"
    string="${string//$'\t'/\\t}"
    echo "$string"
}
add_finding() {
    local module="$1"
    local severity="$2"
    local title="$3"
    local description="$4"
    local affected_path="${5:-}"
    local recommendation="${6:-}"
    
    ((FINDING_ID++))
    
    local finding_json=$(cat << EOF
{
    "id": $FINDING_ID,
    "module": "$(json_escape "$module")",
    "severity": "$(json_escape "$severity")",
    "title": "$(json_escape "$title")",
    "description": "$(json_escape "$description")",
    "affected_path": "$(json_escape "$affected_path")",
    "recommendation": "$(json_escape "$recommendation")",
    "timestamp": "$(date -Iseconds)"
}
EOF
)
    
    # Ajouter au tableau
    FINDINGS+=("$finding_json")
}
generate_scan_json() {
    local output_file="$1"
    local hostname=$(hostname)
    local kernel=$(uname -r)
    local os_info=$(cat /etc/os-release 2>/dev/null | grep "PRETTY_NAME" | cut -d'"' -f2)
    local scan_user=$(whoami)
    local scan_date=$(date -Iseconds)
    
    cat << EOF > "$output_file"
{
    "scan_info": {
        "version": "1.0",
        "date": "$scan_date",
        "hostname": "$(json_escape "$hostname")",
        "kernel": "$(json_escape "$kernel")",
        "os": "$(json_escape "$os_info")",
        "user": "$(json_escape "$scan_user")"
    },
    "summary": {
        "total_findings": ${#FINDINGS[@]},
        "critical": $CRITICAL_COUNT,
        "high": $HIGH_COUNT,
        "medium": $MEDIUM_COUNT,
        "low": $LOW_COUNT,
        "info": $INFO_COUNT
    },
    "findings": [
EOF
    local first=true
    for finding in "${FINDINGS[@]}"; do
        if [ "$first" = true ]; then
            first=false
        else
            echo "," >> "$output_file"
        fi
        echo "$finding" | sed 's/^/        /' >> "$output_file"
    done
    
    cat << EOF >> "$output_file"
    ]
}
EOF
    
    if [[ -f "$output_file" ]]; then
        echo -e "${GREEN:-}[OK]${NC:-} Scan sauvegardé : $output_file"
    else
        echo -e "${BLUE:-}[INFO]${NC:-} Erreur lors de la génération du fichier JSON"
    fi
}
load_previous_scan() {
    local scan_file="$1"
    
    if [[ -f "$scan_file" ]]; then
        cat "$scan_file"
        return 0
    else
        return 1
    fi
}
get_latest_scan() {
    local history_dir="$1"
    local latest=$(ls -t "$history_dir"/scan_*.json 2>/dev/null | head -1)
    
    if [[ -n "$latest" && -f "$latest" ]]; then
        echo "$latest"
        return 0
    else
        return 1
    fi
}
list_all_scans() {
    local history_dir="$1"
    
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    HISTORIQUE DES SCANS                       ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    
    local count=0
    for scan_file in $(ls -t "$history_dir"/scan_*.json 2>/dev/null); do
        ((count++))
        local filename=$(basename "$scan_file")
        local date_str=$(echo "$filename" | grep -oE '[0-9]{8}_[0-9]{6}')
        local formatted_date=$(echo "$date_str" | sed 's/\([0-9]\{4\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)_\([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)/\1-\2-\3 \4:\5:\6/')

        local total=$(grep -o '"total_findings": [0-9]*' "$scan_file" 2>/dev/null | grep -o '[0-9]*')
        local critical=$(grep -o '"critical": [0-9]*' "$scan_file" 2>/dev/null | grep -o '[0-9]*')
        
        printf "  %2d. %-30s | %3s findings | %s critiques\n" \
               "$count" "$formatted_date" "${total:-?}" "${critical:-?}"
    done
    
    if [[ $count -eq 0 ]]; then
        echo "  Aucun scan dans l'historique."
    fi
    
    echo ""
    echo "  Total : $count scan(s)"
    echo ""
}
get_finding_fingerprint() {
    local module="$1"
    local severity="$2"
    local title="$3"
    local path="$4"
    echo "${module}|${severity}|${title}|${path}" | md5sum | cut -d' ' -f1
}
extract_fingerprints_from_json() {
    local json_file="$1"
    local in_finding=false
    local module="" severity="" title="" path=""
    
    while IFS= read -r line; do
        if echo "$line" | grep -q '"module":'; then
            module=$(echo "$line" | sed 's/.*"module": *"\([^"]*\)".*/\1/')
        fi
        if echo "$line" | grep -q '"severity":'; then
            severity=$(echo "$line" | sed 's/.*"severity": *"\([^"]*\)".*/\1/')
        fi
        if echo "$line" | grep -q '"title":'; then
            title=$(echo "$line" | sed 's/.*"title": *"\([^"]*\)".*/\1/')
        fi
        if echo "$line" | grep -q '"affected_path":'; then
            path=$(echo "$line" | sed 's/.*"affected_path": *"\([^"]*\)".*/\1/')
            
            if [[ -n "$module" && -n "$severity" && -n "$title" ]]; then
                get_finding_fingerprint "$module" "$severity" "$title" "$path"
            fi
            
            module="" severity="" title="" path=""
        fi
    done < "$json_file"
}