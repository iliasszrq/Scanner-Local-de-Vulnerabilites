#!/bin/bash
extract_findings_list() {
    local json_file="$1"
    
    if [[ ! -f "$json_file" ]]; then
        return 1
    fi
    
    # Parser le JSON et extraire les champs clés
    awk '
    BEGIN { 
        module=""; severity=""; title=""; path="" 
    }
    /"module":/ { 
        gsub(/.*"module": *"/, ""); 
        gsub(/".*/, ""); 
        module=$0 
    }
    /"severity":/ { 
        gsub(/.*"severity": *"/, ""); 
        gsub(/".*/, ""); 
        severity=$0 
    }
    /"title":/ { 
        gsub(/.*"title": *"/, ""); 
        gsub(/".*/, ""); 
        title=$0 
    }
    /"affected_path":/ { 
        gsub(/.*"affected_path": *"/, ""); 
        gsub(/".*/, ""); 
        path=$0;
        if (module != "" && severity != "") {
            print module "|" severity "|" title "|" path
        }
        module=""; severity=""; title=""; path=""
    }
    ' "$json_file" | sort -u
}

extract_counters() {
    local json_file="$1"
    
    local critical=$(grep -o '"critical": *[0-9]*' "$json_file" 2>/dev/null | head -1 | grep -oE '[0-9]+')
    local high=$(grep -o '"high": *[0-9]*' "$json_file" 2>/dev/null | head -1 | grep -oE '[0-9]+')
    local medium=$(grep -o '"medium": *[0-9]*' "$json_file" 2>/dev/null | head -1 | grep -oE '[0-9]+')
    local low=$(grep -o '"low": *[0-9]*' "$json_file" 2>/dev/null | head -1 | grep -oE '[0-9]+')
    local info=$(grep -o '"info": *[0-9]*' "$json_file" 2>/dev/null | head -1 | grep -oE '[0-9]+')
    
    echo "${critical:-0}:${high:-0}:${medium:-0}:${low:-0}:${info:-0}"
}

print_counter_comparison() {
    local label="$1"
    local old_val="$2"
    local new_val="$3"
    local color="$4"
    
    local diff=$((new_val - old_val))
    local arrow=""
    local diff_color=""
    
    if [[ $diff -gt 0 ]]; then
        arrow="↑"
        diff_color="${RED}"
        diff="+$diff"
    elif [[ $diff -lt 0 ]]; then
        arrow="↓"
        diff_color="${GREEN}"
    else
        arrow="="
        diff_color="${BLUE}"
        diff="0"
    fi
    
    printf "  ${color}%-10s${NC} : %3d → %3d  ${diff_color}[%s %s]${NC}\n" \
           "$label" "$old_val" "$new_val" "$arrow" "$diff"
}

compare_with_latest() {
    local current_scan="$1"
    local history_dir="$2"
    
    local current_basename=$(basename "$current_scan")
    local previous_scan=$(ls -t "$history_dir"/scan_*.json 2>/dev/null | grep -v "$current_basename" | head -1)
    
    if [[ -z "$previous_scan" || ! -f "$previous_scan" ]]; then
        echo ""
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}  Premier scan - Pas de comparaison possible${NC}"
        echo -e "${YELLOW}  Relancez le scanner plus tard pour voir l'évolution${NC}"
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
        return 0
    fi
    
    compare_two_scans "$previous_scan" "$current_scan"
}


compare_two_scans() {
    local old_scan="$1"
    local new_scan="$2"
    
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                 COMPARAISON DES SCANS                         ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Extraire les dates des scans
    local old_date=$(grep -o '"date": *"[^"]*"' "$old_scan" 2>/dev/null | head -1 | cut -d'"' -f4)
    local new_date=$(grep -o '"date": *"[^"]*"' "$new_scan" 2>/dev/null | head -1 | cut -d'"' -f4)
    
    # Fallback sur le nom de fichier
    if [[ -z "$old_date" ]]; then
        old_date=$(basename "$old_scan" .json | sed 's/scan_//')
    fi
    if [[ -z "$new_date" ]]; then
        new_date=$(basename "$new_scan" .json | sed 's/scan_//')
    fi
    
    echo -e "  ${BLUE}Scan précédent :${NC} $old_date"
    echo -e "  ${BLUE}Scan actuel    :${NC} $new_date"
    echo ""
    
    # Comparer les compteurs
    echo -e "${CYAN}── Évolution des vulnérabilités ──${NC}"
    echo ""
    
    local old_counters=$(extract_counters "$old_scan")
    local new_counters=$(extract_counters "$new_scan")
    
    IFS=':' read -r old_crit old_high old_med old_low old_info <<< "$old_counters"
    IFS=':' read -r new_crit new_high new_med new_low new_info <<< "$new_counters"
    
    print_counter_comparison "CRITICAL" "$old_crit" "$new_crit" "$RED"
    print_counter_comparison "HIGH" "$old_high" "$new_high" "$RED"
    print_counter_comparison "MEDIUM" "$old_med" "$new_med" "$YELLOW"
    print_counter_comparison "LOW" "$old_low" "$new_low" "$YELLOW"
    print_counter_comparison "INFO" "$old_info" "$new_info" "$BLUE"
    
    echo ""
    
    # Calculer le total (sans INFO)
    local old_total=$((old_crit + old_high + old_med + old_low))
    local new_total=$((new_crit + new_high + new_med + new_low))
    
    print_counter_comparison "TOTAL" "$old_total" "$new_total" "$CYAN"
    
    # Verdict
    echo ""
    if [[ $new_total -lt $old_total ]]; then
        local diff=$((old_total - new_total))
        echo -e "  ${GREEN}✅ AMÉLIORATION : $diff vulnérabilité(s) corrigée(s)${NC}"
    elif [[ $new_total -gt $old_total ]]; then
        local diff=$((new_total - old_total))
        echo -e "  ${RED}⚠️  RÉGRESSION : $diff nouvelle(s) vulnérabilité(s)${NC}"
    else
        echo -e "  ${YELLOW}➡️  STABLE : Même nombre de vulnérabilités${NC}"
    fi
    
    echo ""
    
    # Comparer les findings détaillés
    compare_findings_detail "$old_scan" "$new_scan"
}

compare_findings_detail() {
    local old_scan="$1"
    local new_scan="$2"
    
    # Créer des fichiers temporaires
    local tmp_old=$(mktemp)
    local tmp_new=$(mktemp)
    
    # Extraire les findings
    extract_findings_list "$old_scan" > "$tmp_old"
    extract_findings_list "$new_scan" > "$tmp_new"
    
    # Comparer
    local new_findings=$(comm -13 <(sort "$tmp_old") <(sort "$tmp_new"))
    local resolved_findings=$(comm -23 <(sort "$tmp_old") <(sort "$tmp_new"))
    local persistent_findings=$(comm -12 <(sort "$tmp_old") <(sort "$tmp_new"))
    
    # Afficher les nouvelles vulnérabilités
    echo -e "${CYAN}── Nouvelles vulnérabilités 🆕 ──${NC}"
    if [[ -n "$new_findings" ]]; then
        local count=0
        while IFS='|' read -r module severity title path; do
            [[ -z "$module" ]] && continue
            ((count++))
            
            local sev_color="$BLUE"
            case "$severity" in
                CRITICAL) sev_color="$RED" ;;
                HIGH) sev_color="$RED" ;;
                MEDIUM) sev_color="$YELLOW" ;;
                LOW) sev_color="$YELLOW" ;;
            esac
            
            echo -e "  ${RED}🆕${NC} ${sev_color}[$severity]${NC} $title"
            echo -e "     └─ Module: $module"
            [[ -n "$path" ]] && echo -e "     └─ Path: $path"
        done <<< "$new_findings"
        echo ""
        echo -e "  ${RED}→ $count nouvelle(s) vulnérabilité(s) détectée(s)${NC}"
    else
        echo -e "  ${GREEN}Aucune nouvelle vulnérabilité${NC}"
    fi
    
    echo ""
    
    # Afficher les vulnérabilités résolues
    echo -e "${CYAN}── Vulnérabilités résolues ✅ ──${NC}"
    if [[ -n "$resolved_findings" ]]; then
        local count=0
        while IFS='|' read -r module severity title path; do
            [[ -z "$module" ]] && continue
            ((count++))
            echo -e "  ${GREEN}✅${NC} [$severity] $title"
            echo -e "     └─ Module: $module"
        done <<< "$resolved_findings"
        echo ""
        echo -e "  ${GREEN}→ $count vulnérabilité(s) corrigée(s)${NC}"
    else
        echo -e "  ${YELLOW}Aucune vulnérabilité résolue depuis le dernier scan${NC}"
    fi
    
    echo ""
    
    # Afficher les vulnérabilités persistantes
    echo -e "${CYAN}── Vulnérabilités persistantes ⏳ ──${NC}"
    if [[ -n "$persistent_findings" ]]; then
        local count=0
        local crit_count=0
        local high_count=0
        
        while IFS='|' read -r module severity title path; do
            [[ -z "$module" ]] && continue
            ((count++))
            [[ "$severity" == "CRITICAL" ]] && ((crit_count++))
            [[ "$severity" == "HIGH" ]] && ((high_count++))
        done <<< "$persistent_findings"
        
        echo -e "  ${YELLOW}⏳ $count vulnérabilité(s) non corrigée(s)${NC}"
        
        if [[ $crit_count -gt 0 || $high_count -gt 0 ]]; then
            echo -e "  ${RED}   ⚠️  Dont $crit_count CRITICAL et $high_count HIGH à traiter en priorité${NC}"
        fi
    else
        echo -e "  ${GREEN}Aucune vulnérabilité persistante (toutes corrigées)${NC}"
    fi
    
    # Nettoyer
    rm -f "$tmp_old" "$tmp_new"
    
    echo ""
}
select_scan_for_comparison() {
    local history_dir="$1"
    
    # Lister les scans disponibles
    if [[ -f "$LIB_DIR/utils.sh" ]]; then
        source "$LIB_DIR/utils.sh"
    fi
    list_all_scans "$history_dir"
    
    local scans=($(ls -t "$history_dir"/scan_*.json 2>/dev/null))
    local num_scans=${#scans[@]}
    
    if [[ $num_scans -lt 2 ]]; then
        echo -e "${YELLOW}Il faut au moins 2 scans pour comparer.${NC}"
        echo "Lancez d'abord plusieurs scans avec : $0"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}Sélectionnez deux scans à comparer :${NC}"
    echo ""
    
    # Demander le premier scan (l'ancien)
    read -p "  Numéro du scan ANCIEN (1-$num_scans) : " old_index
    
    # Valider
    if [[ ! "$old_index" =~ ^[0-9]+$ ]] || [[ $old_index -lt 1 ]] || [[ $old_index -gt $num_scans ]]; then
        echo -e "${RED}Index invalide${NC}"
        return 1
    fi
    
    # Demander le second scan (le nouveau)
    read -p "  Numéro du scan NOUVEAU (1-$num_scans) : " new_index
    
    # Valider
    if [[ ! "$new_index" =~ ^[0-9]+$ ]] || [[ $new_index -lt 1 ]] || [[ $new_index -gt $num_scans ]]; then
        echo -e "${RED}Index invalide${NC}"
        return 1
    fi
    
    # Récupérer les fichiers
    local old_scan="${scans[$((old_index-1))]}"
    local new_scan="${scans[$((new_index-1))]}"
    
    # Lancer la comparaison
    compare_two_scans "$old_scan" "$new_scan"
}