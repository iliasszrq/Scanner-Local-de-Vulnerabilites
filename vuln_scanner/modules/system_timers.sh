#!/bin/bash
SYSTEMD_DIRS=(
    "/etc/systemd/system"
    "/lib/systemd/system"
    "/usr/lib/systemd/system"
    "/run/systemd/system"
    "$HOME/.config/systemd/user"
    "$HOME/.local/share/systemd/user"
)
#patterns de noms suspects
SUSPICIOUS_NAME_PATTERNS=(
    "^[a-f0-9]{8,}$"         # Noms hexadecimaux (hash-like)
    "^[a-z]{10,}$"           # Noms aleatoires longs
    "tmp"                     # References à tmp
    "test"                    # Fichiers de test oublies
    "debug"                   # Debug
    "\.service$" 
)
#des chemins suspects dans Execstart
SUSPICIOUS_EXEC_PATHS=(
    "/tmp/"
    "/var/tmp/"
    "/dev/shm/"
    "/home/*/."              # Fichiers cachs dans home
    "curl"                    # Telechargement
    "wget"                    # Telechargement
    "bash -c"                 # Commandes inline
    "sh -c"                   # Commandes inline
    "python -c"               # Code inline
    "base64"                  # Decodage (obfuscation)
    "eval"                    # Execution dynamique
    "|"                       # Pipes (chaines de commandes)
)

#fonction de lister tous les timers actifs

list_active_timers(){
    log_message "INFO" "Timers systemd actifs :"
    #systemctl pour lister les timers
    if command -v systemctl &>/dev/null;then
        local timers=$(systemctl list-timers --all --no-pager 2>/dev/null)
        if [[ -n "$timers" ]];then
            echo "$timers" | head -20 #afficher les 20 premiers
        else
            log_message "INFO" "aucun timer actif ou systemctl non disponible"
        fi
    fi
}

#fct pour analyser un fichier timer
analyze_timer_file(){
    local timer_file="$1"
    local timer_name=$(basename "$timer_file" .timer)
    local issues=0
    #verifier si le nom est suspect
    for pattern in "${SUSPICIOUS_NAME_PATTERNS[@]}";do
        if echo "$timer_name" | grep -qE "$pattern"; then
            log_message "MEDIUM" "timer avec nom suspect : $timer_file"
            ((issues++))
            break
        fi
    done
    #lire le contenue du timer
    local timer_content=$(cat "$timer_file" 2>/dev/null)
    #verifier si l'execution est frequente ou pas; tres frequent = suspect
    if echo "$timer_content" | grep -qE "OnUnitActiveSec=[0-9]+s";then
        local interval=$(echo "$timer_content" | grep -oE "OnUnitActiveSec=[0-9]+" | cut -d= -f2)
        if [[ "$interval" -lt 60 ]];then
        log_message "MEDIUM" "Timer execute tres frequemment : $timer_file"
        ((issues++))
        fi
    fi
    local service_name="${timer_name}.service"
    local service_file=""
    #chercher le fichier service dans les memes repertoires
    for dir in "${SYSTEMD_DIRS[@]}";do
        if [[ -f "$dir/$service_name" ]];then
            service_file="$dir/$service_name"
            break
        fi
    done
    if [[ -n "$service_file" && -f "$service_file" ]];then
        analyze_service_file "$service_file" "$timer_file"
    fi
    return $issues
}
#fct pour analyser un fichier service associe a un timer
analyze_service_file(){
    local service_file="$1"
    local associated_timer="$2"
    local service_content=$(cat "$service_file" 2>/dev/null)
    #extraction du Execstart
    local exec_start=$(echo "$service_content" | grep -E "^Execstart=" | cut -d= -f2)
    if [[ -n "$exec_start" ]];then
        #verification des chemins suspects
        for pattern in "${SUSPICIOUS_EXEC_PATHS[@]}";do
            if echo "$exec_start" | grep -q "$pattern";then
                log_message "HIGH" "Service avec Execstart suspect : $service_file"
                log_message "INFO" " ->Execstart: $exec_start"
                log_message "INFO" " ->Pattern detecte: $pattern"
                break
            fi
        done
        
        #verification d'un script deja existant
        local script_path=$(echo "$exec_start" | awk '{print $1}')
        if [[ -f "$script_path" ]];then
            local script_perms=$(stat -c '%a' "$script_path" 2>/dev/null)
            local script_owner=$(stat -c '%U' "$script_file" 2>/dev/null)
            #verifier si world writable
            if [[ "${script_perms: -1}" =~ [2367] ]];then
                log_message "CRITICAL" "Le script du timer est world writable: $script_path"
            fi
        elif [[ ! "$exec_start" =~ ^/bin && ! "$exec_start" =~ ^/usr ]];then
            log_message "MEDIUM" "Script non trouve ou chemin relatif: $script_path"
        fi
    fi

    #verifier user et le grp
    local run_as_user=$(echo "$service_content" | grep -E "^User=" | cut -d= -f2)
    if [[ -z "$run_as_user" ]];then
        log_message "INFO" "Service sans user defini (s'execute en root) : $service_file"
    fi
}
#fct du scanner des repertoire systemd
scan_systemd_directories(){
    log_message "INFO" "Scan des repertoires systemd..."
    local total_timers=0
    local suspicious_timers=0

    for dir in "${SYSTEMD_DIRS[@]}";do
        [[ ! -d "$dir" ]] && continue
        #chercher des fichiers timer
        shopt -s nullglob
        for timer_file in "$dir"/*.timer;do
            [[ ! -f "$timer_file" ]] && continue
            ((total_timers++))
            #analyser chaque timer
            analyze_timer_file "$timer_file"
            if [[ $? -gt 0 ]];then
                ((suspicious_timers++))
            fi
        done
        shopt -u nullglob
    done

    log_message "INFO" "Total timers analysees: $total_timers"
    log_message "INFO" "Timers suspects: $suspicious_timers"
}
#fct pour detection des timers recemment crees ou modifiers
check_recent_timers(){
    log_message "INFO" "Verification des timers recemment crees ou modifiees dans les  7 jours derniers..."

    for dir in"${SYSTEMD_DIRS[@]}";do
        [[ ! -d "$dir" ]] && continue
        #trouver kes fichier modifiees dans 7 jours derniers
        local recent=$(find "$dir" -name "*.timer" -mtime -7 2>/dev/null)

        if [[ -n "$recent" ]];then
            while IFS=read -r file;do
                local mod_date=$(stat -c '%y' "$file" 2>/dev/null | cut -d' ' -f1)
                log_message "MEDIUM" "Timer recent: $file (modifie: $mod_date)"
            done <<< "$recent"
        fi
    done
}
check_user_timers(){
    log_message "INFO" "Verification des timers user..."
    local user_systemd="$HOME/.config/systemd/user"
    if [[ -d "$user_systemd" ]];then
        local user_timers=$(find "$user_systemd" -name "*.timer" 2>/dev/null)
        if [[ -n "$user_timers"]];then
            log_message "INFO" "Timers user trouves :"
            while IFS= read -r timer;do
                log_message "LOW" " ->$timer"
                analyze_timer_file "$timer"
            done <<< "$user_timers"
        fi
    fi
}
#fct principal du module
scan_systemd_timers(){
    list_active_timers
    echo ""
    scan_systemd_directories
    check_recent_timers
    check_user_timers
    echo ""
    log_message "OK" "Analyse des timers terminee"
}
scan_systemd_timers