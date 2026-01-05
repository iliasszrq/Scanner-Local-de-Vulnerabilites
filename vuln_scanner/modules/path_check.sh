#!/bin/bash

#fct pour verifier un PATH donne
analyze_path(){
    local path_value="$1"
    local path_source="$2"
    #separation du PATH en elements
    IFS=':' read -ra path_elements <<< "$path_value"

    local issues_found=0
    for element in "${path_elements[@]}";do
        #verifier si l'element est vide
        if [[ -z "$element" || "$element" == "." ]];then
            log_message "CRITICAL" "PATH contient ke repertoire courant (.) - $path_soure"
            log_message "INFO" " ->Permet l'execution de binaire dans le dossier courant"
            ((issues_found++))
        fi
        #verifier si le repertoire existe
        if [[ ! -d "$element" ]];then
            log_message "MEDIUM" "PATH contient un repertoire inexistant : $element"
            log_message "INFO" " ->Un attaquant pourrait creer ce repertoire"
            ((issues_found++))
            continue
        fi
        #verifier les permissions d'ecriture
        if [[ -w "$element" ]];then
            if [[ "$element" == "$HOME" ]];then
                :
            elif [[ "$element" == "/tmp"* || "$element" == "/var/tmp"* ]];then
                log_message "HIGH" "PATH contient un repertoire temporaire : $element"
                log_message "INFO" " -> Tout utilisateur peut placer des executables"
                ((issues_found++))
            else
                log_message "MEDIUM" "PATH contient un repertoire accessible en ecriture : $element"
                ((issues_found++))
            fi
        fi

        #verifier si le repertoire apprtient a un autre utilisateur que root
        local owner=$(stat -c '%U' "$element" 2>/dev/null)
        if [[ "$owner" != "root" && "$element" != "$HOME"* ]];then
            log_message "LOW" "Repertoire PATH non-root : $element (proprietaire:$owner)"
            ((issues_found++))
        fi

        #verifier les permissions du repertoire; world-writable
        local perms=$(stat -c '%a' "$element" 2>/dev/null)
        if [[ "${perms: -1}" =~ [2367] ]];then
            log_message "HIGH" "Repertoire PATH world-writable : $element ($perms)"
            ((issues_found++))
        fi
    done
    return $issues_found
}
#fct pour verifier le PATH de user actuel
check_user_path(){
    log_message "INFO" "Analyse du PATH utilisateur actuel..."
    log_message "INFO" "PATH = $PATH"
    analyze_path "$PATH" "variable PATH actuelle"
}
#verifier les fichiers de profile system
check_profile_files(){
    local profile_files=(
        "/etc/profile"
        "/etc/environment"
        "/etc/bash.bashrc"
        "$HOME/.bashrc"
        "$HOME/.bash_profile"
        "$HOME/.profile"
        "/etc/profile.d/*.sh"
    )
    log_message "INFO" "Analyse des fichiers de profile..."
    for pattern in "${profile_files[@]}";do
        #expansion des wildcards
        for file in $pattern;do
            [[ ! -f "$file" ]] && continue
            [[ ! -r "$file" ]] && continue

            #chercher des modifications de PATH
            local path_mods=$(grep -n "PATH=" "$file" 2>/dev/null | grep -v "^#")
            if [[ -n "$path_mods" ]];then
                while IFS= read -r line; do
                    local line_num=$(echo "$line" | cut -d: -f1)
                    local content=$(echo "$line" | cut -d: -f2)

                    #extraire la valeur du PATH
                    if echo "$content" | grep -q '\.';then
                        log_message "MEDIUM" "Point (.) dans PATH - $file:$line_num"
                        log_message "INFO" " -> $content"
                    fi
                    if echo "$content" | grep -qE '(^|:)(:|$)';then
                        log_message "HIGH" "Element vide dans PATH - $file:$line_num"
                        log_message "INFO" " ->$content"
                    fi
                    if echo "$content" | grep -qE '/tmp|/var/tmp';then
                        log_message "HIGH" "Repertoire temp dans PATH - $file:$line_num"
                        log_message "INFO" " -> $content"
                    fi
                done <<< "$path_mods"
            fi
        done
    done
}
#verifier les scripts cron pour des PATH vulnerables
check_cron_paths(){
    local cron_dirs=(
        "/etc/cron.d"
        "/etc/cron.daily"
        "/etc/cron.hourly"
        "/etc/cron.weekly"
        "/etc/cron.monthly"
        "/var/spool/cron/crontabs"
    )
    log_message "INFO" "Analyse des PATH dans les scripts cron..."
    for dir in "${cron_dirs[@]}";do
        [[ ! -d "$dir" ]] && continue

        for file in "$dir"/*;do
            [[ ! -f "$file" ]] && continue
            [[ ! -r "$file" ]] && continue
            #chercher PATH dans les fichiers cron
            if grep -q "PATH=" "$file" 2>/dev/null;then
                local path_line=$(grep "PATH=" "$file" 2>/dev/null | head -1)
                if echo "$path_line" | grep -qE '(^|:)\.|/tmp|/var/tmp|(:|^)(:|$)';then
                    log_message "HIGH" "PATH vulnerable dans cron : $file"
                    log_message "INFO" " -> $path_line"
                fi
            fi
        done
    done
}
#verifier les scripts systemd
check_systemd_paths(){
    local systemd_dirs=(
        "/etc/systemd/system"
        "/lib/systemd/system"
        "/usr/lib/systemd/system"
    )
    log_message "INFO" "Analyse des PATH dans les services systemd..."
    for dir in "${systemd_dirs[@]}";do
        [[ ! -d "$dir" ]] && continue
        for file in "$dir"/*.service;do
            [[ ! -f "$file" ]] && continue
            if grep -q "Environment.*PATH" "$file" 2>/dev/null;then
                local env_line=$(grep "Environment.*PATH" "$file" 2>/dev/null)

                if echo "$env_line" | grep -qE '/tmp|/var/tmp';then
                    log_message "MEDIUM" "PATH suspect dans service systemd : $file"
                    log_message "INFO" " -> $env_line"
                fi
            fi
        done
    done
}

#fct principal du module
scan_path_injection(){
    check_user_path
    check_profile_files
    check_cron_paths
    check_systemd_paths
    echo ""
    log_message "OK" "Analyse PATH terminee"
}
scan_path_injection