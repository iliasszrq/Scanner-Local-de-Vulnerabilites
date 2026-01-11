#!/bin/bash
detect_reverse_shells(){
    log_message "INFO" "Recherche de reverse shells potentiels..."

    # Patterns FIXES (pas de regex)
    local fixed_patterns=(
        "bash -i"
        "bash%20-i"
        "/dev/tcp/"
        "/dev/udp/"
        "nc -e"
        "nc.traditional -e"
        "ncat -e"
        "mkfifo"
        "socat"
        "0<&196"
        "exec 196<>"
        "xterm -display"
    )
    
    # Patterns REGEX
    local regex_patterns=(
        "mknod.*p"
        "python.*socket"
        "python.*pty.spawn"
        "perl.*socket"
        "ruby.*socket"
        "php.*fsockopen"
        "php.*exec"
        "socat.*exec"
    )

    local search_paths=(
        "/tmp"
        "/var/tmp"
        "/dev/shm"
        "/home"
        "/root"
        "/etc/cron.d"
        "/var/spool/cron"
    )

    for path in "${search_paths[@]}"; do
        [[ ! -d "$path" ]] && continue
        
        # Recherche avec patterns fixes
        for pattern in "${fixed_patterns[@]}"; do
            local found=$(grep -rlF "$pattern" "$path" 2>/dev/null | head -5)
            if [[ -n "$found" ]]; then
                while IFS= read -r file; do
                    log_message "CRITICAL" "Pattern de reverse shell trouve: $pattern"
                    log_message "INFO" " ->Fichier : $file"
                done <<< "$found"
            fi
        done
        
        # Recherche avec patterns regex
        for pattern in "${regex_patterns[@]}"; do
            local found=$(grep -rlE "$pattern" "$path" 2>/dev/null | head -5)
            if [[ -n "$found" ]]; then
                while IFS= read -r file; do
                    log_message "CRITICAL" "Pattern de reverse shell trouve: $pattern"
                    log_message "INFO" " ->Fichier : $file"
                done <<< "$found"
            fi
        done
    done

    # Vérifier les connexions réseau suspectes
    if command -v netstat &>/dev/null; then
        local suspicious_conn=$(netstat -an 2>/dev/null | grep -E "ESTABLISHED.*:(4444|5555|1234|31337|6666|9001|9002)")
        if [[ -n "$suspicious_conn" ]]; then
            log_message "HIGH" "Connexions sur ports suspects :"
            log_message "INFO" "$suspicious_conn"
        fi
    fi
    
    if command -v ss &>/dev/null; then
        local suspicious_conn=$(ss -an 2>/dev/null | grep -E "ESTAB.*:(4444|5555|1234|31337|6666|9001|9002)")
        if [[ -n "$suspicious_conn" ]]; then
            log_message "HIGH" "Connexions sur ports suspects :"
            log_message "INFO" "$suspicious_conn"
        fi
    fi
}
#fct detecter kes cles ssh inconnues
detect_unknown_ssh_keys(){
    log_message "INFO" "Analyse des cles SSH authorized_keys..."
    local auth_keys_files=$(find /home /root -name "authorized_keys" 2>/dev/null)
    while IFS=read -r auth_file;do
        [[ -z "$auth_file" ]] && continue
        [[ ! -f "$auth_file" ]] && continue
        local line_num=0
        while IFS=read -r key_line;do
            ((line_num++))
            #ignores les commentaire et les lignes vides
            [[ -z "$key_line" || "$key_line" =~ ^# ]] && continue
            if echo "$key_line" | grep -qE "Command=|no-pty|permitopen";then
                log_message "HIGH" "Cle SSH avec iptions suspectes: $auth_file:$line_num"
                log_message "INFO" " ->$(echo "$key_line" | cut -c1-100)..."
            fi
            #verification des dates de modifications du fichier
            local mod_date=$(stat -c %Y "$auth_file" 2>/dev/null)
            local now=$(date +%s)
            local age_days=$(((now - mod_date) / 86400 ))
            if [[ $age_days -lt 7 ]];then
                log_message "MEDIUM" "Fichier authorized_keys modifie recemment: $auth_file"
                log_message "INFO" " ->Modifie il y a $age_days jour(s)"
            fi
        done < "$auth_file"
    done <<< "$auth_keys_files"
    #verifier les cles ssh dans des emplacements inhabituels
    local unusual_keys=$(find /tmp /var/tmp /dev/shm -name "*.pub" -o -name "id_rsa*" 2>/dev/null)
    if [[ -n "$unusual_keys" ]];then
        log_message "HIGH" "Cles SSH dans des emplacement suspects: "
        while IFS=read -r key;do
            log_message "INFO" " ->$key"
        done <<< "$unusual_keys"
    fi
}
#fct pour detecter les outils d'attaque connus
detect_attack_tools(){
    log_message "INFO" "Recherche d'outils d'attaque..."
    #noms de fichiers d'outils d'attaque connus
    local attack_tools=(
        "linpeas"
        "linenum"
        "linux-exploit-suggester"
        "les.sh"
        "pspy"
        "pspy64"
        "mimikatz"
        "lazagne"
        "chisel"
        "socat"
        "ncat"
        "nc.traditional"
        "meterpreter"
        "msf"
        "payload"
        "exploit"
        "reverse"
        "shell.py"
        "shell.sh"
        "c2"
        "beacon"
        "cobalt"
        "empire"
        "bloodhound"
        "sharphound"
        "rubeus"
        "mimipenguin"
    )
    for tool in "${attack_tools[@]}";do
        local found=$(find / -name "*${tool}*" -type f 2>/dev/null | grep -v ".git" | head -3)
        if [[ -n "$found" ]];then
            log_message "CRITICAL" "Outil d'attaque potentiel trouve: $tool"
            while IFS= read -r file;do
                log_message "INFO" " ->$file"
            done <<< "$found"
        fi
    done
}
#fct pour detecter kes binaires suspects dans les repertoires temporaires
detect_temp_binaires(){
    log_message "INFO" "Recherche de binaore dans les repertoires temporaires..."
    local temp_dirs=("/tmp" "/var/tmp" "/dev/shm" "/run/shm")
    for dir in "${temp_dirs[@]}";do
        [[ ! -d "$dir" ]] && continue
        #trouver des fichiers executables
        local executables=$(find "$dir" -type f -executable 2>/dev/null)
        if [[ -n "$executables" ]];then
            log_message "MEDIUM" "Fichiers executanles dans $dir :"
            while IFS=read -r exe;do
                local file_type=$(file -b "$exe" 2>/dev/null | cut -c1-50)
                log_message "INFO" " ->$exe ($file_type)"
            done <<< "$executables"
        fi
        #trouver les fichiers caches
        local hidden=$(find "$dir" -name ".*" -type f 2>/dev/null | head -10)
        if [[ -n "$hidden" ]];then
            log_message "MEDIUM" "Fichiers caches dans $dir :"
            while IFS=read -r h;do
                log_message "INFO" " -> $h"
            done <<< "$hidden"
        fi
    done
}
#fct pour detecter les modiufications de fichier de profil
detect_profile_modifications(){
    log_message "INFO" "Verification des fichiers de profil..."
    local profile_files=(
        "/etc/profile"
        "/etc/bash.bashrc"
        "/etc/environment"
    )
    #ajouter les fichiers utilisateur
    for home in /home/* /root;do
        [[ -d "$home" ]] || continue
        profile_files+=(
            "$home/.bashrc"
            "$home/.bash_profile"
            "$home/.profile"
            "$home/.bash_layout"
        )
    done

    #patterns suspects dans les fichiers de profil
    local suspicious_patterns=(
        "curl.*|.*sh"
        "wget.*|.*sh"
        "base64.*decode"
        "eval.*\$("
        "/dev/tcp"
        "/dev/udp"
        "nc.*-e"
        "hidden"
        "backdoor"
        "reverse"
    )
    for file in "${profile_files[@]}";do
        [[ ! -f "$file" ]] && continue
        for pattern in "${suspicious_patterns[@]}";do
            if grep -q "$pattern" "$file" 2>/dev/null;then
                log_message "HIGH" "Pattern suspect dans $file : $pattern"
                log_message "INFO" " ->$(grep "$pattern" "$file" | head -1)"
            fi
        done
        #verifier les modifications recentes
        local mod_date=$(stat -c %Y "$file" 2>/dev/null)
        local now=$(date +%s)
        local age_days=$(((now - mod_date) / 86400 ))
        if [[ $age_days -lt 7 ]];then
            log_message "LOW" "Fichier de profile modifie recemment: $file ($age_days jours)"
        fi
    done
}
#fct pour detecter les processus suspects
detect_suspicious_processes(){
    log_message "INFO" "Analyse des processus en cours..."
    #processus avec des noms suspects
    local suspicious_names=(
        "nc "
        "ncat"
        "socat"
        "python.*-c"
        "perl.*-e"
        "ruby.*-e"
        "php.*-r"
        "cryptominer"
        "xmrig"
        "minerd"
    )
    local ps_output=$(ps aux 2>/dev/null)
    for pattern in "${suspicious_names[@]}";do
        local found=$(echo "$ps_output" | grep -E "$pattern" | grep -v grep)
        if [[ -n "$found" ]];then
            log_message "HIGH" "Processus suspect detecte; pattern: $pattern :"
            log_message "INFO" " $found"
        fi
    done
    local notty=$(ps aux 2>/dev/null | awk '$7 == "?" && $11 !~ /^\[/' | head -20)
    if [[ -n "$notty" ]];then
        log_message "INFO" "Processus sans TTY, verifier manuellement si suspects: $(echo "$notty" | wc -l) trouves"
    fi
}
#fct pour verifier les alias suspects
detect_suspicious_aliases(){
    log_message "INFO" "Verification des alias..."

    #verifier les alias qui pourraient masquer des commandes
    local alias_output=$(alias 2>/dev/null)
    local dangerous_aliases=(
        "sudo="
        "su="
        "ssh="
        "ls="
        "cd="
        "passwd="
    )
    for pattern in "${dangerous_aliases[@]}";do
        if echo "$alias_output" | grep -q "^alias $pattern";then
            local alias_def=$(echo "$alias_output" | grep "^alias $pattern")
            log_message "MEDIUM" "Alias potentiellement dangereux: $alias_def"
        fi
    done
}
#fct principal du module
scan_redteam_artifacts(){
    detect_reverse_shells
    echo ""
    detect_unknown_ssh_keys
    echo ""
    detect_attack_tools
    echo ""
    detect_temp_binaires
    echo ""
    detect_profile_modifications
    echo ""
    detect_suspicious_processes
    echo ""
    detect_suspicious_aliases
    echo ""
    log_message "OK" "Analyse des artefacts Red Team terminee"
}
scan_redteam_artifacts
