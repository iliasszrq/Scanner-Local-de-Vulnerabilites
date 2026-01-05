#!/bin/bash

#listes des binaire suid connus et normaux
LEGITMATE_SUID=(
    "/usr/bin/passwd"
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/newgrp"
    "/usr/bin/gpasswd"
    "/usr/bin/pkexec"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
)

#liste des binaire suid dangereux
DANGEROUS_SUID=(
    "nmap"
    "vim"
    "vi"
    "nano"
    "less"
    "more"
    "man"
    "awk"
    "gawk"
    "python"
    "python3"
    "perl"
    "ruby"
    "lua"
    "php"
    "node"
    "bash"
    "sh"
    "zsh"
    "ksh"
    "csh"
    "find"
    "cp"
    "mv"
    "dd"
    "tar"
    "zip"
    "git"
    "ftp"
    "nc"
    "netcat"
    "socat"
    "curl"
    "wget"
    "tcpdump"
    "tee"
    "env"
    "strace"
    "ltrace"
    "gdb"

)

#fct pour verifier si un binaire est dans la liste LEGITMATE_SUID

is_legitmate(){
    local file="$1"
    for legit in "${LEGITMATE_SUID[@]}";do
        if [[ "$file" == "$legit" ]]; then
            return 0
        fi
    done
    return 1
}

#fct pour verifier si un binaire est dangereux
is_dangerous(){
    local file="$1"
    local basename=$(basename "$file")
    for dangerous in "${DANGEROUS_SUID[@]}";do
        if [[ "$basename" == "$dangerous" ]];then
            return 0
        fi
    done
    return 1
}

#fct ayant le but de ce module (scanner les suid)
scan_suid_sgid(){
    log_message "INFO" "RECHERCHE DES FICHIER SUID ..."

    local suid_files=$(find / -perm -4000 -type f 2>/dev/null)        #2>/dev/null pour ignorer les erreurs; -perm -4000 rechercher tous les fichier avec le bit suid

    local suid_count=0
    local dangerous_count=0
    local unknown_count=0

    #analyser chaque fichier
    while IFS= read -r file;do
        if [[ -z "$file" ]];then
            continue
        fi

        ((suid_count++))

        if is_dangerous "$file";then
            log_message "CRITICAL" "SUID dangereux trouve : $file"
            ((dangerous_count++))
        elif ! is_legitmate "$file";then
            log_message "MEDIUM" "SUID inhabituel : $file"
            local owner=$(stat -c '%U' "$file" 2>/dev/null)
            local perms=$(stat -c '%a' "$file" 2>/dev/null)
            log_message "INFO" " -> Proprietere: $owner, Permissions: $perms"
            ((unknown_count++))
        fi
    done <<< "$suid_files"
    log_message "INFO" "RECHERCHE DES FICHIERS SGID..."
    local sgid_files=$(find / -perm -2000 -type f 2>/dev/null)
    local sgid_count=0
    
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        ((sgid_count++))
    done <<< "$sgid_files"

    echo " "
    log_message "INFO" "Resume SUID/SGID: "
    log_message "INFO" " ->Fichiers SUID trouves : $suid_count"
    log_message "INFO" " ->Fichier SGID trouves : $sgid_count"
    log_message "INFO" " ->Binaires dangereux : $dangerous_count"
    log_message "INFO" " ->Binaires inconnus a verifier : $unknown_count"  
}
scan_suid_sgid