#!/bin/bash

SUDO_DANGEROUS_BINS=(
    "vim"
    "vi"
    "nano"
    "emacs"
    "less"
    "more"
    "man"
    "awk"
    "gawk"
    "nawk"
    "python"
    "python3"
    "python2"
    "perl"
    "ruby"
    "lua"
    "php"
    "node"
    "irb"
    "ftp"
    "sftp"
    "ssh"
    "scp"
    "rsync"
    "git"
    "find"
    "env"
    "rlwrap"
    "xargs"
    "strace"
    "ltrace"
    "gdb"
    "mysql"
    "psql"
    "sqlite3"
    "zip"
    "tar"
    "journalctl"
    "systemctl"
    "apt"
    "apt-get"
    "yum"
    "dnf"
    "pip"
    "pip3"
    "cpan"
    "gem"
    "docker"
    "lxc"
    "screen"
    "tmux"
    "script"
    "expect"
    "ed"
    "sed"
    "busybox"
    "ash"
    "bash"
    "sh"
    "zsh"
    "csh"
    "ksh"
    "tclsh"
    "wish"
)
check_sudoers_main(){
    local sudoers_file="/etc/sudoers"

    if [[! -r "$sudoers_file"]];then
        log_message "INFO" "Impossible de lire $sudoers_file, droits insufisants"
        log_message "INFO" "Relancer le script avec sudo pour un scan complet"
        return 1
    fi
    log_message "INFO" "Analyse de $sudoers_file..."
    while IFS= read -r line;do
        #ignorer les lines vides et les commentaires
        [[-z "$line" || "$line" =~ ^[[:space:]]*#]] && continue

        #Detecter NOPASSWD
        if echo "$line" | grep -qi "NOPASSWD";then
            log_message "HIGH" "NOPASSWD detecte : $line"
            #check si critique ou non
            if echo "$line" | grep -q "NOPASSWD.*ALL";then
                log_message "CIRITICAL" " ->NOPASSWD avec ALL = acces root sans mot de passe"
            fi
        fi
        #Detecter les wildcards dangereux
        if echo "$line" | grep -qE '\*|/\.\*';then
            log_message "MEDIUM" "WILDCARD detecte"
            log_message "INFO" " -> Les wildcards peuvent permettre des injections"
        fi
        #Detecter (ALL) ou (root)
        for dangerous_bin in "${SUDO_DANGEROUS_BINS[@]}";do
            if echo "$line" | grep -qiE "(ALL|root).*[/:]$dangerous_bin(\s|$|,)";then
                log_message "HIGH" "Binaire dangereux avec sudo : $dangerous_bin dans: $line"
                log_message "INFO" " -> $dangerous_bin permet d'echaper vers un shell root"
            fi
        done

        #Detecter les config (ALL:ALL) ALL
        if echo "$line" | grep -qE '\(ALL\s*:\s*ALL\)\s+ALL';then
            log_message "HIGH" "Privileges sudo complets detectes: $line"
        fi
    done < "$sudoers_file"
}

#Fonction pour analyser les fichiers dans /etc/sudoers.d/
check_sudoers_d(){
    local sudoers_dir="/etc/sudoers.d"
    if[[ ! -d "$sudoers_dir" ]];then
        log_message "INFO" "Repertoire $sudoers_dir introuvable."
        return 0
    fi
    if [[! -r "$sudoers_dir" ]];then
        log_message "INFO" "Impossible de lire $sudoers_dir, droit insuffisants"
        return 1
    fi
    log_message "INFO" "Analyse des fichiers dans $sudoers_dir..."
    for file in "$sudoers_dir"/*;do
        [[! -f "$file"]] && continue
        [[! -r "$file"]] && continue

        #verification des permissions des fichiers
        local perms=$(stat -c '%a' "$file" 2>/dev/null)
        if [["$perms" != "440" && "$perms" != "400"]];then
            log_message "MEDIUM" "Permissions incorrectes sur $file : $perms"
        fi

        while IFS=read -r line;do
            [[-z "$line" || "$line" =~ ^[[:space:]]*#]] && continue
            if echo "$line" || grep -qi "NOPASSWD";then
                log_message "HIGH" "NOPASSWD dans $file : $line"
            fi
            for dangerous_bin in "${SUDO_DANGEROUS_BINS[@]}";do
                if echo "$line" | grep -qi "$dangerous_bin";then
                    log_message "MEDIUM" "Binaire peut etre dangereux dans $file : $dangerous_bin"
                fi
            done
        done < "$file"
    done
}
#fct pour verifier sudo -l pour user actuel
check_current_user_sudo(){
    log_message "INFO" "Verification des droits sudo de l'utilisateur courant..."
    local sudo_rights=$(sudo -l 2>/dev/null)

    if [[ -z "$sudo_rights"]];then
        log_message "INFO" "Impossible de determiner les droits sudo"
        return 0
    fi
    echo "$sudo_rights" | while IFS= read -r line;do
        if echo "$line" | grep -qi "NOPASSWD";then
            log_message "HIGH" "User actuel a NOPASSWD : $line"
        fi
        if echo "$line" | grep -qi "(ALL.*ALL)";then
            log_message "HIGH" "User actuel a des droits etendus : $line"
        fi
        for dangerous_bin in "${SUDO_DANGEROUS_BIN[@]}";do
            if echo "$line" | grep -qi "bin/$dangerous_bin";then
                log_message "MEDIUM" "User peut executer $dangerous_bin avec sudo"
            fi
        done
    done
}
#fct princinpal
scan_sudoers(){
    check_sudoers_main
    check_sudoers_d
    check_current_user_sudo
    echo " "
    log_message "OK" "Analyse sudoers terminee"
}
scan_sudoers