#!/bin/bash
#une database local des vulnerabilites critiques connues
declare -A KNOWN_VULNS=(
    # OpenSSL
    ["openssl:1.0.1"]="CVE-2014-0160:Heartbleed - fuite de mémoire:CRITICAL"
    ["openssl:1.0.2"]="CVE-2016-2107:Padding Oracle:HIGH"
    
    # Apache
    ["apache2:2.4.49"]="CVE-2021-41773:Path Traversal:CRITICAL"
    ["apache2:2.4.50"]="CVE-2021-42013:Path Traversal (bypass):CRITICAL"
    
    # Sudo
    ["sudo:1.8.2"]="CVE-2019-14287:Bypass de restriction utilisateur:HIGH"
    ["sudo:1.9.5p1"]="CVE-2021-3156:Baron Samedit - heap overflow:CRITICAL"
    
    # OpenSSH
    ["openssh:7.2"]="CVE-2016-10012:Privilege escalation:HIGH"
    ["openssh:8.3"]="CVE-2020-15778:Command injection via scp:MEDIUM"
    
    # Bash (Shellshock)
    ["bash:4.3"]="CVE-2014-6271:Shellshock:CRITICAL"
    
    # PHP
    ["php:7.4.0"]="CVE-2019-11043:Remote code execution:CRITICAL"
    ["php:8.0.0"]="CVE-2021-21702:Null pointer dereference:MEDIUM"
    
    # MySQL/MariaDB
    ["mysql:5.7.0"]="CVE-2016-6662:Remote root code execution:CRITICAL"
    ["mariadb:10.1.0"]="CVE-2016-6662:Remote root code execution:CRITICAL"
    
    # Kernel Linux (exemples)
    ["linux:4.4.0"]="CVE-2016-5195:Dirty COW - privesc:CRITICAL"
    ["linux:5.8.0"]="CVE-2021-3493:Overlayfs privesc:HIGH"
    
    # Polkit
    ["polkit:0.105"]="CVE-2021-4034:PwnKit - local privesc:CRITICAL"
    
    # Exim
    ["exim:4.87"]="CVE-2019-15846:Remote code execution:CRITICAL"
    
    # Samba
    ["samba:4.5.0"]="CVE-2017-7494:SambaCry - RCE:CRITICAL"
)

#fct pour obtenir la version d'un package(multi distro)
get_package_version(){
    local package="$1"
    local version=""

    #Essayer dpkg (Debian/ubuntu)
    if command -v dpkg &>/dev/null;then
        version=$(dpkg -l "$package" 2>/dev/null | awk '/^ii/ {print $3}' | head -1)
        if [[ -n "$version" ]];then
            echo "$version"
            return 0
        fi
    fi

    #essayer rpm; RHEL/CENTOS/FEDORA
    if command -v rpm &>/dev/null;then
        version=$(rpm -q "$package" 2>/dev/null | sed "s/${package}-//" | head -1)
        if [[ -n "$version" && "$version" != *"not installed"* ]];then
            echo "$version"
            return 0
        fi
    fi

    #essayer la commande --version
    if command -v "$package" &>/dev/null;then
        version=$("$package" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.?[0-9]*' | head -1)
        if [[ -n "$version" ]];then
            echo "$version"
            return 0
        fi
    fi
    return 1
}
#fct pour comparer les versions
version_lte(){
    local v1="$1"
    local v2="$2"

    [[ "$v1" = "$v2" ]] && return 0
    [[ "$(printf '%s\n' "$v1" "$v2" | sort -V | head -n1)" = "$v1" ]]
}
#fct pour verifier les vulnerabilite pour un package
check_package_vulns(){
    local package="$1"
    local installed_version="$2"
    for key in "${!KNOWN_VULNS[@]}";do
        local vuln_package=$(echo "$key" | cut -d: -f1)
        local vuln_version=$(echo "$key" | cut -d: -f2)

        if [[ "$vuln_package" == "$package" ]];then
            local vuln_info="${KNOWN_VULNS[$key]}"
            local cve=$(echo "$vuln_info" | cut -d: -f1)
            local description=$(echo "$vuln_info" | cut -d: -f2)
            local severity=$(echo "$vuln_info" | cut -d: -f3)

            #verifier si la version installee est potensiellement vulnerable
            if [[ "$installed_version" == "$vuln_version"* ]] || version_lte "$installed_version" "$vuln_version";then
                log_message "$severity" "Vulnerabilite potentielle detectee :"
                log_message "INFO" " ->Paquet: $package"
                log_message "INFO" " ->Version installee: $installed_version"
                log_message "INFO" " ->Version vulnerable: $vuln_version"
                log_message "INFO" " ->CVE: $cve"
                log_message "INFO" " ->Description: $description"
                echo ""
            fi
        fi
    done
}
#fct pour scanner les packages critiques
scan_critical_packages(){
    local critical_packages=(
        "openssl"
        "openssh"
        "openssh-server"
        "apache2"
        "httpd"
        "nginx"
        "sudo"
        "bash"
        "php"
        "mysql-server"
        "mariadb-server"
        "postgresql"
        "samba"
        "exim4"
        "postfix"
        "polkit"
        "pkexec"
    )
    log_message "INFO" "Verification des paquets critiques..."
    echo ""
    for package in "${critical_packages[@]}";do
        local version=$(get_package_version "$package")
        if [[ -n "$version" ]];then
            log_message "INFO" "Trouve: $package version $version"
            check_package_vulns "$package" "$version"
        fi
    done
}
#verifier la version du kernel
check_kernel_version(){
    log_message "INFO" "Verification du Kernel..."

    local kernel_version=$(uname -r)
    log_message "INFO" "Kernel actuel: $kernel_version"
    #extraire la version majeure.mineure
    local major_minor=$(echo "$kernel_version" | grep -oE '^[0-9]+\.[0-9]+')
    #verification basiques de kernels connus vulnerables 
    case "$major_minor" in
        "4.4"|"4.5"|"4.6"|"4.7"|"4.8"|"4.9"|"4.10"|"4.11"|"4.12"|"4.13")
            log_message "HIGH" "Kernel potentiellement vulnérable à Dirty COW (CVE-2016-5195)"
            ;;
        "5.8"|"5.9"|"5.10"|"5.11")
            log_message "MEDIUM" "Kernel potentiellement vulnérable à CVE-2021-3493 (overlayfs)"
            ;;
    esac

    #verification d'age du kernel
    local kernel_date=$(stat -c %Y /boot/vmlinuz-${kernel_version} 2>/dev/null)
    if [[ -n "$kernel_date" ]];then
        local now=$(date +%s)
        local age_days=$(( (now - kernel_date) / 86400))

        if [[ $age_days -gt 365 ]];then
            log_message "MEDIUM" "Kernel non mis a jour depuis $age_days jours"
        fi
    fi
}
#fct pour verifier packages avec mis a jour de securite
check_security_updates(){
    log_message "INFO" "Verification des mises a jour de securite..."
    
    #debian/ubuntu
    if command -v apt-get &>/dev/null;then
        apt-get update -qq 2>/dev/null

        local security_updates=$(apt-get -s upgrade 2>/dev/null | grep -i security | wc -l)

        if [[ $security_updates -gt 0 ]];then
            log_message "HIGH" "$security_updates mises a jour de securite disponibles"
            log_message "INFO" "Executez: sudo apt-get upgrade"
        else
            log_message "OK" "Aucun mise a jour de securite."
        fi
    fi

    #pour RHEL/CentOS
    if command -v yum &>/dev/null;then
        local security_updates=$(yum check-update --security 2>/dev/null | grep -v "^$" | wc -l)

        if [[ $security_updates -gt 0 ]];then
            log_message "HIGH" "Mises a jour de securite disponibles"
            log_message "INFO" "Executer: sudo yum update --security"
        fi
    fi
}
#fct generer un rapport des versions installees
generate_version_inventory(){
    log_message "INFO" "Generation de l'inventaire des versions..."
    local inventory_file="$HISTORY_DIR/versions_$TIMESTAMP.txt"
    {
        echo "        Inventaire des versions         " 
        echo "Date: $(date)"
        echo "Machine: $(hostname)"
        echo ""
        echo "   Kernel   "
        uname -a
        echo ""
        echo "   Distribution   "
        cat /etc/os-release 2>/dev/null | head -5
        echo ""
        echo "   Paquets critiques   "
        for pkg in openssl openssh sudo bash apache2 nginx php mysql postgresql;do
            local ver=$(get_package_version "$pkg")
            [[ -n "$ver" ]] && echo "$pkg: $ver"
        done
    } > "$inventory_file" 2>/dev/null
    log_message "INFO" "Inventaire sauvegarde : $inventory_file"
}
#fct principal du module
scan_cve(){
    check_kernel_version
    echo ""
    scan_critical_packages
    check_security_updates
    generate_version_inventory
    echo "" 
    log_message "OK" "Analyse CVE terminee"
    log_message "INFO" "Note: cette analyse utilise une base local simplifiee"
}
scan_cve