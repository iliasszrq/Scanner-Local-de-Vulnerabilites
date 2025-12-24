#!/bin/bash


#couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

#Repertoire du projet
SCRIPT_DIR="$(cd"$(dirname "${BASH_SOURCE[0]}") && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
REPORTS_DIR="$SCRIPTS_DIR/reports"
HISTORY_DIR="$SCRIPTS_DIR/history"
LIB_DIR="$SCRIPT_DIR/lib"

#fichier de scan actuel avec timestamp pour l'historique
TIMESTAMP=$(date + %Y%m%d_%H%M%S")
SCAN_FILE="$HISTORY_DIR/scan_$TIMESTAMP.json"
REPORT_FILE="$REPORTS_DIR/report_$TIMESTAMP.html"

#Les compteurs de vulnerabilites
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0

#Fct pour afficher une barriere de demarage

echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║         SCANNER LOCAL DE VULNÉRABILITÉS v1.0                  ║"
    echo "║                   Projet Linux                                ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${BLUE}[INFO]${NC} Date du scan : $(date)"
    echo -e "${BLUE}[INFO]${NC} Machine : $(hostname)"
    echo -e "${BLUE}[INFO]${NC} Utilisateur : $(whoami)"
    echo ""
}
# FCT POUR AFFICHER LES MESSAGES SELON LEUR NIVEAU
log_message() {
    local level="$1"
    local message="$2"
    
    case "$level" in
        "CRITICAL")
            echo -e "${RED}[CRITICAL]${NC} $message"
            ((CRITICAL_COUNT++))
            ;;
        "HIGH")
            echo -e "${RED}[HIGH]${NC} $message"
            ((HIGH_COUNT++))
            ;;
        "MEDIUM")
            echo -e "${YELLOW}[MEDIUM]${NC} $message"
            ((MEDIUM_COUNT++))
            ;;
        "LOW")
            echo -e "${YELLOW}[LOW]${NC} $message"
            ((LOW_COUNT++))
            ;;
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ((INFO_COUNT++))
            ;;
        "OK")
            echo -e "${GREEN}[OK]${NC} $message"
            ;;
        *)
            echo "$message"
            ;;
    esac
}
check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        log_message "INFO" "Exécution en tant que root - scan complet disponible"
        return 0
    else
        log_message "INFO" "Exécution sans privilèges root - scan limité"
        return 1
    fi
}

# Fonction pour afficher le résumé final
show_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    RÉSUMÉ DU SCAN                             ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${RED}CRITICAL : $CRITICAL_COUNT${NC}"
    echo -e "  ${RED}HIGH     : $HIGH_COUNT${NC}"
    echo -e "  ${YELLOW}MEDIUM   : $MEDIUM_COUNT${NC}"
    echo -e "  ${YELLOW}LOW      : $LOW_COUNT${NC}"
    echo -e "  ${BLUE}INFO     : $INFO_COUNT${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}[INFO]${NC} Rapport HTML généré : $REPORT_FILE"
    echo -e "${BLUE}[INFO]${NC} Données sauvegardées : $SCAN_FILE"
}

# Fonction pour charger et exécuter un module
run_module() {
    local module_name="$1"
    local module_path="$MODULES_DIR/$module_name"
    
    if [[ -f "$module_path" ]]; then
        echo ""
        echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
        echo -e "${CYAN}[MODULE] Exécution de : $module_name${NC}"
        echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
        source "$module_path"
    else
        log_message "INFO" "Module non trouvé : $module_name"
    fi
}

main() {
    # Afficher la bannière
    show_banner
    
    # Vérifier les privilèges
    check_privileges
    
    # Exécuter chaque module de détection
    run_module "suid_sgid.sh"
    run_module "sudoers_check.sh"
    run_module "path_check.sh"
    run_module "systemd_timers.sh"
    run_module "cve_check.sh"
    run_module "redteam_artifacts.sh"
    
    # Générer le rapport HTML
    run_module "generate_report.sh"
    
    # Afficher le résumé
    show_summary
}

# Vérifier les arguments (pour les options futures)
case "$1" in
    -h|--help)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  -h, --help      Afficher cette aide"
        echo "  -c, --compare   Comparer avec le dernier scan"
        echo "  -q, --quick     Scan rapide (modules essentiels)"
        exit 0
        ;;
    -c|--compare)
        COMPARE_MODE=true
        ;;
    -q|--quick)
        QUICK_MODE=true
        ;;
esac

# Lancer le programme principal
main
