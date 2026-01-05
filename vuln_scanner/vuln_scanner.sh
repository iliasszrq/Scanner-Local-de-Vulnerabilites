#!/bin/bash

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
REPORTS_DIR="$SCRIPT_DIR/reports"
HISTORY_DIR="$SCRIPT_DIR/history"
LIB_DIR="$SCRIPT_DIR/lib"

mkdir -p "$REPORTS_DIR" "$HISTORY_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SCAN_FILE="$HISTORY_DIR/scan_$TIMESTAMP.json"
REPORT_FILE="$REPORTS_DIR/report_$TIMESTAMP.html"

CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0

COMPARE_MODE=false
QUICK_MODE=false
LIST_MODE=false
INTERACTIVE_COMPARE=false
if [[ -f "$LIB_DIR/utils.sh" ]]; then
    source "$LIB_DIR/utils.sh"
fi
show_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║         SCANNER LOCAL DE VULNÉRABILITES v2.0                  ║"
    echo "║                   Projet Linux                                ║"
    echo "║                                                               ║"
    echo "║        Avec historisation et comparaison de scans             ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${BLUE}[INFO]${NC} Date du scan : $(date)"
    echo -e "${BLUE}[INFO]${NC} Machine : $(hostname)"
    echo -e "${BLUE}[INFO]${NC} Utilisateur : $(whoami)"
    echo ""
}

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

log_and_record() {
    local level="$1"
    local message="$2"
    local module="$3"
    local path="${4:-}"
    local recommendation="${5:-}"
    
    log_message "$level" "$message"
    
    if [[ "$level" != "INFO" && "$level" != "OK" ]]; then
        if declare -f add_finding > /dev/null; then
            add_finding "$module" "$level" "$message" "" "$path" "$recommendation"
        fi
    fi
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

show_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    RESUME DU SCAN                             ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${RED}CRITICAL : $CRITICAL_COUNT${NC}"
    echo -e "  ${RED}HIGH     : $HIGH_COUNT${NC}"
    echo -e "  ${YELLOW}MEDIUM   : $MEDIUM_COUNT${NC}"
    echo -e "  ${YELLOW}LOW      : $LOW_COUNT${NC}"
    echo -e "  ${BLUE}INFO     : $INFO_COUNT${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BLUE}[INFO]${NC} Rapport HTML : $REPORT_FILE"
    echo -e "${BLUE}[INFO]${NC} Données JSON : $SCAN_FILE"
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Scanner Local de Vulnerabilites v2.0"
    echo ""
    echo "Options:"
    echo "  -h, --help        Afficher cette aide"
    echo "  -c, --compare     Comparer avec le dernier scan"
    echo "  -C, --Compare     Choisir deux scans à comparer (interactif)"
    echo "  -l, --list        Lister tous les scans de l'historique"
    echo "  -q, --quick       Scan rapide (modules essentiels uniquement)"
    echo ""
    echo "Exemples:"
    echo "  $0                Lancer un scan complet"
    echo "  $0 -c             Scanner et comparer avec le precedent"
    echo "  $0 -l             Voir l'historique des scans"
    echo "  $0 -C             Comparer deux scans au choix"
    echo ""
    echo "Modules disponibles:"
    echo "  - suid_sgid       Fichiers SUID/SGID dangereux"
    echo "  - sudoers         Configuration sudo"
    echo "  - path_check      Vulnerabilites PATH"
    echo "  - systemd_timers  Timers systemd suspects"
    echo "  - cve_check       Vulnerabilités CVE connues"
    echo "  - redteam         Artefacts Red Team"
    echo ""
}


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


run_scan() {
    show_banner
    check_privileges
    
    if [[ "$QUICK_MODE" == true ]]; then
        log_message "INFO" "Mode rapide activé - modules essentiels uniquement"
        run_module "suid_sgid.sh"
        run_module "sudoers_check.sh"
        run_module "redteam_artifacts.sh"
    else
        run_module "suid_sgid.sh"
        run_module "sudoers_check.sh"
        run_module "path_check.sh"
        run_module "systemd_timers.sh"
        run_module "cve_check.sh"
        run_module "redteam_artifacts.sh"
    fi
    
    if declare -f generate_scan_json > /dev/null; then
        generate_scan_json "$SCAN_FILE"
    fi
    
    run_module "generate_report.sh"
    
    show_summary
    
    if [[ "$COMPARE_MODE" == true ]]; then
        if [[ -f "$MODULES_DIR/compare.sh" ]]; then
            source "$MODULES_DIR/compare.sh"
            compare_with_latest "$SCAN_FILE" "$HISTORY_DIR"
        fi
    fi
}

# Parser les arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -c|--compare)
            COMPARE_MODE=true
            shift
            ;;
        -C|--Compare)
            INTERACTIVE_COMPARE=true
            shift
            ;;
        -l|--list)
            LIST_MODE=true
            shift
            ;;
        -q|--quick)
            QUICK_MODE=true
            shift
            ;;
        *)
            echo "Option inconnue : $1"
            echo "Utilisez -h pour l'aide"
            exit 1
            ;;
    esac
done

if [[ "$LIST_MODE" == true ]]; then
    # Charger les fonctions utilitaires
    if [[ -f "$LIB_DIR/utils.sh" ]]; then
        source "$LIB_DIR/utils.sh"
    fi
    list_all_scans "$HISTORY_DIR"
elif [[ "$INTERACTIVE_COMPARE" == true ]]; then
    # Mode comparaison interactive
    if [[ -f "$MODULES_DIR/compare.sh" ]]; then
        source "$MODULES_DIR/compare.sh"
        select_scan_for_comparison "$HISTORY_DIR"
    else
        echo "Module de comparaison non trouvé"
        exit 1
    fi
else
    # Mode scan normal
    run_scan
fi