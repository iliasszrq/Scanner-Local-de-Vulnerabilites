# 🛡️ Scanner Local de Vulnérabilités Linux

[![Bash](https://img.shields.io/badge/Bash-5.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-Educational-blue.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)]()

> **Projet de Fin de Module - Cybersécurité Shell Scripting**  
> Scanner automatisé de vulnérabilités locales pour systèmes Linux

---

## 📋 Table des Matières

- [Aperçu](#-aperçu)
- [Fonctionnalités](#-fonctionnalités)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Modules](#-modules)
- [Rapports](#-rapports)
- [Historisation](#-historisation)
- [Exemples](#-exemples)
- [Auteur](#-auteur)

---

## 🎯 Aperçu

Ce scanner de vulnérabilités est un outil de sécurité développé en **Bash** permettant d'auditer la configuration de sécurité d'un système Linux. Il détecte automatiquement les failles de sécurité courantes, les mauvaises configurations et les artefacts potentiellement malveillants.

### Objectifs Pédagogiques

- Maîtriser le scripting Shell avancé
- Comprendre les vecteurs d'attaque sur Linux
- Apprendre les bonnes pratiques de sécurisation
- Développer un outil de sécurité modulaire

---

## ✨ Fonctionnalités

| Fonctionnalité | Description |
|----------------|-------------|
| 🔍 **Scan Multi-Modules** | 6 modules d'analyse couvrant différents aspects de la sécurité |
| 📊 **Rapport HTML** | Génération automatique d'un rapport visuel interactif |
| 📁 **Historisation JSON** | Sauvegarde de chaque scan pour suivi dans le temps |
| 🔄 **Comparaison de Scans** | Détection des nouvelles vulnérabilités et corrections |
| 🎨 **Interface Colorée** | Affichage clair avec codes couleurs par sévérité |
| ⚡ **Mode Rapide** | Scan des modules essentiels uniquement |

### Niveaux de Sévérité

| Niveau | Couleur | Description |
|--------|---------|-------------|
| `CRITICAL` | 🔴 Rouge | Vulnérabilité exploitable immédiatement |
| `HIGH` | 🟠 Orange | Risque élevé nécessitant une action rapide |
| `MEDIUM` | 🟡 Jaune | Risque modéré à corriger |
| `LOW` | 🔵 Bleu | Risque faible, amélioration recommandée |
| `INFO` | ⚪ Gris | Information utile |

---

## 🏗️ Architecture

```
vuln_scanner/
├── vuln_scanner.sh          # Script principal
├── modules/
│   ├── suid_sgid.sh         # Analyse des fichiers SUID/SGID
│   ├── sudoers_check.sh     # Vérification de la configuration sudo
│   ├── path_check.sh        # Détection des vulnérabilités PATH
│   ├── systemd_timers.sh    # Analyse des timers systemd
│   ├── cve_check.sh         # Vérification des CVE connues
│   ├── redteam_artifacts.sh # Détection d'artefacts malveillants
│   ├── compare.sh           # Comparaison entre scans
│   └── generate_report.sh   # Génération du rapport HTML
├── lib/
│   └── utils.sh             # Fonctions utilitaires et gestion JSON
├── history/                 # Historique des scans (JSON)
│   ├── scan_YYYYMMDD_HHMMSS.json
│   └── latest.json -> ...
└── reports/                 # Rapports générés (HTML)
    └── report_YYYYMMDD_HHMMSS.html
```

---

## 🚀 Installation

### Prérequis

- Système Linux (Ubuntu, Debian, CentOS, etc.)
- Bash 4.0 ou supérieur
- Droits root/sudo (recommandé pour un scan complet)

### Étapes

```bash
# 1. Cloner le dépôt
git clone https://github.com/votre-username/Scanner-Local-de-Vulnerabilites.git

# 2. Accéder au répertoire
cd Scanner-Local-de-Vulnerabilites

# 3. Rendre les scripts exécutables
chmod +x vuln_scanner.sh
chmod +x modules/*.sh

# 4. (Optionnel) Vérifier l'installation
./vuln_scanner.sh --help
```

---

## 📖 Utilisation

### Commandes Principales

```bash
# Scan complet avec droits root
sudo ./vuln_scanner.sh

# Scan rapide (modules essentiels uniquement)
sudo ./vuln_scanner.sh -q

# Scan avec comparaison automatique au dernier scan
sudo ./vuln_scanner.sh -c

# Comparaison interactive entre deux scans
./vuln_scanner.sh -C

# Afficher l'historique des scans
./vuln_scanner.sh -l

# Afficher l'aide
./vuln_scanner.sh -h
```

### Options Disponibles

| Option | Forme Longue | Description |
|--------|--------------|-------------|
| `-h` | `--help` | Affiche l'aide |
| `-q` | `--quick` | Mode rapide (3 modules) |
| `-c` | `--compare` | Compare avec le dernier scan |
| `-C` | `--Compare` | Comparaison interactive |
| `-l` | `--list` | Liste l'historique des scans |

---

## 🔧 Modules

### 1. SUID/SGID (`suid_sgid.sh`)

Analyse les fichiers avec les bits SUID et SGID activés.

**Détecte :**
- Binaires SUID dangereux (vim, find, python, etc.)
- Fichiers SUID non standards
- Permissions anormales

**Exemple de sortie :**
```
[CRITICAL] SUID dangereux trouvé : /usr/bin/find
[MEDIUM] SUID inhabituel : /usr/local/bin/custom_app
```

---

### 2. Sudoers (`sudoers_check.sh`)

Vérifie la configuration sudo pour détecter les mauvaises pratiques.

**Détecte :**
- Utilisation de `NOPASSWD`
- Wildcards dangereux
- Binaires permettant l'évasion vers un shell root

**Exemple de sortie :**
```
[HIGH] NOPASSWD détecté : user ALL=(ALL) NOPASSWD: /usr/bin/vim
[HIGH] Binaire dangereux avec sudo : vim
```

---

### 3. PATH Injection (`path_check.sh`)

Analyse la variable PATH pour détecter les vulnérabilités d'injection.

**Détecte :**
- Répertoire courant (`.`) dans PATH
- Répertoires temporaires (`/tmp`, `/var/tmp`)
- Répertoires world-writable
- Répertoires inexistants

**Exemple de sortie :**
```
[CRITICAL] PATH contient le répertoire courant (.)
[HIGH] PATH contient un répertoire temporaire : /tmp
```

---

### 4. Timers Systemd (`systemd_timers.sh`)

Analyse les tâches planifiées systemd pour détecter les activités suspectes.

**Détecte :**
- Timers avec noms suspects (hexadécimaux, aléatoires)
- ExecStart pointant vers `/tmp` ou `/dev/shm`
- Scripts world-writable
- Timers créés récemment

**Exemple de sortie :**
```
[HIGH] Service avec ExecStart suspect : /tmp/malicious.sh
[MEDIUM] Timer récent : backup.timer (créé il y a 2 jours)
```

---

### 5. CVE Check (`cve_check.sh`)

Compare les versions des logiciels installés avec une base de vulnérabilités connues.

**Vérifie :**
- Version du kernel (Dirty COW, etc.)
- OpenSSL, OpenSSH, Sudo, Bash
- Apache, Nginx, PHP, MySQL
- Polkit (PwnKit)

**Exemple de sortie :**
```
[CRITICAL] Vulnérabilité potentielle : CVE-2021-4034 (PwnKit)
[HIGH] Kernel vulnérable à Dirty COW (CVE-2016-5195)
```

---

### 6. Red Team Artifacts (`redteam_artifacts.sh`)

Recherche des traces d'activités malveillantes ou de tests d'intrusion.

**Détecte :**
- Patterns de reverse shells
- Outils d'attaque (linpeas, pspy, mimikatz, etc.)
- Clés SSH suspectes
- Binaires dans les répertoires temporaires
- Modifications récentes des fichiers de profil
- Connexions sur ports suspects (4444, 31337, etc.)

**Exemple de sortie :**
```
[CRITICAL] Pattern de reverse shell trouvé : /dev/tcp/
[CRITICAL] Outil d'attaque potentiel : linpeas.sh
[HIGH] Clé SSH avec options suspectes
```

---

## 📊 Rapports

### Rapport HTML

Chaque scan génère un rapport HTML interactif dans le dossier `reports/`.

**Caractéristiques :**
- Dashboard avec compteurs par sévérité
- Sections dépliables par module
- Design responsive (mobile-friendly)
- Mode sombre professionnel
- Bouton d'impression

**Ouvrir le rapport :**
```bash
firefox reports/report_*.html
# ou
xdg-open reports/report_*.html
```

### Rapport JSON

Les données brutes sont sauvegardées en JSON dans `history/`.

**Structure :**
```json
{
    "scan_info": {
        "version": "1.0",
        "date": "2025-01-05T10:30:00+00:00",
        "hostname": "server01",
        "kernel": "5.15.0-generic",
        "os": "Ubuntu 22.04 LTS"
    },
    "summary": {
        "total_findings": 15,
        "critical": 2,
        "high": 5,
        "medium": 6,
        "low": 2,
        "info": 10
    },
    "findings": [...]
}
```

---

## 📈 Historisation

### Fonctionnement

1. Chaque scan crée un fichier `scan_YYYYMMDD_HHMMSS.json`
2. Un lien symbolique `latest.json` pointe vers le dernier scan
3. La comparaison permet de suivre l'évolution

### Comparaison de Scans

```bash
# Comparaison automatique avec le dernier scan
sudo ./vuln_scanner.sh -c

# Sortie exemple :
# ╔════════════════════════════════════════════╗
# ║         COMPARAISON DES SCANS              ║
# ╚════════════════════════════════════════════╝
#
# CRITICAL : 5 → 3  [↓ -2]
# HIGH     : 3 → 2  [↓ -1]
# MEDIUM   : 2 → 5  [↑ +3]
#
# ✅ AMÉLIORATION : 2 vulnérabilité(s) corrigée(s)
#
# ── Nouvelles vulnérabilités 🆕 ──
# ── Vulnérabilités résolues ✅ ──
# ── Vulnérabilités persistantes ⏳ ──
```

---

## 💡 Exemples

### Exemple 1 : Premier Audit

```bash
# Scan complet d'un nouveau serveur
sudo ./vuln_scanner.sh

# Consulter le rapport
firefox reports/report_*.html
```

### Exemple 2 : Suivi Post-Correction

```bash
# Après avoir corrigé des vulnérabilités
sudo ./vuln_scanner.sh -c

# Vérifier que les corrections sont détectées
```

### Exemple 3 : Audit Rapide

```bash
# Vérification rapide avant mise en production
sudo ./vuln_scanner.sh -q
```

---

## ⚠️ Limitations

- Base CVE locale simplifiée (non exhaustive)
- Nécessite les droits root pour un scan complet
- Optimisé pour les distributions Debian/Ubuntu
- Ne remplace pas un scanner professionnel (Nessus, OpenVAS)

---

## 🔮 Améliorations Futures

- [ ] Intégration avec des bases CVE en ligne
- [ ] Support des distributions RHEL/CentOS
- [ ] Export PDF du rapport
- [ ] Mode daemon pour scans programmés
- [ ] Intégration SIEM (syslog)

---

## 👨‍💻 Auteur

**Iliass Zarquan**  
Projet de Fin de Module

---