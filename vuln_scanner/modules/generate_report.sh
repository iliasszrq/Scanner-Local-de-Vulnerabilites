#!/bin/bash

generate_html_header() {
    cat << 'HTMLHEADER'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Scan de Vulnérabilités</title>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
            --ok: #28a745;
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --text: #eee;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, #0f3460, #16213e);
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            color: #00d9ff;
        }
        
        .scan-info {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .scan-info span {
            background: rgba(255,255,255,0.1);
            padding: 8px 20px;
            border-radius: 20px;
            font-size: 0.9em;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-card);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card.critical { border-left: 4px solid var(--critical); }
        .stat-card.high { border-left: 4px solid var(--high); }
        .stat-card.medium { border-left: 4px solid var(--medium); }
        .stat-card.low { border-left: 4px solid var(--low); }
        .stat-card.info { border-left: 4px solid var(--info); }
        
        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-card.critical .stat-number { color: var(--critical); }
        .stat-card.high .stat-number { color: var(--high); }
        .stat-card.medium .stat-number { color: var(--medium); }
        .stat-card.low .stat-number { color: var(--low); }
        .stat-card.info .stat-number { color: var(--info); }
        
        .section {
            background: var(--bg-card);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .section-header {
            background: rgba(0,0,0,0.3);
            padding: 15px 25px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .section-header:hover {
            background: rgba(0,0,0,0.4);
        }
        
        .section-header h2 {
            font-size: 1.3em;
            color: #00d9ff;
        }
        
        .section-content {
            padding: 20px 25px;
            display: none;
        }
        
        .section-content.active {
            display: block;
        }
        
        .finding {
            background: rgba(0,0,0,0.2);
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            border-left: 3px solid var(--info);
        }
        
        .finding.critical { border-left-color: var(--critical); }
        .finding.high { border-left-color: var(--high); }
        .finding.medium { border-left-color: var(--medium); }
        .finding.low { border-left-color: var(--low); }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        
        .severity-badge {
            padding: 3px 12px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-badge.critical { background: var(--critical); }
        .severity-badge.high { background: var(--high); color: #000; }
        .severity-badge.medium { background: var(--medium); color: #000; }
        .severity-badge.low { background: var(--low); }
        .severity-badge.info { background: var(--info); }
        
        .toggle-icon {
            font-size: 1.5em;
            transition: transform 0.3s;
        }
        
        .section.open .toggle-icon {
            transform: rotate(180deg);
        }
        
        code {
            background: rgba(0,0,0,0.4);
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #00ff88;
        }
        
        .recommendations {
            background: linear-gradient(135deg, #1e4d2b, #16213e);
        }
        
        .recommendations ul {
            list-style: none;
            padding-left: 0;
        }
        
        .recommendations li {
            padding: 10px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .recommendations li:before {
            content: "✓ ";
            color: var(--ok);
        }
        
        footer {
            text-align: center;
            padding: 20px;
            margin-top: 30px;
            color: #666;
        }
        
        @media (max-width: 768px) {
            header h1 { font-size: 1.8em; }
            .stat-number { font-size: 2em; }
        }
    </style>
</head>
<body>
    <div class="container">
HTMLHEADER
}
generate_html_content() {
    local hostname=$(hostname)
    local scan_date=$(date "+%d/%m/%Y à %H:%M:%S")
    local user=$(whoami)
    
    cat << HTMLCONTENT
        <header>
            <h1>🛡️ Rapport de Vulnérabilités</h1>
            <p>Scanner Local de Vulnérabilités v1.0</p>
            <div class="scan-info">
                <span>📅 $scan_date</span>
                <span>🖥️ $hostname</span>
                <span>👤 $user</span>
            </div>
        </header>

        <div class="dashboard">
            <div class="stat-card critical">
                <div class="stat-number">$CRITICAL_COUNT</div>
                <div>CRITICAL</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">$HIGH_COUNT</div>
                <div>HIGH</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">$MEDIUM_COUNT</div>
                <div>MEDIUM</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">$LOW_COUNT</div>
                <div>LOW</div>
            </div>
            <div class="stat-card info">
                <div class="stat-number">$INFO_COUNT</div>
                <div>INFO</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>🔐 Fichiers SUID/SGID</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <p>Les fichiers SUID/SGID peuvent permettre une escalade de privilèges s'ils sont mal configurés.</p>
                <div id="suid-findings">
                    <!-- Les résultats seront ajoutés ici -->
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>🔑 Configuration Sudoers</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <p>Analyse des permissions sudo et configurations dangereuses.</p>
                <div id="sudo-findings"></div>
            </div>
        </div>

        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>📁 Vulnérabilités PATH</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <p>Vérification des répertoires PATH pour des injections potentielles.</p>
                <div id="path-findings"></div>
            </div>
        </div>

        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>⏰ Timers Systemd</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <p>Analyse des timers systemd pour détecter des tâches planifiées suspectes.</p>
                <div id="timer-findings"></div>
            </div>
        </div>

        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>🐛 Vulnérabilités CVE</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <p>Comparaison des versions installées avec les vulnérabilités connues.</p>
                <div id="cve-findings"></div>
            </div>
        </div>

        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>🎯 Artefacts Red Team</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <p>Détection de traces d'activités malveillantes ou de tests d'intrusion.</p>
                <div id="redteam-findings"></div>
            </div>
        </div>

        <div class="section recommendations">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>📋 Recommandations</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content active">
                <ul>
                    <li>Mettre à jour régulièrement le système avec les patches de sécurité</li>
                    <li>Auditer les fichiers SUID/SGID et supprimer ceux non nécessaires</li>
                    <li>Restreindre les permissions sudo au minimum nécessaire</li>
                    <li>Éviter d'utiliser NOPASSWD dans la configuration sudo</li>
                    <li>Vérifier régulièrement les clés SSH autorisées</li>
                    <li>Monitorer les modifications des fichiers de configuration</li>
                    <li>Utiliser des outils de détection d'intrusion (AIDE, OSSEC)</li>
                    <li>Implémenter une politique de mots de passe robuste</li>
                </ul>
            </div>
        </div>

        <footer>
            <p>Généré par le Scanner Local de Vulnérabilités | Projet Cybersécurité Shell</p>
            <p>© 2025 - À des fins éducatives uniquement</p>
        </footer>
    </div>

    <script>
        function toggleSection(header) {
            const section = header.parentElement;
            const content = section.querySelector('.section-content');
            section.classList.toggle('open');
            content.classList.toggle('active');
        }

        // Ouvrir la première section par défaut
        document.addEventListener('DOMContentLoaded', function() {
            const firstSection = document.querySelector('.section');
            if (firstSection) {
                firstSection.classList.add('open');
                firstSection.querySelector('.section-content').classList.add('active');
            }
        });
    </script>
</body>
</html>
HTMLCONTENT
}

generate_html_report() {
    log_message "INFO" "Génération du rapport HTML..."
    
    {
        generate_html_header
        generate_html_content
    } > "$REPORT_FILE"
    
    if [[ -f "$REPORT_FILE" ]]; then
        log_message "OK" "Rapport HTML généré : $REPORT_FILE"
    else
        log_message "INFO" "Erreur lors de la génération du rapport"
    fi
}
generate_html_report