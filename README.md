# SOC Analyst Lab - Laboratoire d'Analyse de Sécurité

![SOC](https://img.shields.io/badge/SOC-Analyst-blue)
![Python](https://img.shields.io/badge/Python-3.8+-green)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 📋 Description

Ce laboratoire personnel est conçu pour pratiquer et démontrer les compétences essentielles d'un **Analyste SOC**. Il comprend des outils d'analyse de logs, de détection d'incidents, de Threat Hunting et de réponse aux menaces.

---

## Instructions Rapides

### Installation

```bash
# 1. Cloner le repository
git clone https://github.com/RostelHerdyYoulou/soc-analyst-lab.git
cd soc-analyst-lab

# 2. (Optionnel) Créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt
```

### Utilisation en 30 secondes

```bash
# Analyser des logs et détecter des menaces
python3 scripts/log_parser.py --input logs/linux_syslog/auth.log --analyze

# Lancer une campagne de Threat Hunting
python3 scripts/threat_hunter.py --logs logs/

# Extraire les Indicateurs de Compromission (IoCs)
python3 scripts/ioc_detector.py --input logs/web_server/access.log

# Générer un rapport d'incident professionnel
python3 scripts/report_generator.py --demo
```

---

## Démonstration

### Détection de Brute Force SSH
![Log Analysis](screenshots/log_analysis.png)
*Détection automatique de 13 tentatives de brute force depuis une IP malveillante*

### Campagne de Threat Hunting
![Threat Hunting](screenshots/threat_hunting.png)
*Résultats de la chasse aux menaces basée sur MITRE ATT&CK*

### Rapport d'Incident Généré
![Incident Report](screenshots/incident_report.png)
*Rapport HTML professionnel avec chronologie et recommandations*

---

## 🛠️ Outils et Technologies

| Catégorie | Outils |
|-----------|--------|
| **Langage** | Python 3.8+ |
| **Parsing de logs** | Regex, python-evtx |
| **Règles de détection** | Sigma Rules (standard industrie) |
| **Framework de menaces** | MITRE ATT&CK |
| **Analyse de données** | Pandas, NumPy |
| **Formats de rapport** | HTML, Markdown, JSON |
| **Threat Intelligence** | YARA, listes d'IoCs |

### Compétences Blue Team Démontrées

-  **Log Analysis** - Parsing multi-format (Syslog, Windows Event, Apache, Firewall)
-  **Threat Detection** - Règles Sigma, corrélation d'événements
-  **Threat Hunting** - Chasse proactive basée sur hypothèses
-  **IoC Extraction** - IPs, domaines, hashes, URLs, CVEs
-  **Incident Response** - Documentation et reporting
-  **MITRE ATT&CK** - Mapping des techniques adverses

---

##  Fonctionnalités

### 1. Analyseur de Logs (`log_parser.py`)

Analyse automatique de logs multi-format avec détection de menaces.

**Formats supportés :**
- Linux Syslog / Auth.log
- Windows Security Events
- Apache / Nginx Access Logs
- Firewall (iptables, UFW)

**Détections :**
- ✅ Brute Force SSH/FTP
- ✅ Escalade de privilèges
- ✅ Connexions suspectes

```bash
python3 scripts/log_parser.py --input /var/log/auth.log --analyze --output report.json
```

### 2. Détecteur d'IoCs (`ioc_detector.py`)

Extraction automatique d'Indicateurs de Compromission.

**Types d'IoCs :**
- Adresses IP (avec exclusion des IPs privées)
- Domaines et URLs
- Hashes (MD5, SHA1, SHA256)
- Adresses email
- CVEs

```bash
python3 scripts/ioc_detector.py --input suspicious_file.log --ioc-file rules/malicious_iocs.txt
```

### 3. Threat Hunter (`threat_hunter.py`)

Chasse proactive aux menaces basée sur le framework MITRE ATT&CK.

**8 Hypothèses de chasse intégrées :**

| Hypothèse | Technique MITRE |
|-----------|-----------------|
| SSH Brute Force | T1110.001 |
| Web Application Attack (SQLi, XSS) | T1190 |
| Port Scanning | T1046 |
| Privilege Escalation | T1548 |
| Web Shell Detection | T1505.003 |
| DNS Exfiltration | T1048.003 |
| Lateral Movement | T1021 |
| Suspicious Account Activity | T1136 |

```bash
python3 scripts/threat_hunter.py --logs /var/log/ --hypothesis "Web Shell Detection"
```

### 4. Générateur de Rapports (`report_generator.py`)

Création de rapports d'incidents professionnels.

**Contenus du rapport :**
- Résumé exécutif
- Classification (sévérité, catégorie NIST)
- Indicateurs de compromission
- Chronologie détaillée
- Actions de réponse
- Recommandations

```bash
python3 scripts/report_generator.py --new INC-2026-001 "Intrusion détectée sur serveur web"
```

---

## 🏗️ Structure du Projet

```
soc-analyst-lab/
├── scripts/                    # Outils d'analyse Python
│   ├── log_parser.py           # Analyseur de logs multi-format
│   ├── ioc_detector.py         # Extracteur d'IoCs
│   ├── threat_hunter.py        # Outil de Threat Hunting
│   └── report_generator.py     # Générateur de rapports
├── logs/                       # Échantillons de logs pour tests
│   ├── linux_syslog/           # Logs d'authentification Linux
│   ├── firewall/               # Logs pare-feu (iptables)
│   └── web_server/             # Logs Apache/Nginx
├── rules/                      # Règles de détection
│   ├── sigma/                  # Règles Sigma
│   └── malicious_iocs.txt      # Liste d'IoCs malveillants
├── reports/                    # Rapports générés
├── screenshots/                # Captures d'écran de démonstration
├── documentation/              # Guide complet de l'analyste SOC
├── requirements.txt
├── LICENSE
└── README.md
```

---

##  Cas Pratiques Inclus

1. **Détection de Brute Force SSH** - Analyse de tentatives de connexion échouées
2. **Analyse d'attaques Web** - Détection SQLi, XSS, Path Traversal
3. **Chasse aux Web Shells** - Identification de backdoors (c99, r57, WSO)
4. **Investigation de mouvement latéral** - Corrélation d'événements réseau

---

##  Certifications Associées

- ✅ Certificate Of Participation Tec4Peace Bootcamp | UNDP | Give1Project | Open Society Foundations
- ✅ Analyste en Cybersécurité - FORCE-N
- ✅ Certified Phishing Prevention Specialist (CPPS)
- ✅ ISO/IEC 27001 Information Security Management

---

##  Ressources Recommandées

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [SANS Blue Team Wiki](https://wiki.sans.blue/)
- [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)

---

## 👤 Auteur

**Herdy Rostel Youlou**
- Analyste SOC
- 🔗 LinkedIn: [linkedin.com/in/herdy-rostel-youlou](https://www.linkedin.com/in/herdy-rostel-youlou/)
- 🐙 GitHub: [github.com/RostelHerdyYoulou](https://github.com/RostelHerdyYoulou)

---

## 📄 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

<p align="center">
  <i>Ce projet a été créé dans le cadre du renforcement des compétences pratiques en cybersécurité.</i>
</p>

<p align="center">
  <b>⭐ Si ce projet vous est utile, n'hésitez pas à lui donner une étoile !</b>
</p>
