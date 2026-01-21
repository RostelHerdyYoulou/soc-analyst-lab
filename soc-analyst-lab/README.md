# 🛡️ SOC Analyst Lab - Laboratoire d'Analyse de Sécurité

![SOC](https://img.shields.io/badge/SOC-Analyst%20Level%201-blue)
![Python](https://img.shields.io/badge/Python-3.8+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 📋 Description

Ce laboratoire personnel est conçu pour pratiquer et démontrer les compétences essentielles d'un **Analyste SOC de Niveau 1**. Il comprend des outils d'analyse de logs, de détection d'incidents, et de réponse aux menaces.

## 🎯 Objectifs du Projet

- Analyser des logs de sécurité (Windows Event Logs, Syslog, Firewall)
- Détecter des indicateurs de compromission (IoCs)
- Créer des règles de détection personnalisées
- Générer des rapports d'incidents
- Pratiquer le Threat Hunting

## 🏗️ Structure du Projet

```
soc-analyst-lab/
├── logs/                    # Échantillons de logs pour l'analyse
│   ├── windows_events/      # Logs Windows Event
│   ├── linux_syslog/        # Logs Syslog Linux
│   ├── firewall/            # Logs Firewall
│   └── web_server/          # Logs Apache/Nginx
├── scripts/                 # Scripts d'analyse Python
│   ├── log_parser.py        # Parseur de logs multi-format
│   ├── ioc_detector.py      # Détecteur d'IoCs
│   ├── threat_hunter.py     # Outil de Threat Hunting
│   └── report_generator.py  # Générateur de rapports
├── rules/                   # Règles de détection
│   ├── sigma/               # Règles Sigma
│   └── yara/                # Règles YARA
├── reports/                 # Rapports d'incidents générés
├── documentation/           # Documentation et procédures
└── README.md
```

## 🛠️ Outils et Technologies

- **Python 3.8+** - Scripts d'automatisation
- **Pandas** - Analyse de données
- **Regex** - Parsing de logs
- **YARA** - Détection de malwares
- **Sigma** - Règles de détection génériques

## 🚀 Installation

```bash
# Cloner le repository
git clone https://github.com/[votre-username]/soc-analyst-lab.git
cd soc-analyst-lab

# Créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
.\venv\Scripts\activate   # Windows

# Installer les dépendances
pip install -r requirements.txt
```

## 📊 Utilisation

### 1. Analyser des logs

```bash
python scripts/log_parser.py --input logs/windows_events/sample.evtx --output reports/
```

### 2. Détecter des IoCs

```bash
python scripts/ioc_detector.py --log logs/firewall/sample.log --ioc-file rules/iocs.txt
```

### 3. Threat Hunting

```bash
python scripts/threat_hunter.py --logs logs/ --rules rules/sigma/
```

### 4. Générer un rapport

```bash
python scripts/report_generator.py --incident INC-2024-001 --output reports/
```

## 📚 Cas Pratiques Inclus

1. **Détection de Brute Force SSH** - Analyse de tentatives de connexion échouées
2. **Analyse de Phishing** - Extraction d'IoCs depuis des emails suspects
3. **Détection de Mouvement Latéral** - Identification de comportements suspects
4. **Investigation de Malware** - Analyse basique d'artefacts

## 🎓 Certifications Associées

- ✅ Analyste en Cybersécurité - FORCE-N
- ✅ Certified Phishing Prevention Specialist (CPPS)
- ✅ ISO/IEC 27001 Information Security Management

## 📖 Ressources Recommandées

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [SANS Blue Team Wiki](https://wiki.sans.blue/)

## 👤 Auteur

**Herdy Rostel Youlou**
- Analyste SOC Niveau 1
- Certifié FORCE-N Sénégal
- 📧 Contact: [Votre email]
- 🔗 LinkedIn: [linkedin.com/in/herdy-rostel-youlou](https://www.linkedin.com/in/herdy-rostel-youlou/)

## 📄 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

*Ce projet a été créé dans le cadre du renforcement des compétences pratiques en cybersécurité.*
