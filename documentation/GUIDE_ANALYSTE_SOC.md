# Guide de l'Analyste SOC - Documentation Complète

## Table des Matières

1. [Introduction](#introduction)
2. [Compétences d'un Analyste SOC](#compétences-analyste-soc)
3. [Outils Essentiels](#outils-essentiels)
4. [Analyse de Logs](#analyse-de-logs)
5. [Détection d'IoCs](#détection-diocs)
6. [Threat Hunting](#threat-hunting)
7. [Réponse aux Incidents](#réponse-aux-incidents)
8. [Framework MITRE ATT&CK](#framework-mitre-attck)
9. [Ressources Recommandées](#ressources-recommandées)

---

## Introduction

Ce guide accompagne le laboratoire SOC Analyst Lab et fournit les connaissances théoriques nécessaires pour devenir un analyste SOC efficace.

### Qu'est-ce qu'un SOC ?

Un **Security Operations Center (SOC)** est une équipe centralisée responsable de:
- La surveillance continue de la sécurité
- La détection et l'analyse des menaces
- La réponse aux incidents de sécurité
- L'amélioration continue de la posture de sécurité

### Niveaux d'Analystes SOC

| Niveau | Responsabilités |
|--------|-----------------|
| **Tier 1** | Surveillance des alertes, triage initial, escalade |
| **Tier 2** | Analyse approfondie, investigation, réponse aux incidents |
| **Tier 3** | Threat hunting, forensics, développement de détections |

---

## Compétences Analyste SOC

### Compétences Techniques

1. **Réseaux**
   - Modèle OSI et TCP/IP
   - Protocoles (HTTP, DNS, SMTP, SSH, etc.)
   - Analyse de paquets (Wireshark)

2. **Systèmes d'exploitation**
   - Administration Linux
   - Administration Windows
   - Logs système

3. **Sécurité**
   - Cryptographie de base
   - Vulnérabilités courantes (OWASP Top 10)
   - Malwares et techniques d'attaque

4. **Scripting**
   - Python (automatisation)
   - Bash (Linux)
   - PowerShell (Windows)

### Compétences Non-Techniques

- Communication écrite et orale
- Pensée analytique
- Gestion du stress
- Travail d'équipe
- Curiosité et apprentissage continu

---

## Outils Essentiels

### SIEM (Security Information and Event Management)

| Outil | Description |
|-------|-------------|
| Splunk | SIEM commercial leader du marché |
| Elastic Security | Solution open source (ELK Stack) |
| Microsoft Sentinel | SIEM cloud Azure |
| Wazuh | SIEM open source |
| QRadar | SIEM IBM |

### Analyse de Logs

```bash
# Commandes Linux utiles pour l'analyse de logs

# Rechercher des patterns
grep -i "failed password" /var/log/auth.log

# Compter les occurrences
grep -c "Failed" /var/log/auth.log

# Extraire les IPs uniques
grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' file.log | sort -u

# Analyser les logs en temps réel
tail -f /var/log/syslog | grep --line-buffered "error"

# Filtrer par date
awk '/Jan 15 14:/ {print}' /var/log/auth.log
```

### Analyse Réseau

| Outil | Usage |
|-------|-------|
| Wireshark | Analyse de paquets graphique |
| tcpdump | Capture de paquets en ligne de commande |
| Zeek (Bro) | Analyse de trafic réseau |
| NetworkMiner | Extraction d'artefacts réseau |

### Threat Intelligence

| Plateforme | Description |
|------------|-------------|
| VirusTotal | Analyse de fichiers et URLs |
| AbuseIPDB | Réputation d'adresses IP |
| URLhaus | Base de données d'URLs malveillantes |
| MalwareBazaar | Échantillons de malwares |
| MISP | Plateforme de partage d'IoCs |

---

## Analyse de Logs

### Types de Logs Importants

#### Logs Windows

| Event ID | Description |
|----------|-------------|
| 4624 | Connexion réussie |
| 4625 | Échec de connexion |
| 4672 | Privilèges spéciaux assignés |
| 4688 | Création de processus |
| 4698 | Tâche planifiée créée |
| 4720 | Compte utilisateur créé |
| 7045 | Service installé |

#### Logs Linux

| Fichier | Contenu |
|---------|---------|
| /var/log/auth.log | Authentification (Debian/Ubuntu) |
| /var/log/secure | Authentification (RHEL/CentOS) |
| /var/log/syslog | Logs système généraux |
| /var/log/apache2/access.log | Accès web Apache |
| /var/log/nginx/access.log | Accès web Nginx |

### Méthodologie d'Analyse

1. **Collecter** - Rassembler les logs pertinents
2. **Normaliser** - Mettre les données dans un format standard
3. **Corréler** - Lier les événements entre eux
4. **Analyser** - Identifier les anomalies
5. **Documenter** - Enregistrer les découvertes

---

## Détection d'IoCs

### Types d'Indicateurs de Compromission

| Type | Exemple |
|------|---------|
| IP | 185.220.101.42 |
| Domaine | malware-c2.evil.tk |
| URL | http://bad.site/payload.exe |
| Hash MD5 | d41d8cd98f00b204e9800998ecf8427e |
| Hash SHA256 | e3b0c44298fc1c149afbf4c8996fb924... |
| Email | attacker@malicious.com |
| CVE | CVE-2024-1234 |

### Cycle de Vie d'un IoC

```
                    ┌─────────────┐
                    │ Découverte  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ Validation  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ Enrichissement│
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ Distribution │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Détection  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Expiration │
                    └─────────────┘
```

### Vérification d'IoCs

```python
# Exemple: Vérifier une IP sur AbuseIPDB
import requests

def check_ip_abuseipdb(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    return response.json()
```

---

## Threat Hunting

### Définition

Le **Threat Hunting** est une approche proactive de recherche de menaces qui n'ont pas été détectées par les outils automatisés.

### Méthodologie

1. **Hypothèse** - Formuler une hypothèse basée sur les renseignements sur les menaces
2. **Collecte** - Rassembler les données nécessaires
3. **Analyse** - Rechercher des preuves supportant l'hypothèse
4. **Validation** - Confirmer ou infirmer l'hypothèse
5. **Amélioration** - Créer de nouvelles détections

### Exemples d'Hypothèses

```
Hypothèse: Un attaquant utilise des comptes compromis pour se déplacer latéralement.

Données à collecter:
- Logs d'authentification
- Logs de connexions réseau
- Logs de création de processus

Indicateurs à rechercher:
- Connexions depuis des emplacements inhabituels
- Accès à des systèmes non habituels pour un utilisateur
- Utilisation d'outils d'administration à distance
```

---

## Réponse aux Incidents

### Cycle de Réponse aux Incidents (NIST)

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│ Préparation │ → │ Détection & │ → │ Confinement │ → │ Éradication │
│             │   │   Analyse   │   │             │   │             │
└─────────────┘   └─────────────┘   └─────────────┘   └──────┬──────┘
                                                              │
┌─────────────┐   ┌─────────────┐                             │
│   Leçons    │ ← │ Récupération│ ←───────────────────────────┘
│  Apprises   │   │             │
└─────────────┘   └─────────────┘
```

### Template de Rapport d'Incident

1. **Résumé Exécutif**
   - Description brève de l'incident
   - Impact
   - Statut actuel

2. **Chronologie**
   - Quand l'incident a été détecté
   - Actions prises avec timestamps

3. **Analyse Technique**
   - Indicateurs de compromission
   - Systèmes affectés
   - Vecteur d'attaque

4. **Actions de Remédiation**
   - Confinement
   - Éradication
   - Récupération

5. **Recommandations**
   - Mesures préventives
   - Améliorations à apporter

---

## Framework MITRE ATT&CK

### Vue d'Ensemble

MITRE ATT&CK est une base de connaissances des tactiques et techniques adverses basée sur des observations du monde réel.

### Tactiques Principales

| Tactique | Description |
|----------|-------------|
| Reconnaissance | Collecte d'informations sur la cible |
| Resource Development | Création de ressources pour l'attaque |
| Initial Access | Obtention de l'accès initial |
| Execution | Exécution de code malveillant |
| Persistence | Maintien de l'accès |
| Privilege Escalation | Obtention de privilèges supérieurs |
| Defense Evasion | Évitement de la détection |
| Credential Access | Vol de credentials |
| Discovery | Exploration de l'environnement |
| Lateral Movement | Déplacement dans le réseau |
| Collection | Collecte de données |
| Exfiltration | Extraction de données |
| Impact | Dommages à l'environnement |

### Utilisation Pratique

```yaml
# Exemple de mapping d'une attaque
Incident: Brute Force SSH suivi d'escalade de privilèges

Techniques MITRE:
  - T1110.001: Brute Force - Password Guessing
  - T1078: Valid Accounts
  - T1548: Abuse Elevation Control Mechanism
  - T1021.004: Remote Services - SSH

Détections à implémenter:
  - Seuil d'échecs de connexion
  - Monitoring des commandes sudo/su
  - Alerte sur ajout aux groupes privilégiés
```

---

## Ressources Recommandées

### Formations en Français

| Ressource | URL |
|-----------|-----|
| Root-Me | https://www.root-me.org |
| Hack The Box | https://www.hackthebox.com |
| TryHackMe | https://tryhackme.com |
| OpenClassrooms | https://openclassrooms.com |

### Certifications Recommandées

| Certification | Organisation | Niveau |
|---------------|--------------|--------|
| CompTIA Security+ | CompTIA | Débutant |
| CySA+ | CompTIA | Intermédiaire |
| Blue Team Level 1 (BTL1) | Security Blue Team | Intermédiaire |
| GCIH | SANS/GIAC | Avancé |

### Livres Recommandés

1. "The Practice of Network Security Monitoring" - Richard Bejtlich
2. "Blue Team Handbook" - Don Murdoch
3. "Intelligence-Driven Incident Response" - Scott Roberts

### Chaînes YouTube (Français)

- Processus Thief
- Hafnium Security
- Le Blog du Hacker

---

## Conclusion

Ce guide fournit les bases pour démarrer en tant qu'analyste SOC. La clé du succès est la pratique continue et l'apprentissage constant. Utilisez ce laboratoire pour développer vos compétences et n'hésitez pas à expérimenter avec les différents outils fournis.

**Bon apprentissage ! **

---

*Document créé par Herdy Rostel Youlou*
*SOC Analyst Lab - 2026*
