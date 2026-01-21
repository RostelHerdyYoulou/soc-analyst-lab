#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC Analyst Lab - Outil de Threat Hunting
==========================================
Auteur: Herdy Rostel Youlou
Description: Outil proactif de recherche de menaces basé sur des hypothèses
             et des techniques MITRE ATT&CK
"""

import re
import json
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum


class ThreatCategory(Enum):
    """Catégories de menaces MITRE ATT&CK"""
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    COMMAND_AND_CONTROL = "Command and Control"
    IMPACT = "Impact"


@dataclass
class HuntingHypothesis:
    """Hypothèse de chasse aux menaces"""
    name: str
    description: str
    category: ThreatCategory
    mitre_techniques: List[str]
    detection_logic: str
    data_sources: List[str]
    severity: str = "MEDIUM"


@dataclass
class HuntingResult:
    """Résultat d'une recherche de menace"""
    hypothesis: str
    timestamp: datetime
    source_file: str
    evidence: str
    confidence: str
    context: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "hypothesis": self.hypothesis,
            "timestamp": self.timestamp.isoformat(),
            "source_file": self.source_file,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "context": self.context
        }


class ThreatHunter:
    """
    Moteur de Threat Hunting proactif
    
    Fonctionnalités:
    - Recherche basée sur des hypothèses
    - Corrélation d'événements
    - Détection d'anomalies comportementales
    - Mapping MITRE ATT&CK
    """
    
    # Hypothèses de chasse prédéfinies
    HUNTING_HYPOTHESES = [
        HuntingHypothesis(
            name="SSH Brute Force",
            description="Détection de tentatives de brute force SSH",
            category=ThreatCategory.CREDENTIAL_ACCESS,
            mitre_techniques=["T1110.001", "T1110.003"],
            detection_logic="Plus de 5 échecs de connexion SSH depuis la même IP en 5 minutes",
            data_sources=["auth.log", "syslog"],
            severity="HIGH"
        ),
        HuntingHypothesis(
            name="Web Application Attack",
            description="Détection de tentatives d'injection SQL/XSS",
            category=ThreatCategory.INITIAL_ACCESS,
            mitre_techniques=["T1190"],
            detection_logic="Patterns d'injection dans les requêtes HTTP",
            data_sources=["access.log", "error.log"],
            severity="HIGH"
        ),
        HuntingHypothesis(
            name="Suspicious Port Scanning",
            description="Détection de scan de ports",
            category=ThreatCategory.DISCOVERY,
            mitre_techniques=["T1046"],
            detection_logic="Connexions vers plusieurs ports depuis la même IP",
            data_sources=["firewall.log", "netflow"],
            severity="MEDIUM"
        ),
        HuntingHypothesis(
            name="Privilege Escalation Attempt",
            description="Tentative d'escalade de privilèges",
            category=ThreatCategory.PRIVILEGE_ESCALATION,
            mitre_techniques=["T1548", "T1068"],
            detection_logic="Échecs sudo/su ou modifications de groupes privilégiés",
            data_sources=["auth.log", "syslog"],
            severity="CRITICAL"
        ),
        HuntingHypothesis(
            name="Web Shell Detection",
            description="Recherche de web shells connus",
            category=ThreatCategory.PERSISTENCE,
            mitre_techniques=["T1505.003"],
            detection_logic="Accès à des fichiers PHP suspects (c99, r57, WSO)",
            data_sources=["access.log"],
            severity="CRITICAL"
        ),
        HuntingHypothesis(
            name="Data Exfiltration via DNS",
            description="Exfiltration de données via requêtes DNS",
            category=ThreatCategory.EXFILTRATION,
            mitre_techniques=["T1048.003"],
            detection_logic="Requêtes DNS avec sous-domaines anormalement longs",
            data_sources=["dns.log", "firewall.log"],
            severity="HIGH"
        ),
        HuntingHypothesis(
            name="Lateral Movement Detection",
            description="Détection de mouvement latéral",
            category=ThreatCategory.LATERAL_MOVEMENT,
            mitre_techniques=["T1021", "T1570"],
            detection_logic="Connexions SSH/RDP entre serveurs internes",
            data_sources=["auth.log", "firewall.log"],
            severity="HIGH"
        ),
        HuntingHypothesis(
            name="Suspicious Account Activity",
            description="Activité suspecte sur les comptes",
            category=ThreatCategory.PERSISTENCE,
            mitre_techniques=["T1136", "T1098"],
            detection_logic="Création de comptes ou modification de privilèges",
            data_sources=["auth.log", "windows_security"],
            severity="HIGH"
        ),
    ]
    
    # Patterns de détection
    DETECTION_PATTERNS = {
        "sql_injection": [
            r"(?:\'|\"|;|--|\|\||&&).*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND)",
            r"(?:1\s*=\s*1|1\s*OR\s*1|\'.*OR.*\')",
            r";\s*(?:DROP|DELETE|TRUNCATE)\s+(?:TABLE|DATABASE)",
        ],
        "xss_attack": [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on(?:error|load|click|mouseover)=",
            r"alert\s*\(",
        ],
        "path_traversal": [
            r"\.\.\/",
            r"\.\.\\",
            r"etc/passwd",
            r"etc/shadow",
            r"windows/system32",
        ],
        "webshell_access": [
            r"(?:c99|r57|WSO|b374k|alfa|shell)\.php",
            r"(?:cmd|command|exec|system|passthru)\.php",
        ],
        "brute_force_ssh": [
            r"Failed password for .* from",
            r"Invalid user .* from",
            r"authentication failure.*rhost=",
        ],
        "privilege_escalation": [
            r"sudo.*FAILED",
            r"su\[.*\].*FAILED",
            r"usermod.*-aG.*(?:sudo|wheel|admin)",
            r"useradd.*-G.*(?:sudo|wheel|admin)",
        ],
        "port_scan": [
            r"SRC=(\d+\.\d+\.\d+\.\d+).*DPT=",
        ],
    }
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: List[HuntingResult] = []
        self.stats = defaultdict(int)
    
    def hunt(self, log_directory: str, hypotheses: Optional[List[str]] = None) -> List[HuntingResult]:
        """
        Lance une campagne de Threat Hunting
        
        Args:
            log_directory: Répertoire contenant les logs
            hypotheses: Liste des noms d'hypothèses à tester (toutes si None)
        
        Returns:
            Liste des résultats de la chasse
        """
        log_dir = Path(log_directory)
        if not log_dir.exists():
            raise FileNotFoundError(f"Répertoire non trouvé: {log_directory}")
        
        # Sélectionner les hypothèses à tester
        active_hypotheses = []
        for h in self.HUNTING_HYPOTHESES:
            if hypotheses is None or h.name in hypotheses:
                active_hypotheses.append(h)
        
        print(f"\n[*] Démarrage de la campagne de Threat Hunting")
        print(f"[*] Hypothèses actives: {len(active_hypotheses)}")
        print(f"[*] Répertoire de logs: {log_dir}")
        
        # Collecter tous les fichiers de logs
        log_files = list(log_dir.rglob("*"))
        log_files = [f for f in log_files if f.is_file() and not f.name.startswith('.')]
        
        print(f"[*] Fichiers de logs trouvés: {len(log_files)}")
        
        # Exécuter chaque hypothèse
        for hypothesis in active_hypotheses:
            print(f"\n[+] Test de l'hypothèse: {hypothesis.name}")
            print(f"    Catégorie: {hypothesis.category.value}")
            print(f"    MITRE: {', '.join(hypothesis.mitre_techniques)}")
            
            results = self._test_hypothesis(hypothesis, log_files)
            self.results.extend(results)
            
            if results:
                print(f"    ⚠️  {len(results)} résultat(s) trouvé(s)!")
                self.stats[hypothesis.name] = len(results)
            else:
                print(f"    ✓ Aucune menace détectée")
        
        return self.results
    
    def _test_hypothesis(self, hypothesis: HuntingHypothesis, 
                         log_files: List[Path]) -> List[HuntingResult]:
        """Teste une hypothèse spécifique"""
        results = []
        
        if hypothesis.name == "SSH Brute Force":
            results = self._hunt_ssh_brute_force(log_files)
        elif hypothesis.name == "Web Application Attack":
            results = self._hunt_web_attacks(log_files)
        elif hypothesis.name == "Suspicious Port Scanning":
            results = self._hunt_port_scanning(log_files)
        elif hypothesis.name == "Privilege Escalation Attempt":
            results = self._hunt_privilege_escalation(log_files)
        elif hypothesis.name == "Web Shell Detection":
            results = self._hunt_webshells(log_files)
        elif hypothesis.name == "Suspicious Account Activity":
            results = self._hunt_account_activity(log_files)
        
        # Ajouter le nom de l'hypothèse aux résultats
        for r in results:
            r.hypothesis = hypothesis.name
        
        return results
    
    def _hunt_ssh_brute_force(self, log_files: List[Path]) -> List[HuntingResult]:
        """Chasse aux tentatives de brute force SSH"""
        results = []
        failed_attempts = defaultdict(list)
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        for pattern in self.DETECTION_PATTERNS["brute_force_ssh"]:
                            if re.search(pattern, line, re.IGNORECASE):
                                # Extraire l'IP
                                ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                                if ip_match:
                                    ip = ip_match.group(1)
                                    failed_attempts[ip].append({
                                        "file": str(log_file),
                                        "line": line.strip()
                                    })
            except Exception as e:
                if self.verbose:
                    print(f"    [!] Erreur lecture {log_file}: {e}")
        
        # Analyser les patterns de brute force
        for ip, attempts in failed_attempts.items():
            if len(attempts) >= 5:  # Seuil de détection
                results.append(HuntingResult(
                    hypothesis="SSH Brute Force",
                    timestamp=datetime.now(),
                    source_file=attempts[0]["file"],
                    evidence=f"IP {ip}: {len(attempts)} tentatives échouées détectées",
                    confidence="HIGH" if len(attempts) >= 10 else "MEDIUM",
                    context={
                        "source_ip": ip,
                        "attempt_count": len(attempts),
                        "sample_logs": [a["line"][:200] for a in attempts[:3]]
                    }
                ))
        
        return results
    
    def _hunt_web_attacks(self, log_files: List[Path]) -> List[HuntingResult]:
        """Chasse aux attaques web (SQLi, XSS, etc.)"""
        results = []
        
        attack_types = {
            "sql_injection": "Injection SQL",
            "xss_attack": "Cross-Site Scripting (XSS)",
            "path_traversal": "Path Traversal"
        }
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        for attack_type, attack_name in attack_types.items():
                            for pattern in self.DETECTION_PATTERNS.get(attack_type, []):
                                if re.search(pattern, line, re.IGNORECASE):
                                    # Extraire l'IP source
                                    ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
                                    source_ip = ip_match.group(1) if ip_match else "Unknown"
                                    
                                    results.append(HuntingResult(
                                        hypothesis="Web Application Attack",
                                        timestamp=datetime.now(),
                                        source_file=str(log_file),
                                        evidence=f"{attack_name} détecté depuis {source_ip}",
                                        confidence="HIGH",
                                        context={
                                            "attack_type": attack_type,
                                            "source_ip": source_ip,
                                            "line_number": line_num,
                                            "payload": line.strip()[:300]
                                        }
                                    ))
                                    break  # Un seul match par ligne
            except Exception as e:
                if self.verbose:
                    print(f"    [!] Erreur lecture {log_file}: {e}")
        
        return results
    
    def _hunt_port_scanning(self, log_files: List[Path]) -> List[HuntingResult]:
        """Détection de scan de ports"""
        results = []
        port_connections = defaultdict(set)
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        # Chercher les connexions bloquées avec info de port
                        match = re.search(
                            r'SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)', 
                            line
                        )
                        if match and ('DROP' in line or 'BLOCK' in line or 'DENY' in line):
                            ip = match.group(1)
                            port = match.group(2)
                            port_connections[ip].add(port)
            except Exception as e:
                if self.verbose:
                    print(f"    [!] Erreur lecture {log_file}: {e}")
        
        # Détecter les IPs scannant plusieurs ports
        for ip, ports in port_connections.items():
            if len(ports) >= 5:  # Seuil: 5 ports différents
                results.append(HuntingResult(
                    hypothesis="Suspicious Port Scanning",
                    timestamp=datetime.now(),
                    source_file="firewall logs",
                    evidence=f"IP {ip} a scanné {len(ports)} ports différents",
                    confidence="HIGH" if len(ports) >= 10 else "MEDIUM",
                    context={
                        "source_ip": ip,
                        "ports_scanned": sorted(list(ports))[:20],
                        "port_count": len(ports)
                    }
                ))
        
        return results
    
    def _hunt_privilege_escalation(self, log_files: List[Path]) -> List[HuntingResult]:
        """Chasse aux tentatives d'escalade de privilèges"""
        results = []
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        for pattern in self.DETECTION_PATTERNS["privilege_escalation"]:
                            if re.search(pattern, line, re.IGNORECASE):
                                # Extraire l'utilisateur
                                user_match = re.search(r'(?:user[=:\s]+|by\s+)(\w+)', line, re.IGNORECASE)
                                user = user_match.group(1) if user_match else "Unknown"
                                
                                results.append(HuntingResult(
                                    hypothesis="Privilege Escalation Attempt",
                                    timestamp=datetime.now(),
                                    source_file=str(log_file),
                                    evidence=f"Tentative d'escalade de privilèges par {user}",
                                    confidence="HIGH",
                                    context={
                                        "user": user,
                                        "raw_log": line.strip()[:300]
                                    }
                                ))
                                break
            except Exception as e:
                if self.verbose:
                    print(f"    [!] Erreur lecture {log_file}: {e}")
        
        return results
    
    def _hunt_webshells(self, log_files: List[Path]) -> List[HuntingResult]:
        """Recherche de web shells"""
        results = []
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        for pattern in self.DETECTION_PATTERNS["webshell_access"]:
                            match = re.search(pattern, line, re.IGNORECASE)
                            if match:
                                # Extraire l'IP
                                ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
                                source_ip = ip_match.group(1) if ip_match else "Unknown"
                                
                                results.append(HuntingResult(
                                    hypothesis="Web Shell Detection",
                                    timestamp=datetime.now(),
                                    source_file=str(log_file),
                                    evidence=f"Accès web shell suspect depuis {source_ip}: {match.group(0)}",
                                    confidence="CRITICAL",
                                    context={
                                        "source_ip": source_ip,
                                        "webshell": match.group(0),
                                        "raw_log": line.strip()[:300]
                                    }
                                ))
                                break
            except Exception as e:
                if self.verbose:
                    print(f"    [!] Erreur lecture {log_file}: {e}")
        
        return results
    
    def _hunt_account_activity(self, log_files: List[Path]) -> List[HuntingResult]:
        """Détection d'activité suspecte sur les comptes"""
        results = []
        
        account_patterns = [
            (r'useradd\[.*\].*new user.*name=(\w+)', "Création de compte"),
            (r'usermod\[.*\].*add.*to group.*sudo', "Ajout au groupe sudo"),
            (r'passwd\[.*\].*password changed for (\w+)', "Changement de mot de passe"),
        ]
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        for pattern, description in account_patterns:
                            match = re.search(pattern, line, re.IGNORECASE)
                            if match:
                                results.append(HuntingResult(
                                    hypothesis="Suspicious Account Activity",
                                    timestamp=datetime.now(),
                                    source_file=str(log_file),
                                    evidence=f"{description}: {match.group(0)[:100]}",
                                    confidence="MEDIUM",
                                    context={
                                        "activity_type": description,
                                        "raw_log": line.strip()[:300]
                                    }
                                ))
                                break
            except Exception as e:
                if self.verbose:
                    print(f"    [!] Erreur lecture {log_file}: {e}")
        
        return results
    
    def get_results(self) -> List[Dict]:
        """Retourne tous les résultats de la chasse"""
        return [r.to_dict() for r in self.results]
    
    def get_summary(self) -> Dict:
        """Génère un résumé de la campagne de chasse"""
        summary = {
            "total_findings": len(self.results),
            "by_hypothesis": dict(self.stats),
            "by_confidence": defaultdict(int),
            "critical_findings": []
        }
        
        for result in self.results:
            summary["by_confidence"][result.confidence] += 1
            if result.confidence in ["CRITICAL", "HIGH"]:
                summary["critical_findings"].append({
                    "hypothesis": result.hypothesis,
                    "evidence": result.evidence[:100]
                })
        
        summary["by_confidence"] = dict(summary["by_confidence"])
        return summary
    
    def export_results(self, filepath: str) -> None:
        """Exporte les résultats au format JSON"""
        output = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_findings": len(self.results)
            },
            "summary": self.get_summary(),
            "findings": self.get_results()
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)


def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description='SOC Analyst Lab - Outil de Threat Hunting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python threat_hunter.py --logs /var/log/
  python threat_hunter.py --logs logs/ --hypothesis "SSH Brute Force"
  python threat_hunter.py --logs logs/ --output reports/hunting_results.json
  python threat_hunter.py --list-hypotheses
        """
    )
    
    parser.add_argument('-l', '--logs', help='Répertoire contenant les logs')
    parser.add_argument('-o', '--output', help='Fichier de sortie JSON')
    parser.add_argument('--hypothesis', action='append', 
                       help='Hypothèse spécifique à tester (peut être répété)')
    parser.add_argument('--list-hypotheses', action='store_true',
                       help='Lister toutes les hypothèses disponibles')
    parser.add_argument('-v', '--verbose', action='store_true', help='Mode verbeux')
    
    args = parser.parse_args()
    
    print(f"\n{'='*60}")
    print("  SOC Analyst Lab - Threat Hunting")
    print(f"{'='*60}")
    
    if args.list_hypotheses:
        print("\n[*] Hypothèses de chasse disponibles:\n")
        for h in ThreatHunter.HUNTING_HYPOTHESES:
            print(f"  📌 {h.name}")
            print(f"     Catégorie: {h.category.value}")
            print(f"     Sévérité: {h.severity}")
            print(f"     MITRE: {', '.join(h.mitre_techniques)}")
            print(f"     Description: {h.description}")
            print()
        return
    
    if not args.logs:
        parser.print_help()
        return
    
    hunter = ThreatHunter(verbose=args.verbose)
    
    try:
        results = hunter.hunt(args.logs, args.hypothesis)
        
        # Afficher le résumé
        summary = hunter.get_summary()
        print(f"\n{'='*60}")
        print("  RÉSUMÉ DE LA CAMPAGNE")
        print(f"{'='*60}")
        print(f"\n[+] Total de découvertes: {summary['total_findings']}")
        print(f"\n[+] Par niveau de confiance:")
        for conf, count in summary['by_confidence'].items():
            print(f"    - {conf}: {count}")
        
        if summary['critical_findings']:
            print(f"\n[!] Découvertes critiques/hautes:")
            for finding in summary['critical_findings'][:5]:
                print(f"    ⚠️  {finding['hypothesis']}: {finding['evidence']}")
        
        # Export si demandé
        if args.output:
            hunter.export_results(args.output)
            print(f"\n[+] Résultats exportés vers: {args.output}")
        
    except FileNotFoundError as e:
        print(f"\n[!] Erreur: {e}")
    
    print(f"\n{'='*60}")
    print("  Campagne terminée")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
