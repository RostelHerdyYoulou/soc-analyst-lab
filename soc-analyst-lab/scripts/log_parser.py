#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC Analyst Lab - Parseur de Logs Multi-Format
===============================================
Auteur: Herdy Rostel Youlou
Description: Outil d'analyse et de parsing de logs de sécurité
             supportant plusieurs formats (Windows, Syslog, Firewall, Web)
"""

import re
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Generator
from dataclasses import dataclass
from enum import Enum
import argparse


class LogType(Enum):
    """Types de logs supportés"""
    WINDOWS_SECURITY = "windows_security"
    SYSLOG = "syslog"
    FIREWALL = "firewall"
    APACHE = "apache"
    NGINX = "nginx"
    AUTH = "auth"
    UNKNOWN = "unknown"


@dataclass
class ParsedLog:
    """Structure d'un log parsé"""
    timestamp: datetime
    log_type: LogType
    source_ip: Optional[str]
    destination_ip: Optional[str]
    user: Optional[str]
    action: str
    severity: str
    raw_message: str
    additional_fields: Dict


class LogParser:
    """
    Parseur de logs multi-format pour analyse SOC
    
    Supporte:
    - Windows Security Events (format texte exporté)
    - Syslog (RFC 3164 et RFC 5424)
    - Logs Firewall (iptables, pf)
    - Logs Apache/Nginx
    """
    
    # Patterns de détection de format
    PATTERNS = {
        LogType.SYSLOG: re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.*)'
        ),
        LogType.APACHE: re.compile(
            r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+'
            r'(?P<user>\S+)\s+'
            r'\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<method>\w+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
            r'(?P<status>\d{3})\s+'
            r'(?P<size>\d+|-)'
        ),
        LogType.FIREWALL: re.compile(
            r'(?P<timestamp>\S+\s+\S+)\s+.*?'
            r'(?P<action>ACCEPT|DROP|REJECT|DENY)\s+.*?'
            r'SRC=(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?'
            r'DST=(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?'
            r'PROTO=(?P<proto>\w+)'
        ),
        LogType.AUTH: re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.*(?:authentication|password|login|session|sudo|su).*)',
            re.IGNORECASE
        ),
        LogType.WINDOWS_SECURITY: re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?'
            r'EventID[=:\s]+(?P<event_id>\d+).*?'
            r'(?:User[=:\s]+(?P<user>\S+))?',
            re.IGNORECASE
        )
    }
    
    # Event IDs Windows importants pour la sécurité
    WINDOWS_SECURITY_EVENTS = {
        4624: ("Connexion réussie", "INFO"),
        4625: ("Échec de connexion", "WARNING"),
        4634: ("Déconnexion", "INFO"),
        4648: ("Connexion avec credentials explicites", "WARNING"),
        4672: ("Privilèges spéciaux assignés", "WARNING"),
        4688: ("Nouveau processus créé", "INFO"),
        4697: ("Service installé", "WARNING"),
        4698: ("Tâche planifiée créée", "WARNING"),
        4720: ("Compte utilisateur créé", "WARNING"),
        4722: ("Compte utilisateur activé", "INFO"),
        4723: ("Tentative de changement de mot de passe", "WARNING"),
        4724: ("Réinitialisation de mot de passe", "WARNING"),
        4725: ("Compte utilisateur désactivé", "INFO"),
        4726: ("Compte utilisateur supprimé", "WARNING"),
        4728: ("Membre ajouté à un groupe de sécurité global", "WARNING"),
        4732: ("Membre ajouté à un groupe local", "WARNING"),
        4756: ("Membre ajouté à un groupe universel", "WARNING"),
        4768: ("Ticket Kerberos TGT demandé", "INFO"),
        4769: ("Ticket de service Kerberos demandé", "INFO"),
        4771: ("Échec de pré-authentification Kerberos", "WARNING"),
        4776: ("Validation des credentials (NTLM)", "INFO"),
        5140: ("Accès à un partage réseau", "INFO"),
        5145: ("Objet de partage réseau vérifié", "INFO"),
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.stats = {
            "total_lines": 0,
            "parsed_lines": 0,
            "errors": 0,
            "by_type": {}
        }
    
    def detect_log_type(self, line: str) -> LogType:
        """Détecte automatiquement le type de log"""
        # Vérifier d'abord les logs d'authentification
        if self.PATTERNS[LogType.AUTH].search(line):
            return LogType.AUTH
        
        for log_type, pattern in self.PATTERNS.items():
            if pattern.search(line):
                return log_type
        
        return LogType.UNKNOWN
    
    def parse_line(self, line: str, force_type: Optional[LogType] = None) -> Optional[ParsedLog]:
        """Parse une ligne de log"""
        self.stats["total_lines"] += 1
        line = line.strip()
        
        if not line:
            return None
        
        log_type = force_type or self.detect_log_type(line)
        
        try:
            if log_type == LogType.SYSLOG or log_type == LogType.AUTH:
                return self._parse_syslog(line, log_type)
            elif log_type == LogType.APACHE:
                return self._parse_apache(line)
            elif log_type == LogType.FIREWALL:
                return self._parse_firewall(line)
            elif log_type == LogType.WINDOWS_SECURITY:
                return self._parse_windows(line)
            else:
                return self._parse_generic(line)
        except Exception as e:
            self.stats["errors"] += 1
            if self.verbose:
                print(f"[!] Erreur parsing: {e}")
            return None
    
    def _parse_syslog(self, line: str, log_type: LogType) -> Optional[ParsedLog]:
        """Parse un log au format Syslog"""
        match = self.PATTERNS[LogType.SYSLOG].search(line)
        if not match:
            return None
        
        self.stats["parsed_lines"] += 1
        self.stats["by_type"][log_type.value] = self.stats["by_type"].get(log_type.value, 0) + 1
        
        # Extraction d'IP si présente dans le message
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', match.group('message'))
        source_ip = ip_match.group(1) if ip_match else None
        
        # Extraction d'utilisateur
        user_match = re.search(r'(?:user[=:\s]+|for\s+)(\w+)', match.group('message'), re.IGNORECASE)
        user = user_match.group(1) if user_match else None
        
        # Déterminer la sévérité
        severity = self._determine_severity(match.group('message'))
        
        return ParsedLog(
            timestamp=self._parse_syslog_timestamp(match.group('timestamp')),
            log_type=log_type,
            source_ip=source_ip,
            destination_ip=None,
            user=user,
            action=match.group('process'),
            severity=severity,
            raw_message=line,
            additional_fields={
                "hostname": match.group('hostname'),
                "pid": match.group('pid'),
                "message": match.group('message')
            }
        )
    
    def _parse_apache(self, line: str) -> Optional[ParsedLog]:
        """Parse un log Apache"""
        match = self.PATTERNS[LogType.APACHE].search(line)
        if not match:
            return None
        
        self.stats["parsed_lines"] += 1
        self.stats["by_type"]["apache"] = self.stats["by_type"].get("apache", 0) + 1
        
        status_code = int(match.group('status'))
        severity = "ERROR" if status_code >= 500 else "WARNING" if status_code >= 400 else "INFO"
        
        return ParsedLog(
            timestamp=self._parse_apache_timestamp(match.group('timestamp')),
            log_type=LogType.APACHE,
            source_ip=match.group('ip'),
            destination_ip=None,
            user=match.group('user') if match.group('user') != '-' else None,
            action=f"{match.group('method')} {match.group('uri')}",
            severity=severity,
            raw_message=line,
            additional_fields={
                "method": match.group('method'),
                "uri": match.group('uri'),
                "protocol": match.group('protocol'),
                "status": status_code,
                "size": match.group('size')
            }
        )
    
    def _parse_firewall(self, line: str) -> Optional[ParsedLog]:
        """Parse un log Firewall (iptables)"""
        match = self.PATTERNS[LogType.FIREWALL].search(line)
        if not match:
            return None
        
        self.stats["parsed_lines"] += 1
        self.stats["by_type"]["firewall"] = self.stats["by_type"].get("firewall", 0) + 1
        
        action = match.group('action')
        severity = "WARNING" if action in ["DROP", "REJECT", "DENY"] else "INFO"
        
        # Extraire les ports si présents
        sport_match = re.search(r'SPT=(\d+)', line)
        dport_match = re.search(r'DPT=(\d+)', line)
        
        return ParsedLog(
            timestamp=datetime.now(),  # Le format exact dépend de la config
            log_type=LogType.FIREWALL,
            source_ip=match.group('src_ip'),
            destination_ip=match.group('dst_ip'),
            user=None,
            action=action,
            severity=severity,
            raw_message=line,
            additional_fields={
                "protocol": match.group('proto'),
                "source_port": sport_match.group(1) if sport_match else None,
                "dest_port": dport_match.group(1) if dport_match else None
            }
        )
    
    def _parse_windows(self, line: str) -> Optional[ParsedLog]:
        """Parse un log Windows Security Event"""
        match = self.PATTERNS[LogType.WINDOWS_SECURITY].search(line)
        if not match:
            return None
        
        self.stats["parsed_lines"] += 1
        self.stats["by_type"]["windows"] = self.stats["by_type"].get("windows", 0) + 1
        
        event_id = int(match.group('event_id'))
        event_info = self.WINDOWS_SECURITY_EVENTS.get(
            event_id, 
            (f"Event ID {event_id}", "INFO")
        )
        
        # Extraire l'IP si présente
        ip_match = re.search(r'(?:Source\s+)?(?:Network\s+)?Address[=:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        
        return ParsedLog(
            timestamp=datetime.strptime(match.group('timestamp'), '%Y-%m-%d %H:%M:%S'),
            log_type=LogType.WINDOWS_SECURITY,
            source_ip=ip_match.group(1) if ip_match else None,
            destination_ip=None,
            user=match.group('user') if match.group('user') else None,
            action=event_info[0],
            severity=event_info[1],
            raw_message=line,
            additional_fields={
                "event_id": event_id,
                "event_description": event_info[0]
            }
        )
    
    def _parse_generic(self, line: str) -> ParsedLog:
        """Parse générique pour les logs non reconnus"""
        self.stats["parsed_lines"] += 1
        self.stats["by_type"]["unknown"] = self.stats["by_type"].get("unknown", 0) + 1
        
        # Tenter d'extraire une IP
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        
        return ParsedLog(
            timestamp=datetime.now(),
            log_type=LogType.UNKNOWN,
            source_ip=ip_match.group(1) if ip_match else None,
            destination_ip=None,
            user=None,
            action="UNKNOWN",
            severity="INFO",
            raw_message=line,
            additional_fields={}
        )
    
    def _determine_severity(self, message: str) -> str:
        """Détermine la sévérité basée sur le contenu du message"""
        message_lower = message.lower()
        
        critical_keywords = ['critical', 'emergency', 'alert', 'fatal']
        error_keywords = ['error', 'fail', 'failed', 'denied', 'invalid', 'illegal']
        warning_keywords = ['warning', 'warn', 'timeout', 'retry', 'refused']
        
        if any(kw in message_lower for kw in critical_keywords):
            return "CRITICAL"
        elif any(kw in message_lower for kw in error_keywords):
            return "ERROR"
        elif any(kw in message_lower for kw in warning_keywords):
            return "WARNING"
        return "INFO"
    
    def _parse_syslog_timestamp(self, ts_str: str) -> datetime:
        """Parse un timestamp syslog"""
        current_year = datetime.now().year
        try:
            return datetime.strptime(f"{current_year} {ts_str}", '%Y %b %d %H:%M:%S')
        except ValueError:
            return datetime.now()
    
    def _parse_apache_timestamp(self, ts_str: str) -> datetime:
        """Parse un timestamp Apache"""
        try:
            return datetime.strptime(ts_str.split()[0], '%d/%b/%Y:%H:%M:%S')
        except ValueError:
            return datetime.now()
    
    def parse_file(self, filepath: str, force_type: Optional[LogType] = None) -> Generator[ParsedLog, None, None]:
        """Parse un fichier de logs complet"""
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"Fichier non trouvé: {filepath}")
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed = self.parse_line(line, force_type)
                if parsed:
                    yield parsed
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques de parsing"""
        return {
            **self.stats,
            "success_rate": f"{(self.stats['parsed_lines'] / max(self.stats['total_lines'], 1)) * 100:.2f}%"
        }


class LogAnalyzer:
    """
    Analyseur de logs pour détection d'anomalies et menaces
    """
    
    def __init__(self, parser: LogParser):
        self.parser = parser
        self.alerts = []
    
    def detect_brute_force(self, logs: List[ParsedLog], threshold: int = 5, 
                          time_window_minutes: int = 5) -> List[Dict]:
        """
        Détecte les tentatives de brute force
        
        Args:
            logs: Liste de logs parsés
            threshold: Nombre d'échecs avant alerte
            time_window_minutes: Fenêtre de temps en minutes
        """
        failed_logins = {}
        alerts = []
        
        for log in logs:
            # Chercher les échecs d'authentification
            is_failed = any(kw in log.raw_message.lower() 
                          for kw in ['failed', 'failure', 'invalid', 'denied', '4625'])
            
            if is_failed and log.source_ip:
                key = log.source_ip
                if key not in failed_logins:
                    failed_logins[key] = []
                failed_logins[key].append(log.timestamp)
        
        # Analyser les patterns
        for ip, timestamps in failed_logins.items():
            timestamps.sort()
            
            # Fenêtre glissante
            for i in range(len(timestamps) - threshold + 1):
                window_start = timestamps[i]
                window_end = timestamps[i + threshold - 1]
                
                if (window_end - window_start).total_seconds() <= time_window_minutes * 60:
                    alerts.append({
                        "type": "BRUTE_FORCE",
                        "severity": "HIGH",
                        "source_ip": ip,
                        "attempts": threshold,
                        "time_window": f"{time_window_minutes} minutes",
                        "first_attempt": window_start.isoformat(),
                        "last_attempt": window_end.isoformat(),
                        "description": f"Détection de {threshold} tentatives échouées depuis {ip} en {time_window_minutes} minutes"
                    })
                    break  # Une alerte par IP suffit
        
        self.alerts.extend(alerts)
        return alerts
    
    def detect_suspicious_ports(self, logs: List[ParsedLog]) -> List[Dict]:
        """Détecte les connexions vers des ports suspects"""
        suspicious_ports = {
            22: "SSH",
            23: "Telnet",
            3389: "RDP",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            4444: "Metasploit default",
            5555: "Android Debug",
            8080: "HTTP Alt (souvent proxy)",
            9001: "Tor",
        }
        
        alerts = []
        
        for log in logs:
            if log.log_type == LogType.FIREWALL:
                dest_port = log.additional_fields.get('dest_port')
                if dest_port and int(dest_port) in suspicious_ports:
                    alerts.append({
                        "type": "SUSPICIOUS_PORT",
                        "severity": "MEDIUM",
                        "source_ip": log.source_ip,
                        "destination_ip": log.destination_ip,
                        "port": dest_port,
                        "service": suspicious_ports[int(dest_port)],
                        "timestamp": log.timestamp.isoformat(),
                        "description": f"Connexion détectée vers port {dest_port} ({suspicious_ports[int(dest_port)]})"
                    })
        
        self.alerts.extend(alerts)
        return alerts
    
    def detect_privilege_escalation(self, logs: List[ParsedLog]) -> List[Dict]:
        """Détecte les tentatives d'escalade de privilèges"""
        escalation_indicators = [
            (r'sudo.*FAILED', "Échec sudo"),
            (r'su\[.*\].*FAILED', "Échec su"),
            (r'4672', "Privilèges spéciaux Windows"),
            (r'4728|4732|4756', "Ajout à un groupe privilégié"),
            (r'passwd.*change', "Changement de mot de passe"),
            (r'usermod.*-aG.*sudo', "Ajout au groupe sudo"),
        ]
        
        alerts = []
        
        for log in logs:
            for pattern, description in escalation_indicators:
                if re.search(pattern, log.raw_message, re.IGNORECASE):
                    alerts.append({
                        "type": "PRIVILEGE_ESCALATION",
                        "severity": "HIGH",
                        "source_ip": log.source_ip,
                        "user": log.user,
                        "indicator": description,
                        "timestamp": log.timestamp.isoformat(),
                        "raw_log": log.raw_message[:200],
                        "description": f"Indicateur d'escalade de privilèges: {description}"
                    })
        
        self.alerts.extend(alerts)
        return alerts
    
    def get_all_alerts(self) -> List[Dict]:
        """Retourne toutes les alertes détectées"""
        return self.alerts
    
    def get_alert_summary(self) -> Dict:
        """Résumé des alertes"""
        summary = {
            "total": len(self.alerts),
            "by_type": {},
            "by_severity": {}
        }
        
        for alert in self.alerts:
            alert_type = alert.get('type', 'UNKNOWN')
            severity = alert.get('severity', 'UNKNOWN')
            
            summary["by_type"][alert_type] = summary["by_type"].get(alert_type, 0) + 1
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
        
        return summary


def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description='SOC Analyst Lab - Parseur de Logs Multi-Format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python log_parser.py --input /var/log/auth.log
  python log_parser.py --input logs/sample.log --type syslog --analyze
  python log_parser.py --input logs/ --recursive --output reports/analysis.json
        """
    )
    
    parser.add_argument('-i', '--input', required=True, help='Fichier ou dossier de logs à analyser')
    parser.add_argument('-o', '--output', help='Fichier de sortie (JSON)')
    parser.add_argument('-t', '--type', choices=['syslog', 'apache', 'firewall', 'windows', 'auth', 'auto'],
                       default='auto', help='Type de log (défaut: auto)')
    parser.add_argument('-a', '--analyze', action='store_true', help='Activer l\'analyse de sécurité')
    parser.add_argument('-v', '--verbose', action='store_true', help='Mode verbeux')
    parser.add_argument('--recursive', action='store_true', help='Traiter récursivement les dossiers')
    
    args = parser.parse_args()
    
    # Mapping type
    type_mapping = {
        'syslog': LogType.SYSLOG,
        'apache': LogType.APACHE,
        'firewall': LogType.FIREWALL,
        'windows': LogType.WINDOWS_SECURITY,
        'auth': LogType.AUTH,
        'auto': None
    }
    
    log_parser = LogParser(verbose=args.verbose)
    parsed_logs = []
    
    input_path = Path(args.input)
    
    print(f"\n{'='*60}")
    print("  SOC Analyst Lab - Analyse de Logs")
    print(f"{'='*60}\n")
    
    if input_path.is_file():
        print(f"[*] Analyse du fichier: {input_path}")
        for log in log_parser.parse_file(str(input_path), type_mapping[args.type]):
            parsed_logs.append(log)
    elif input_path.is_dir():
        pattern = '**/*' if args.recursive else '*'
        for file_path in input_path.glob(pattern):
            if file_path.is_file() and not file_path.name.startswith('.'):
                print(f"[*] Analyse: {file_path}")
                for log in log_parser.parse_file(str(file_path), type_mapping[args.type]):
                    parsed_logs.append(log)
    else:
        print(f"[!] Chemin invalide: {input_path}")
        return
    
    # Afficher les statistiques
    stats = log_parser.get_statistics()
    print(f"\n[+] Statistiques de parsing:")
    print(f"    - Lignes totales: {stats['total_lines']}")
    print(f"    - Lignes parsées: {stats['parsed_lines']}")
    print(f"    - Erreurs: {stats['errors']}")
    print(f"    - Taux de succès: {stats['success_rate']}")
    print(f"    - Par type: {json.dumps(stats['by_type'], indent=2)}")
    
    # Analyse de sécurité si demandée
    if args.analyze and parsed_logs:
        print(f"\n[*] Analyse de sécurité en cours...")
        analyzer = LogAnalyzer(log_parser)
        
        analyzer.detect_brute_force(parsed_logs)
        analyzer.detect_suspicious_ports(parsed_logs)
        analyzer.detect_privilege_escalation(parsed_logs)
        
        alerts = analyzer.get_all_alerts()
        summary = analyzer.get_alert_summary()
        
        print(f"\n[+] Résumé des alertes:")
        print(f"    - Total: {summary['total']}")
        print(f"    - Par type: {json.dumps(summary['by_type'], indent=2)}")
        print(f"    - Par sévérité: {json.dumps(summary['by_severity'], indent=2)}")
        
        if alerts:
            print(f"\n[!] Alertes détectées:")
            for i, alert in enumerate(alerts[:10], 1):  # Limite à 10
                print(f"\n    --- Alerte #{i} ---")
                print(f"    Type: {alert['type']}")
                print(f"    Sévérité: {alert['severity']}")
                print(f"    Description: {alert['description']}")
    
    # Export si demandé
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        output_data = {
            "statistics": stats,
            "logs": [
                {
                    "timestamp": log.timestamp.isoformat(),
                    "type": log.log_type.value,
                    "source_ip": log.source_ip,
                    "user": log.user,
                    "action": log.action,
                    "severity": log.severity
                }
                for log in parsed_logs[:1000]  # Limite pour l'export
            ]
        }
        
        if args.analyze:
            output_data["alerts"] = alerts
            output_data["alert_summary"] = summary
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n[+] Résultats exportés vers: {output_path}")
    
    print(f"\n{'='*60}")
    print("  Analyse terminée")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
