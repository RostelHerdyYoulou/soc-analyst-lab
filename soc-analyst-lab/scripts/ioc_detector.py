#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC Analyst Lab - Détecteur d'IoCs (Indicateurs de Compromission)
==================================================================
Auteur: Herdy Rostel Youlou
Description: Outil de détection d'IoCs dans les logs et fichiers
             Supporte: IP, domaines, URLs, hashes, emails
"""

import re
import json
import hashlib
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field
from enum import Enum
import ipaddress


class IoCType(Enum):
    """Types d'indicateurs de compromission"""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"
    FILE_PATH = "filepath"
    CVE = "cve"
    REGISTRY_KEY = "registry"


@dataclass
class IoC:
    """Structure d'un indicateur de compromission"""
    value: str
    ioc_type: IoCType
    source: str
    confidence: str  # LOW, MEDIUM, HIGH
    context: str = ""
    tags: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "value": self.value,
            "type": self.ioc_type.value,
            "source": self.source,
            "confidence": self.confidence,
            "context": self.context,
            "tags": self.tags,
            "first_seen": self.first_seen.isoformat()
        }


class IoCDetector:
    """
    Détecteur d'indicateurs de compromission
    
    Fonctionnalités:
    - Extraction automatique d'IoCs depuis du texte
    - Chargement de listes d'IoCs malveillants
    - Comparaison avec des feeds de threat intelligence
    - Classification et scoring
    """
    
    # Expressions régulières pour l'extraction
    PATTERNS = {
        IoCType.IP_ADDRESS: re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        IoCType.DOMAIN: re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+' 
            r'(?:com|net|org|edu|gov|mil|io|co|info|biz|xyz|top|tk|ml|ga|cf|gq|ru|cn|br)\b',
            re.IGNORECASE
        ),
        IoCType.URL: re.compile(
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*',
            re.IGNORECASE
        ),
        IoCType.HASH_MD5: re.compile(r'\b[a-fA-F0-9]{32}\b'),
        IoCType.HASH_SHA1: re.compile(r'\b[a-fA-F0-9]{40}\b'),
        IoCType.HASH_SHA256: re.compile(r'\b[a-fA-F0-9]{64}\b'),
        IoCType.EMAIL: re.compile(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        ),
        IoCType.CVE: re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE),
        IoCType.REGISTRY_KEY: re.compile(
            r'\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR|HKCC)\\[^\s]+',
            re.IGNORECASE
        ),
    }
    
    # IPs privées et réservées à exclure
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('0.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('224.0.0.0/4'),
        ipaddress.ip_network('240.0.0.0/4'),
    ]
    
    # Domaines légitimes à exclure (whitelist basique)
    WHITELISTED_DOMAINS = {
        'google.com', 'googleapis.com', 'gstatic.com',
        'microsoft.com', 'windows.com', 'windowsupdate.com',
        'amazon.com', 'amazonaws.com',
        'cloudflare.com', 'cloudflare-dns.com',
        'github.com', 'githubusercontent.com',
        'facebook.com', 'fbcdn.net',
        'twitter.com', 'twimg.com',
        'linkedin.com', 'licdn.com',
        'apple.com', 'icloud.com',
    }
    
    def __init__(self, exclude_private: bool = True, verbose: bool = False):
        self.exclude_private = exclude_private
        self.verbose = verbose
        self.known_malicious: Dict[IoCType, Set[str]] = {t: set() for t in IoCType}
        self.detected_iocs: List[IoC] = []
        self.stats = {
            "total_extracted": 0,
            "malicious_matches": 0,
            "by_type": {}
        }
    
    def load_ioc_file(self, filepath: str, ioc_type: Optional[IoCType] = None, 
                      confidence: str = "HIGH") -> int:
        """
        Charge une liste d'IoCs connus malveillants
        
        Args:
            filepath: Chemin vers le fichier (un IoC par ligne)
            ioc_type: Type d'IoC (si None, détection auto)
            confidence: Niveau de confiance par défaut
        
        Returns:
            Nombre d'IoCs chargés
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Fichier d'IoCs non trouvé: {filepath}")
        
        count = 0
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                ioc_value = line.strip()
                if not ioc_value or ioc_value.startswith('#'):
                    continue
                
                detected_type = ioc_type or self._detect_ioc_type(ioc_value)
                if detected_type:
                    self.known_malicious[detected_type].add(ioc_value.lower())
                    count += 1
        
        if self.verbose:
            print(f"[+] Chargé {count} IoCs depuis {filepath}")
        
        return count
    
    def _detect_ioc_type(self, value: str) -> Optional[IoCType]:
        """Détecte automatiquement le type d'un IoC"""
        for ioc_type, pattern in self.PATTERNS.items():
            if pattern.fullmatch(value):
                return ioc_type
        return None
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Vérifie si une IP est privée/réservée"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in self.PRIVATE_RANGES)
        except ValueError:
            return False
    
    def _is_whitelisted_domain(self, domain: str) -> bool:
        """Vérifie si un domaine est dans la whitelist"""
        domain_lower = domain.lower()
        for whitelisted in self.WHITELISTED_DOMAINS:
            if domain_lower == whitelisted or domain_lower.endswith('.' + whitelisted):
                return True
        return False
    
    def extract_iocs(self, text: str, source: str = "unknown") -> List[IoC]:
        """
        Extrait tous les IoCs d'un texte
        
        Args:
            text: Texte à analyser
            source: Source de l'extraction (nom de fichier, etc.)
        
        Returns:
            Liste des IoCs extraits
        """
        extracted = []
        seen = set()  # Pour éviter les doublons
        
        for ioc_type, pattern in self.PATTERNS.items():
            matches = pattern.findall(text)
            
            for match in matches:
                if match in seen:
                    continue
                seen.add(match)
                
                # Filtrage
                if ioc_type == IoCType.IP_ADDRESS:
                    if self.exclude_private and self._is_private_ip(match):
                        continue
                
                if ioc_type == IoCType.DOMAIN:
                    if self._is_whitelisted_domain(match):
                        continue
                
                # Déterminer la confiance
                match_lower = match.lower()
                is_malicious = match_lower in self.known_malicious.get(ioc_type, set())
                confidence = "HIGH" if is_malicious else "LOW"
                
                # Extraire le contexte (50 caractères autour)
                context_match = re.search(
                    rf'.{{0,50}}{re.escape(match)}.{{0,50}}', 
                    text, 
                    re.IGNORECASE
                )
                context = context_match.group(0) if context_match else ""
                
                ioc = IoC(
                    value=match,
                    ioc_type=ioc_type,
                    source=source,
                    confidence=confidence,
                    context=context.strip(),
                    tags=["malicious"] if is_malicious else []
                )
                
                extracted.append(ioc)
                self.stats["total_extracted"] += 1
                self.stats["by_type"][ioc_type.value] = self.stats["by_type"].get(ioc_type.value, 0) + 1
                
                if is_malicious:
                    self.stats["malicious_matches"] += 1
        
        self.detected_iocs.extend(extracted)
        return extracted
    
    def extract_from_file(self, filepath: str) -> List[IoC]:
        """Extrait les IoCs d'un fichier"""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Fichier non trouvé: {filepath}")
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return self.extract_iocs(content, source=str(filepath))
    
    def check_ioc(self, value: str) -> Dict:
        """
        Vérifie un IoC spécifique contre les listes connues
        
        Args:
            value: Valeur de l'IoC à vérifier
        
        Returns:
            Résultat de la vérification
        """
        ioc_type = self._detect_ioc_type(value)
        
        result = {
            "value": value,
            "type": ioc_type.value if ioc_type else "unknown",
            "is_known_malicious": False,
            "is_private": False,
            "is_whitelisted": False,
            "risk_score": 0,
            "recommendations": []
        }
        
        if not ioc_type:
            result["recommendations"].append("Type d'IoC non reconnu")
            return result
        
        # Vérifications spécifiques
        if ioc_type == IoCType.IP_ADDRESS:
            result["is_private"] = self._is_private_ip(value)
            if result["is_private"]:
                result["recommendations"].append("IP privée - pas de risque externe")
        
        if ioc_type == IoCType.DOMAIN:
            result["is_whitelisted"] = self._is_whitelisted_domain(value)
            if result["is_whitelisted"]:
                result["recommendations"].append("Domaine whitelisté - probablement légitime")
        
        # Vérification malveillance
        if value.lower() in self.known_malicious.get(ioc_type, set()):
            result["is_known_malicious"] = True
            result["risk_score"] = 100
            result["recommendations"].append("⚠️ IoC connu malveillant - investigation immédiate recommandée")
        else:
            # Score basé sur des heuristiques
            score = 0
            
            if ioc_type == IoCType.IP_ADDRESS and not result["is_private"]:
                score += 20  # IP publique
            
            if ioc_type == IoCType.DOMAIN:
                # Domaines suspects (TLDs souvent abusés)
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
                if any(value.lower().endswith(tld) for tld in suspicious_tlds):
                    score += 40
                    result["recommendations"].append("TLD souvent utilisé pour le phishing")
            
            if ioc_type in [IoCType.HASH_MD5, IoCType.HASH_SHA1, IoCType.HASH_SHA256]:
                score += 30  # Les hashes méritent investigation
                result["recommendations"].append("Vérifier sur VirusTotal ou autre service")
            
            result["risk_score"] = min(score, 80)  # Max 80 si pas confirmé malveillant
        
        return result
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques d'extraction"""
        return self.stats
    
    def get_all_iocs(self) -> List[Dict]:
        """Retourne tous les IoCs détectés"""
        return [ioc.to_dict() for ioc in self.detected_iocs]
    
    def get_malicious_iocs(self) -> List[Dict]:
        """Retourne uniquement les IoCs malveillants"""
        return [ioc.to_dict() for ioc in self.detected_iocs if "malicious" in ioc.tags]
    
    def export_iocs(self, filepath: str, format: str = "json") -> None:
        """
        Exporte les IoCs détectés
        
        Args:
            filepath: Chemin du fichier de sortie
            format: Format d'export (json, csv, txt)
        """
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == "json":
            output = {
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "total_iocs": len(self.detected_iocs),
                    "statistics": self.stats
                },
                "iocs": self.get_all_iocs()
            }
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2, ensure_ascii=False)
        
        elif format == "csv":
            import csv
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['value', 'type', 'source', 'confidence', 'context', 'tags'])
                for ioc in self.detected_iocs:
                    writer.writerow([
                        ioc.value, ioc.ioc_type.value, ioc.source,
                        ioc.confidence, ioc.context, ','.join(ioc.tags)
                    ])
        
        elif format == "txt":
            with open(path, 'w', encoding='utf-8') as f:
                for ioc in self.detected_iocs:
                    f.write(f"{ioc.value}\n")
        
        if self.verbose:
            print(f"[+] IoCs exportés vers {path}")
    
    def generate_report(self) -> str:
        """Génère un rapport textuel des IoCs détectés"""
        report = []
        report.append("=" * 60)
        report.append("  RAPPORT D'ANALYSE IoCs")
        report.append("=" * 60)
        report.append(f"\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"\nSTATISTIQUES:")
        report.append(f"  - Total IoCs extraits: {self.stats['total_extracted']}")
        report.append(f"  - Correspondances malveillantes: {self.stats['malicious_matches']}")
        report.append(f"\n  Par type:")
        for ioc_type, count in self.stats['by_type'].items():
            report.append(f"    - {ioc_type}: {count}")
        
        if self.stats['malicious_matches'] > 0:
            report.append(f"\n{'='*60}")
            report.append("  ⚠️  IoCs MALVEILLANTS DÉTECTÉS")
            report.append("=" * 60)
            for ioc in self.detected_iocs:
                if "malicious" in ioc.tags:
                    report.append(f"\n  [{ioc.ioc_type.value.upper()}] {ioc.value}")
                    report.append(f"    Source: {ioc.source}")
                    report.append(f"    Contexte: {ioc.context[:100]}...")
        
        report.append(f"\n{'='*60}")
        return "\n".join(report)


def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description='SOC Analyst Lab - Détecteur d\'IoCs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python ioc_detector.py --input logs/suspicious.log
  python ioc_detector.py --input email.txt --ioc-file rules/malicious_ips.txt
  python ioc_detector.py --check 192.168.1.1
  python ioc_detector.py --input logs/ --output reports/iocs.json
        """
    )
    
    parser.add_argument('-i', '--input', help='Fichier ou dossier à analyser')
    parser.add_argument('-o', '--output', help='Fichier de sortie')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'txt'], 
                       default='json', help='Format de sortie')
    parser.add_argument('--ioc-file', action='append', 
                       help='Fichier d\'IoCs malveillants connus (peut être répété)')
    parser.add_argument('--check', help='Vérifier un IoC spécifique')
    parser.add_argument('--include-private', action='store_true',
                       help='Inclure les IPs privées')
    parser.add_argument('-v', '--verbose', action='store_true', help='Mode verbeux')
    
    args = parser.parse_args()
    
    detector = IoCDetector(
        exclude_private=not args.include_private,
        verbose=args.verbose
    )
    
    print(f"\n{'='*60}")
    print("  SOC Analyst Lab - Détecteur d'IoCs")
    print(f"{'='*60}\n")
    
    # Charger les fichiers d'IoCs connus
    if args.ioc_file:
        for ioc_file in args.ioc_file:
            try:
                count = detector.load_ioc_file(ioc_file)
                print(f"[+] Chargé {count} IoCs depuis {ioc_file}")
            except FileNotFoundError as e:
                print(f"[!] {e}")
    
    # Mode vérification d'un IoC unique
    if args.check:
        print(f"\n[*] Vérification de l'IoC: {args.check}")
        result = detector.check_ioc(args.check)
        print(f"\n  Résultat:")
        print(f"    - Type: {result['type']}")
        print(f"    - Malveillant connu: {'OUI ⚠️' if result['is_known_malicious'] else 'Non'}")
        print(f"    - IP Privée: {'Oui' if result['is_private'] else 'Non'}")
        print(f"    - Whitelisté: {'Oui' if result['is_whitelisted'] else 'Non'}")
        print(f"    - Score de risque: {result['risk_score']}/100")
        if result['recommendations']:
            print(f"    - Recommandations:")
            for rec in result['recommendations']:
                print(f"      • {rec}")
        return
    
    # Mode extraction depuis fichier(s)
    if args.input:
        input_path = Path(args.input)
        
        if input_path.is_file():
            print(f"[*] Analyse du fichier: {input_path}")
            iocs = detector.extract_from_file(str(input_path))
            print(f"    Trouvé: {len(iocs)} IoCs")
        
        elif input_path.is_dir():
            for file_path in input_path.glob('**/*'):
                if file_path.is_file():
                    print(f"[*] Analyse: {file_path}")
                    iocs = detector.extract_from_file(str(file_path))
                    print(f"    Trouvé: {len(iocs)} IoCs")
        
        else:
            print(f"[!] Chemin invalide: {input_path}")
            return
        
        # Afficher le rapport
        print(detector.generate_report())
        
        # Export si demandé
        if args.output:
            detector.export_iocs(args.output, args.format)
            print(f"\n[+] Résultats exportés vers: {args.output}")
    
    else:
        parser.print_help()
    
    print(f"\n{'='*60}")
    print("  Analyse terminée")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
