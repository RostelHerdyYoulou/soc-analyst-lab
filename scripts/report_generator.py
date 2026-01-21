#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC Analyst Lab - Générateur de Rapports d'Incidents
=====================================================
Auteur: Herdy Rostel Youlou
Description: Outil de génération de rapports d'incidents de sécurité
             au format HTML et Markdown
"""

import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class IncidentSeverity(Enum):
    """Niveaux de sévérité des incidents"""
    CRITICAL = ("Critical", "#dc3545", 1)
    HIGH = ("High", "#fd7e14", 2)
    MEDIUM = ("Medium", "#ffc107", 3)
    LOW = ("Low", "#28a745", 4)
    INFO = ("Informational", "#17a2b8", 5)
    
    def __init__(self, label: str, color: str, priority: int):
        self.label = label
        self.color = color
        self.priority = priority


class IncidentStatus(Enum):
    """Statuts des incidents"""
    NEW = "New"
    IN_PROGRESS = "In Progress"
    CONTAINED = "Contained"
    ERADICATED = "Eradicated"
    RECOVERED = "Recovered"
    CLOSED = "Closed"
    FALSE_POSITIVE = "False Positive"


class IncidentCategory(Enum):
    """Catégories d'incidents NIST"""
    MALWARE = "Malware"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"
    DOS = "Denial of Service"
    DATA_BREACH = "Data Breach"
    PHISHING = "Phishing/Social Engineering"
    INSIDER_THREAT = "Insider Threat"
    WEB_ATTACK = "Web Application Attack"
    RECONNAISSANCE = "Reconnaissance"
    OTHER = "Other"


@dataclass
class TimelineEntry:
    """Entrée dans la chronologie de l'incident"""
    timestamp: datetime
    action: str
    analyst: str
    details: str = ""


@dataclass
class Artifact:
    """Artefact/preuve de l'incident"""
    name: str
    artifact_type: str  # log, pcap, image, hash, etc.
    location: str
    description: str = ""
    hash_value: str = ""


@dataclass
class IncidentReport:
    """Rapport d'incident complet"""
    # Identification
    incident_id: str
    title: str
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    # Classification
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    status: IncidentStatus = IncidentStatus.NEW
    category: IncidentCategory = IncidentCategory.OTHER
    
    # Détails
    description: str = ""
    impact: str = ""
    affected_systems: List[str] = field(default_factory=list)
    
    # IoCs
    iocs: List[Dict] = field(default_factory=list)
    
    # Analyse
    root_cause: str = ""
    attack_vector: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    
    # Réponse
    containment_actions: List[str] = field(default_factory=list)
    eradication_actions: List[str] = field(default_factory=list)
    recovery_actions: List[str] = field(default_factory=list)
    
    # Chronologie et preuves
    timeline: List[TimelineEntry] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    
    # Recommandations
    recommendations: List[str] = field(default_factory=list)
    lessons_learned: str = ""
    
    # Métadonnées
    analyst: str = ""
    reviewer: str = ""
    tags: List[str] = field(default_factory=list)


class ReportGenerator:
    """
    Générateur de rapports d'incidents
    
    Formats supportés:
    - HTML (avec styling moderne)
    - Markdown
    - JSON
    """
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def create_incident(self, incident_id: str, title: str) -> IncidentReport:
        """Crée un nouveau rapport d'incident"""
        return IncidentReport(incident_id=incident_id, title=title)
    
    def generate_html(self, report: IncidentReport) -> str:
        """Génère le rapport au format HTML"""
        
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Incident - {report.incident_id}</title>
    <style>
        :root {{
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --background-color: #f8f9fa;
            --text-color: #333;
            --border-color: #dee2e6;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--background-color);
            color: var(--text-color);
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        
        .header h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        
        .header .meta {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            font-size: 0.9em;
            opacity: 0.9;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            color: white;
            background-color: {report.severity.color};
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            background-color: #6c757d;
            color: white;
        }}
        
        .section {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }}
        
        .section h2 {{
            color: var(--primary-color);
            border-bottom: 2px solid var(--secondary-color);
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        
        .section h3 {{
            color: var(--secondary-color);
            margin: 15px 0 10px;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }}
        
        .info-item {{
            padding: 15px;
            background: var(--background-color);
            border-radius: 8px;
        }}
        
        .info-item label {{
            font-weight: bold;
            color: #666;
            display: block;
            margin-bottom: 5px;
        }}
        
        .ioc-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        .ioc-table th, .ioc-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .ioc-table th {{
            background-color: var(--primary-color);
            color: white;
        }}
        
        .ioc-table tr:hover {{
            background-color: #f5f5f5;
        }}
        
        .timeline {{
            position: relative;
            padding-left: 30px;
        }}
        
        .timeline::before {{
            content: '';
            position: absolute;
            left: 10px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--secondary-color);
        }}
        
        .timeline-item {{
            position: relative;
            margin-bottom: 20px;
            padding: 15px;
            background: var(--background-color);
            border-radius: 8px;
        }}
        
        .timeline-item::before {{
            content: '';
            position: absolute;
            left: -24px;
            top: 20px;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--secondary-color);
        }}
        
        .timeline-item .time {{
            font-size: 0.85em;
            color: #666;
        }}
        
        .mitre-tag {{
            display: inline-block;
            padding: 3px 10px;
            background: #e9ecef;
            border-radius: 15px;
            margin: 3px;
            font-size: 0.85em;
        }}
        
        .action-list {{
            list-style: none;
        }}
        
        .action-list li {{
            padding: 10px;
            margin: 5px 0;
            background: var(--background-color);
            border-left: 3px solid var(--secondary-color);
            border-radius: 0 5px 5px 0;
        }}
        
        .recommendation {{
            padding: 15px;
            margin: 10px 0;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 0 5px 5px 0;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
        
        @media print {{
            body {{ background: white; }}
            .section {{ box-shadow: none; border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Rapport d'Incident de Sécurité</h1>
            <div style="margin: 15px 0;">
                <span class="severity-badge">{report.severity.label}</span>
                <span class="status-badge">{report.status.value}</span>
            </div>
            <div class="meta">
                <span>📋 ID: {report.incident_id}</span>
                <span>📅 Créé: {report.created_at.strftime('%Y-%m-%d %H:%M')}</span>
                <span>🔄 Mis à jour: {report.updated_at.strftime('%Y-%m-%d %H:%M')}</span>
                <span>👤 Analyste: {report.analyst or 'Non assigné'}</span>
            </div>
        </div>
        
        <div class="section">
            <h2>📝 Résumé Exécutif</h2>
            <h3>{report.title}</h3>
            <p>{report.description or 'Aucune description fournie.'}</p>
            
            <div class="info-grid" style="margin-top: 20px;">
                <div class="info-item">
                    <label>Catégorie</label>
                    <span>{report.category.value}</span>
                </div>
                <div class="info-item">
                    <label>Vecteur d'Attaque</label>
                    <span>{report.attack_vector or 'Non déterminé'}</span>
                </div>
                <div class="info-item">
                    <label>Impact</label>
                    <span>{report.impact or 'En cours d\'évaluation'}</span>
                </div>
                <div class="info-item">
                    <label>Systèmes Affectés</label>
                    <span>{', '.join(report.affected_systems) or 'Non identifiés'}</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Techniques MITRE ATT&CK</h2>
            <div>
                {' '.join([f'<span class="mitre-tag">{t}</span>' for t in report.mitre_techniques]) or '<p>Aucune technique identifiée</p>'}
            </div>
        </div>
        
        <div class="section">
            <h2>Indicateurs de Compromission (IoCs)</h2>
            {self._generate_ioc_table_html(report.iocs)}
        </div>
        
        <div class="section">
            <h2>Chronologie de l'Incident</h2>
            <div class="timeline">
                {self._generate_timeline_html(report.timeline)}
            </div>
        </div>
        
        <div class="section">
            <h2>🛠️ Actions de Réponse</h2>
            
            <h3>Confinement</h3>
            <ul class="action-list">
                {self._generate_action_list_html(report.containment_actions)}
            </ul>
            
            <h3>Éradication</h3>
            <ul class="action-list">
                {self._generate_action_list_html(report.eradication_actions)}
            </ul>
            
            <h3>Récupération</h3>
            <ul class="action-list">
                {self._generate_action_list_html(report.recovery_actions)}
            </ul>
        </div>
        
        <div class="section">
            <h2>Recommandations</h2>
            {self._generate_recommendations_html(report.recommendations)}
        </div>
        
        <div class="section">
            <h2>Leçons Apprises</h2>
            <p>{report.lessons_learned or 'À compléter après clôture de l\'incident.'}</p>
        </div>
        
        <div class="footer">
            <p>Rapport généré automatiquement par SOC Analyst Lab</p>
            <p>© {datetime.now().year} - Herdy Rostel Youlou</p>
        </div>
    </div>
</body>
</html>"""
        
        return html
    
    def _generate_ioc_table_html(self, iocs: List[Dict]) -> str:
        """Génère le tableau HTML des IoCs"""
        if not iocs:
            return "<p>Aucun IoC identifié</p>"
        
        rows = ""
        for ioc in iocs:
            rows += f"""
            <tr>
                <td><code>{ioc.get('value', 'N/A')}</code></td>
                <td>{ioc.get('type', 'N/A')}</td>
                <td>{ioc.get('confidence', 'N/A')}</td>
                <td>{ioc.get('context', '')[:50]}...</td>
            </tr>"""
        
        return f"""
        <table class="ioc-table">
            <thead>
                <tr>
                    <th>Valeur</th>
                    <th>Type</th>
                    <th>Confiance</th>
                    <th>Contexte</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>"""
    
    def _generate_timeline_html(self, timeline: List[TimelineEntry]) -> str:
        """Génère la chronologie HTML"""
        if not timeline:
            return "<p>Aucune entrée dans la chronologie</p>"
        
        items = ""
        for entry in timeline:
            items += f"""
            <div class="timeline-item">
                <div class="time">{entry.timestamp.strftime('%Y-%m-%d %H:%M')} - {entry.analyst}</div>
                <strong>{entry.action}</strong>
                <p>{entry.details}</p>
            </div>"""
        
        return items
    
    def _generate_action_list_html(self, actions: List[str]) -> str:
        """Génère la liste HTML des actions"""
        if not actions:
            return "<li>Aucune action enregistrée</li>"
        
        return "\n".join([f"<li>{action}</li>" for action in actions])
    
    def _generate_recommendations_html(self, recommendations: List[str]) -> str:
        """Génère les recommandations HTML"""
        if not recommendations:
            return "<p>Aucune recommandation</p>"
        
        return "\n".join([f'<div class="recommendation">💡 {rec}</div>' for rec in recommendations])
    
    def generate_markdown(self, report: IncidentReport) -> str:
        """Génère le rapport au format Markdown"""

        md = f"""# Rapport d'Incident de Sécurité

## Informations Générales

| Champ | Valeur |
|-------|--------|
| **ID Incident** | {report.incident_id} |
| **Titre** | {report.title} |
| **Sévérité** | {report.severity.label} |
| **Statut** | {report.status.value} |
| **Catégorie** | {report.category.value} |
| **Date de création** | {report.created_at.strftime('%Y-%m-%d %H:%M')} |
| **Dernière mise à jour** | {report.updated_at.strftime('%Y-%m-%d %H:%M')} |
| **Analyste** | {report.analyst or 'Non assigné'} |

---

## 📝 Description

{report.description or '*Aucune description fournie.*'}

### Impact
{report.impact or '*En cours d\'évaluation*'}

### Systèmes Affectés
{', '.join(report.affected_systems) if report.affected_systems else '*Non identifiés*'}

### Vecteur d'Attaque
{report.attack_vector or '*Non déterminé*'}

---

## Techniques MITRE ATT&CK

{', '.join([f'`{t}`' for t in report.mitre_techniques]) if report.mitre_techniques else '*Aucune technique identifiée*'}

---

## Indicateurs de Compromission (IoCs)

{self._generate_ioc_table_md(report.iocs)}

---

## Chronologie

{self._generate_timeline_md(report.timeline)}

---

## 🛠️ Actions de Réponse

### Confinement
{self._generate_action_list_md(report.containment_actions)}

### Éradication
{self._generate_action_list_md(report.eradication_actions)}

### Récupération
{self._generate_action_list_md(report.recovery_actions)}

---

## Recommandations

{self._generate_recommendations_md(report.recommendations)}

---

## Leçons Apprises

{report.lessons_learned or '*À compléter après clôture de l\'incident.*'}

---

*Rapport généré automatiquement par SOC Analyst Lab*
*© {datetime.now().year} - Herdy Rostel Youlou*
"""
        return md
    
    def _generate_ioc_table_md(self, iocs: List[Dict]) -> str:
        """Génère le tableau Markdown des IoCs"""
        if not iocs:
            return "*Aucun IoC identifié*"
        
        md = "| Valeur | Type | Confiance |\n|--------|------|----------|\n"
        for ioc in iocs:
            md += f"| `{ioc.get('value', 'N/A')}` | {ioc.get('type', 'N/A')} | {ioc.get('confidence', 'N/A')} |\n"
        
        return md
    
    def _generate_timeline_md(self, timeline: List[TimelineEntry]) -> str:
        """Génère la chronologie Markdown"""
        if not timeline:
            return "*Aucune entrée dans la chronologie*"
        
        md = ""
        for entry in timeline:
            md += f"- **{entry.timestamp.strftime('%Y-%m-%d %H:%M')}** - {entry.analyst}\n"
            md += f"  - {entry.action}\n"
            if entry.details:
                md += f"  - {entry.details}\n"
        
        return md
    
    def _generate_action_list_md(self, actions: List[str]) -> str:
        """Génère la liste Markdown des actions"""
        if not actions:
            return "*Aucune action enregistrée*"
        
        return "\n".join([f"- {action}" for action in actions])
    
    def _generate_recommendations_md(self, recommendations: List[str]) -> str:
        """Génère les recommandations Markdown"""
        if not recommendations:
            return "*Aucune recommandation*"
        
        return "\n".join([f"- 💡 {rec}" for rec in recommendations])
    
    def save_report(self, report: IncidentReport, format: str = "html") -> Path:
        """Sauvegarde le rapport dans un fichier"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format == "html":
            content = self.generate_html(report)
            filename = f"{report.incident_id}_{timestamp}.html"
        elif format == "md":
            content = self.generate_markdown(report)
            filename = f"{report.incident_id}_{timestamp}.md"
        elif format == "json":
            content = json.dumps(report.__dict__, default=str, indent=2, ensure_ascii=False)
            filename = f"{report.incident_id}_{timestamp}.json"
        else:
            raise ValueError(f"Format non supporté: {format}")
        
        output_path = self.output_dir / filename
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return output_path


def create_sample_report() -> IncidentReport:
    """Crée un rapport d'exemple pour démonstration"""
    report = IncidentReport(
        incident_id="INC-2026-001",
        title="Tentative de Brute Force SSH détectée sur serveur de production",
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.CONTAINED,
        category=IncidentCategory.UNAUTHORIZED_ACCESS,
        description="""
        Le 15 janvier 2026 à 14h32, le système de monitoring a détecté une série 
        de tentatives de connexion SSH échouées provenant de l'adresse IP 185.220.101.42.
        Plus de 500 tentatives ont été enregistrées en l'espace de 10 minutes, 
        ciblant le serveur de production SRV-PROD-01.
        """,
        impact="Aucune compromission confirmée. Service SSH temporairement ralenti.",
        affected_systems=["SRV-PROD-01", "192.168.1.100"],
        attack_vector="Attaque par force brute sur le service SSH (port 22)",
        mitre_techniques=["T1110.001 - Brute Force: Password Guessing", "T1078 - Valid Accounts"],
        root_cause="Service SSH exposé sur Internet sans protection rate-limiting",
        analyst="Herdy Rostel Youlou"
    )
    
    # Ajouter des IoCs
    report.iocs = [
        {"value": "185.220.101.42", "type": "ip", "confidence": "HIGH", "context": "Source de l'attaque"},
        {"value": "192.168.1.100", "type": "ip", "confidence": "HIGH", "context": "Cible de l'attaque"},
    ]
    
    # Ajouter la chronologie
    report.timeline = [
        TimelineEntry(
            timestamp=datetime(2026, 1, 15, 14, 32),
            action="Détection de l'incident",
            analyst="Système SIEM",
            details="Alerte automatique: seuil de tentatives SSH dépassé"
        ),
        TimelineEntry(
            timestamp=datetime(2026, 1, 15, 14, 35),
            action="Escalade vers l'équipe SOC",
            analyst="Auto",
            details="Incident assigné à l'analyste de garde"
        ),
        TimelineEntry(
            timestamp=datetime(2026, 1, 15, 14, 40),
            action="Blocage de l'IP source",
            analyst="Herdy Rostel Youlou",
            details="Ajout de 185.220.101.42 dans la blacklist du firewall"
        ),
    ]
    
    # Ajouter les actions de réponse
    report.containment_actions = [
        "Blocage de l'IP 185.220.101.42 au niveau du firewall périmétrique",
        "Activation du rate-limiting SSH (5 tentatives/minute)",
        "Notification envoyée à l'équipe infrastructure"
    ]
    
    report.eradication_actions = [
        "Vérification des comptes utilisateurs - aucune compromission",
        "Rotation des mots de passe des comptes administrateurs",
        "Mise à jour des règles Fail2ban"
    ]
    
    report.recovery_actions = [
        "Restauration du service SSH normal",
        "Monitoring renforcé pendant 48h"
    ]
    
    report.recommendations = [
        "Implémenter l'authentification par clé SSH uniquement",
        "Déployer une solution de protection contre les brute force (Fail2ban, CrowdSec)",
        "Considérer l'utilisation d'un bastion/jump host pour l'accès SSH",
        "Activer la journalisation détaillée des connexions SSH"
    ]
    
    report.lessons_learned = """
    Cet incident a mis en évidence la nécessité de renforcer la protection du service SSH.
    La détection rapide (moins de 5 minutes) a permis de contenir l'incident efficacement.
    Il est recommandé de revoir la politique d'accès SSH pour tous les serveurs exposés.
    """
    
    return report


def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description='SOC Analyst Lab - Générateur de Rapports d\'Incidents',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python report_generator.py --demo
  python report_generator.py --new INC-2026-002 "Alerte Malware"
  python report_generator.py --input incident.json --format html
        """
    )
    
    parser.add_argument('--demo', action='store_true', help='Générer un rapport de démonstration')
    parser.add_argument('--new', nargs=2, metavar=('ID', 'TITLE'), help='Créer un nouveau rapport')
    parser.add_argument('-i', '--input', help='Fichier JSON d\'incident à convertir')
    parser.add_argument('-f', '--format', choices=['html', 'md', 'json'], 
                       default='html', help='Format de sortie')
    parser.add_argument('-o', '--output', default='reports', help='Dossier de sortie')
    
    args = parser.parse_args()
    
    generator = ReportGenerator(output_dir=args.output)
    
    print(f"\n{'='*60}")
    print("  SOC Analyst Lab - Générateur de Rapports")
    print(f"{'='*60}\n")
    
    if args.demo:
        print("[*] Génération du rapport de démonstration...")
        report = create_sample_report()
        
        # Générer tous les formats
        for fmt in ['html', 'md', 'json']:
            output_path = generator.save_report(report, format=fmt)
            print(f"[+] Rapport généré: {output_path}")
    
    elif args.new:
        incident_id, title = args.new
        print(f"[*] Création d'un nouveau rapport: {incident_id}")
        report = generator.create_incident(incident_id, title)
        output_path = generator.save_report(report, format=args.format)
        print(f"[+] Rapport créé: {output_path}")
    
    elif args.input:
        print(f"[*] Chargement de l'incident depuis: {args.input}")
        # TODO: Implémenter le chargement depuis JSON
        print("[!] Fonctionnalité en cours de développement")
    
    else:
        parser.print_help()
    
    print(f"\n{'='*60}")
    print("  Génération terminée")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
