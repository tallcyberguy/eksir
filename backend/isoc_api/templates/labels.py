"""Per-locale labels for the customer notification template.

The LLM writes the body content in the target language; these labels are
the section headings and column names rendered by the HTML template.
Keep additions tight — only labels actually used in the template.
"""

from __future__ import annotations

_DEFAULT = "en"

_LABELS: dict[str, dict[str, str]] = {
    "en": {
        "untitled": "Untitled incident",
        "for_customer": "For",
        "incident_analysis": "Incident Analysis",
        "incident_details": "Incident Details",
        "related_incidents": "Related Incidents",
        "critical_impact": "Critical Impact",
        "threat_intel": "Threat Intelligence",
        "actions_taken": "Actions We Took",
        "recommended_actions": "Recommended Actions",
        "urgent": "URGENT",
        "generated_at": "Generated",
        "field_case_id": "Case ID",
        "field_severity": "Severity",
        "field_attack_type": "Attack Type",
        "field_rule": "Rule",
        "field_source": "Source",
        "field_time": "Time",
        "col_case": "Case",
        "col_rule": "Rule",
        "col_severity": "Severity",
        "col_time": "Time",
        # ── Threat Intelligence table ──────────────────────────────
        "ti_ioc": "IOC",
        "ti_location": "Location",
        "ti_vt_score": "VT Score",
        "ti_domain": "Domain",
        "ti_attribution": "Attribution",
        "ti_prior_cases": "Prior cases",
        "ti_detection": "Detection",
        "ti_feeds": "Threat feeds",
        "vt_clean": "CLEAN",
        "vt_suspicious": "SUSPICIOUS",
        "vt_malicious": "MALICIOUS",
        "ti_unavailable": "—",
    },
    "tr": {
        "untitled": "Adsız olay",
        "for_customer": "Müşteri",
        "incident_analysis": "Olay Analizi",
        "incident_details": "Olay Bilgileri",
        "related_incidents": "İlgili Olaylar",
        "critical_impact": "Kritik Etki",
        "threat_intel": "Tehdit İstihbaratı",
        "actions_taken": "Aldığımız Aksiyonlar",
        "recommended_actions": "Önerilen Aksiyonlar",
        "urgent": "ACİL",
        "generated_at": "Oluşturulma",
        "field_case_id": "Vaka No",
        "field_severity": "Önem",
        "field_attack_type": "Saldırı Türü",
        "field_rule": "Kural",
        "field_source": "Kaynak",
        "field_time": "Zaman",
        "col_case": "Vaka",
        "col_rule": "Kural",
        "col_severity": "Önem",
        "col_time": "Zaman",
        # ── Tehdit İstihbaratı tablosu ─────────────────────────────
        "ti_ioc": "IOC",
        "ti_location": "Konum",
        "ti_vt_score": "VT Skoru",
        "ti_domain": "Alan adı",
        "ti_attribution": "Atıf",
        "ti_prior_cases": "Önceki vakalar",
        "ti_detection": "Tespit",
        "ti_feeds": "Tehdit beslemeleri",
        "vt_clean": "TEMİZ",
        "vt_suspicious": "ŞÜPHELİ",
        "vt_malicious": "ZARARLI",
        "ti_unavailable": "—",
    },
    "de": {
        "untitled": "Unbenannter Vorfall",
        "for_customer": "Für",
        "incident_analysis": "Vorfallanalyse",
        "incident_details": "Vorfalldetails",
        "critical_impact": "Kritische Auswirkung",
        "threat_intel": "Bedrohungsdaten",
        "recommended_actions": "Empfohlene Maßnahmen",
        "urgent": "DRINGEND",
        "generated_at": "Erstellt",
        "field_case_id": "Fall-ID",
        "field_severity": "Schweregrad",
        "field_attack_type": "Angriffstyp",
        "field_rule": "Regel",
        "field_source": "Quelle",
        "field_time": "Zeit",
    },
    "fr": {
        "untitled": "Incident sans titre",
        "for_customer": "Pour",
        "incident_analysis": "Analyse de l'incident",
        "incident_details": "Détails de l'incident",
        "critical_impact": "Impact critique",
        "threat_intel": "Renseignements sur les menaces",
        "recommended_actions": "Actions recommandées",
        "urgent": "URGENT",
        "generated_at": "Généré",
        "field_case_id": "ID du cas",
        "field_severity": "Gravité",
        "field_attack_type": "Type d'attaque",
        "field_rule": "Règle",
        "field_source": "Source",
        "field_time": "Heure",
    },
    "es": {
        "untitled": "Incidente sin título",
        "for_customer": "Para",
        "incident_analysis": "Análisis del incidente",
        "incident_details": "Detalles del incidente",
        "critical_impact": "Impacto crítico",
        "threat_intel": "Inteligencia de amenazas",
        "recommended_actions": "Acciones recomendadas",
        "urgent": "URGENTE",
        "generated_at": "Generado",
        "field_case_id": "ID del caso",
        "field_severity": "Gravedad",
        "field_attack_type": "Tipo de ataque",
        "field_rule": "Regla",
        "field_source": "Fuente",
        "field_time": "Hora",
    },
}


def labels_for(locale: str | None) -> dict[str, str]:
    """Return labels for `locale`, falling back to English for any missing key.
    This way adding a new label only requires editing the English dict — other
    locales can be translated lazily without breaking the template."""
    base = _LABELS[_DEFAULT]
    chosen = _LABELS.get((locale or _DEFAULT).lower(), base)
    if chosen is base:
        return base
    return {**base, **chosen}
