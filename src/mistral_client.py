# ============================================================
#  REMI Solar Services — AI Email Triage
#  Created by GOVERNYS (Niels Tilch — CTO)
# ============================================================
"""
mistral_client.py — AI engines for the triage system.

Two tasks (OCR and classification) can each run on one of two providers, chosen
by the global administrator on the Settings page and passed in per call:
  * "mistral" — hosted Mistral models (needs MISTRAL_API_KEY)
  * "local"   — lightweight on-box engine, no token required

Every function returns a dict that includes usage metrics
(provider / model_version / pages / input_tokens / output_tokens / confidence)
so the system can meter AI consumption regardless of provider.
"""
import os
import re

MODELS = {
    ("ocr", "mistral"): "mistral-ocr-latest",
    ("ocr", "local"): "local-ocr",
    ("classification", "mistral"): "mistral-small-latest",
    ("classification", "local"): "local-classifier",
}

API_KEY = os.environ.get("MISTRAL_API_KEY")


def _toks(*texts):
    return max(1, sum(len(t or "") for t in texts) // 4)


def _resolve(task, provider):
    """Pick the provider actually used; fall back to local if Mistral has no key."""
    fell_back = False
    if provider == "mistral" and not API_KEY:
        provider, fell_back = "local", True
    return provider, MODELS[(task, provider)], fell_back


# ----------------------------------------------------------------------------
#  OCR
# ----------------------------------------------------------------------------
def ocr_document(file_bytes, mime_type="", filename="", provider="local"):
    """Returns {text, confidence, model_version, provider, pages,
    input_tokens, output_tokens, fell_back}."""
    provider, model, fell_back = _resolve("ocr", provider)

    if provider == "mistral":
        # TODO: real Mistral OCR call here (provider has a token).
        text, conf = "", 0.0
        pages = max(1, len(file_bytes) // 40000)
    else:
        text, conf = _local_ocr(file_bytes, mime_type, filename)
        pages = max(1, len(text) // 1500)

    return {"text": text, "confidence": conf, "model_version": model,
            "provider": provider, "pages": pages,
            "input_tokens": pages * 256, "output_tokens": _toks(text),
            "fell_back": fell_back}


def _local_ocr(file_bytes, mime_type, filename):
    text_like = filename.lower().endswith((".txt", ".csv", ".md", ".log", ".json", ".eml"))
    if text_like or (mime_type or "").startswith("text/"):
        try:
            return file_bytes.decode("utf-8", "ignore")[:5000], 0.99
        except Exception:
            pass
    return (f"[binary file '{filename or 'document'}' — local OCR returned no machine text; "
            f"a real OCR model (Mistral or an on-prem OCR engine) is needed]"), 0.0


# ----------------------------------------------------------------------------
#  Classification + extraction
# ----------------------------------------------------------------------------
_CATEGORY_RULES = [
    ("maintenance", ["panne", "erreur", "onduleur", "ne produit", "dépannage", "défaut",
                     "broken", "not working", "outage", "repair", "fault"]),
    ("invoices",    ["facture", "échéance", "paiement", "montant", "règlement",
                     "invoice", "payment", "due", "amount"]),
    ("lead",        ["devis", "kwc", "kw", "prix", "intéressé", "projet",
                     "quote", "quotation", "interested", "estimate"]),
    ("installation",["pose", "raccordement", "mise en service", "chantier", "commissioning", "installation"]),
    ("support",     ["question", "aide", "support", "renseignement", "candidature", "help"]),
]
_URGENT = ["urgent", "immédiat", "immediately", "panne", "ne produit", "outage",
           "mise en demeure", "asap", "critique", "critical"]
_HIGH = ["échéance", "deadline", "due", "facture", "réclamation", "complaint", "demeure"]
_FLAG_DEFAULT = ["mise en demeure", "rgpd", "gdpr", "avocat", "legal", "réclamation", "complaint"]


def classify_email(subject, body, ocr_text="", provider="local"):
    """Returns {category, request_type, priority, priority_score, confidence,
    summary, fields, model_version, provider, input_tokens, output_tokens, fell_back}."""
    provider, model, fell_back = _resolve("classification", provider)

    if provider == "mistral":
        # TODO: real Mistral Large call here (JSON-mode prompt).
        out = {"category": None, "request_type": None, "priority": "low",
               "priority_score": 0.0, "confidence": 0.0, "summary": "", "fields": {}}
    else:
        out = _local_classify(subject, body, ocr_text)

    out["model_version"] = model
    out["provider"] = provider
    out["fell_back"] = fell_back
    out["input_tokens"] = _toks(subject, body, ocr_text)
    out["output_tokens"] = 18 + 6 * len(out.get("fields") or {})
    return out


def _local_classify(subject, body, ocr_text):
    blob = f"{subject}\n{body}\n{ocr_text}".lower()
    category, hits = None, 0
    for cat, words in _CATEGORY_RULES:
        n = sum(1 for w in words if w in blob)
        if n > hits:
            category, hits = cat, n
    if any(w in blob for w in _URGENT):
        priority, score = "critical", 0.9
    elif any(w in blob for w in _HIGH):
        priority, score = "high", 0.72
    elif category in ("lead", "installation"):
        priority, score = "medium", 0.5
    else:
        priority, score = "low", 0.3
    rtype = None
    if "facture" in blob or "invoice" in blob:
        rtype = "invoice"
    elif "devis" in blob or "quote" in blob:
        rtype = "lead"
    elif "rendez" in blob or "appointment" in blob or "disponib" in blob:
        rtype = "appointment request"
    elif "réclamation" in blob or "complaint" in blob or "demeure" in blob:
        rtype = "complaint"
    elif category == "maintenance":
        rtype = "technical inquiry"
    confidence = round(min(0.95, 0.55 + 0.12 * hits), 2) if hits else 0.45
    return {"category": category, "request_type": rtype, "priority": priority,
            "priority_score": score, "confidence": confidence,
            "summary": (subject or body or "").strip()[:120],
            "fields": _extract_fields(f"{subject} {body} {ocr_text}")}


def _extract_fields(text):
    fields = {}
    m = re.search(r"\b(FA[-\s]?\d{4}[-\s]?\d{3,5})\b", text, re.I)
    if m: fields["invoice_number"] = m.group(1).upper().replace(" ", "-")
    m = re.search(r"(\d[\d\s.,]*)\s?€", text)
    if m: fields["amount_eur"] = m.group(1).strip()
    m = re.search(r"\b(\d{1,2}[/.]\d{1,2}[/.]\d{2,4})\b", text)
    if m: fields["date"] = m.group(1)
    m = re.search(r"\b(\d+(?:[.,]\d+)?)\s?kWc\b", text, re.I)
    if m: fields["system_size"] = m.group(0)
    return fields


def default_flagged_topics():
    return _FLAG_DEFAULT
