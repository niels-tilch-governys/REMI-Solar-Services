# ============================================================
#  REMI Solar Services — AI Email Triage
#  Created by GOVERNYS (Niels Tilch — CTO)
# ============================================================
"""
init_db.py — create the SQLite database, load the schema, and seed demo data.

Run once:   python init_db.py
Re-run:     python init_db.py --reset   (drops and recreates everything)

Passwords are hashed with bcrypt. Demo accounts are printed at the end.
"""
import os
import sqlite3
import argparse
import random
import datetime as dt
import bcrypt
from ids import uuid7

DB_PATH = os.path.join(os.path.dirname(__file__), "remi_solar.db")
SCHEMA = os.path.join(os.path.dirname(__file__), "schema.sql")


def hash_pw(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def iso(days_ago=0, hours_ago=0):
    t = dt.datetime.now() - dt.timedelta(days=days_ago, hours=hours_ago)
    return t.strftime("%Y-%m-%d %H:%M:%S")


def seed(con: sqlite3.Connection):
    c = con.cursor()

    # ---- roles ----
    roles = [
        ("global_administrator", "Full access to every page and action."),
        ("department_viewer", "Sees the mailbox of their own department."),
        ("audit_administrator", "Reviews audit records and audit logs."),
        ("classification_verification_administrator", "Reviews flagged / low-confidence items."),
        ("email_administrator", "Accesses mailbox reception storage before classification."),
    ]
    c.executemany("INSERT INTO roles(name, description) VALUES (?,?)", roles)
    role_id = {r[0]: i + 1 for i, r in enumerate(roles)}

    # ---- departments (each has its own inbound address) ----
    departments = [
        ("HR", "hr@remi-solar.eu"),
        ("Finance", "finance@remi-solar.eu"),
        ("Sales", "sales@remi-solar.eu"),
        ("IT", "it@remi-solar.eu"),
        ("Directors", "directors@remi-solar.eu"),
        ("Legal", "legal@remi-solar.eu"),
        ("Technician", "technician@remi-solar.eu"),
    ]
    c.executemany("INSERT INTO departments(uuid, name, email_address) VALUES (?,?,?)",
                  [(uuid7(), name, addr) for name, addr in departments])
    dept_id = {d[0]: i + 1 for i, d in enumerate(departments)}

    # ---- lookups ----
    categories = ["lead", "installation", "maintenance", "invoices", "support"]
    c.executemany("INSERT INTO email_categories(name) VALUES (?)", [(x,) for x in categories])
    cat_id = {x: i + 1 for i, x in enumerate(categories)}

    rtypes = ["technical inquiry", "appointment request", "lead", "invoice", "complaint", "supplier inquiry"]
    c.executemany("INSERT INTO request_types(name) VALUES (?)", [(x,) for x in rtypes])

    priorities = [
        ("critical", 0.85, 1.0), ("high", 0.6, 0.85),
        ("medium", 0.35, 0.6), ("low", 0.0, 0.35),
    ]
    c.executemany("INSERT INTO priorities(level, score_min, score_max) VALUES (?,?,?)", priorities)
    prio_id = {p[0]: i + 1 for i, p in enumerate(priorities)}

    mailboxes = [
        ("Team Leader mailbox", "leaders@remi-solar.eu", dept_id["Directors"], 0),
        ("Default mailbox", "unclassified@remi-solar.eu", None, 1),
    ]
    c.executemany("INSERT INTO mailboxes(name, address, department_id, is_default) VALUES (?,?,?,?)", mailboxes)

    # ---- settings (AI engine selection) ----
    settings = [
        ("confidence_threshold", "0.70"),
        ("flagged_topics", "gdpr, legal, complaint, contract"),
        ("classification_target_seconds", "8"),
        ("routing_accuracy_target", "0.90"),
        ("ocr_provider", "mistral"),            # 'mistral' | 'local'
        ("llm_provider", "mistral"),            # 'mistral' | 'local'
        ("mistral_ocr_model", "mistral-ocr-latest"),
        ("mistral_llm_model", "mistral-small-latest"),
        ("local_ocr_model", "local-ocr"),
        ("local_llm_model", "local-classifier"),
    ]
    c.executemany("INSERT INTO app_settings(key, value) VALUES (?,?)", settings)

    # ---- users (all passwords below are DEMO ONLY) ----
    users = [
        ("Niels Tilch", "admin@remi-solar.eu", "admin123", "global_administrator", None),
        ("Sofia Laurent", "sales@remi-solar.eu", "sales123", "department_viewer", "Sales"),
        ("Marc Lefèvre", "finance@remi-solar.eu", "finance123", "department_viewer", "Finance"),
        ("Audrey Roche", "audit@remi-solar.eu", "audit123", "audit_administrator", None),
        ("Victor Nguyen", "verify@remi-solar.eu", "verify123", "classification_verification_administrator", None),
        ("Léa Fontaine", "mail@remi-solar.eu", "mail123", "email_administrator", None),
    ]
    for name, email, pw, role, dept in users:
        c.execute(
            "INSERT INTO users(uuid, full_name, email, password_hash, role_id, department_id) VALUES (?,?,?,?,?,?)",
            (uuid7(), name, email, hash_pw(pw), role_id[role], dept_id[dept] if dept else None),
        )

    # ---- bulk department viewers across every department (DEMO password: viewer123) ----
    first_names = ["Emma", "Lucas", "Chloé", "Hugo", "Manon", "Louis", "Jade", "Gabriel",
                   "Alice", "Raphaël", "Inès", "Arthur", "Léna", "Nathan", "Camille",
                   "Thomas", "Sarah", "Maxime", "Julie", "Antoine", "清", "Yanis",
                   "Noor", "Diego", "Fatou", "Pierre", "Awa", "Mehdi", "Clara", "Tom"]
    last_names = ["Martin", "Bernard", "Dubois", "Robert", "Petit", "Durand", "Leroy",
                  "Moreau", "Simon", "Laurent", "Garcia", "Roux", "Vincent", "Faure",
                  "Mercier", "Blanc", "Guerin", "Muller", "Henry", "Rousseau", "Nicolas",
                  "Perrin", "Morel", "Girard", "Andre", "Lefebvre", "Mendy", "Da Silva",
                  "Boucher", "Fontaine"]
    all_depts = [d[0] for d in departments]
    viewer_password = hash_pw("viewer123")
    used_emails = set()
    rng = random.Random(42)
    n_viewers = 26
    for i in range(n_viewers):
        fn = first_names[i % len(first_names)]
        ln = last_names[(i * 7 + 3) % len(last_names)]
        dept = all_depts[i % len(all_depts)]      # round-robin → every department covered
        # build a unique ascii-ish email
        base = (fn + "." + ln).lower().replace(" ", "").replace("é", "e").replace("è", "e") \
            .replace("ç", "c").replace("清", "qing")
        email = f"{base}@remi-solar.eu"
        n = 2
        while email in used_emails:
            email = f"{base}{n}@remi-solar.eu"; n += 1
        used_emails.add(email)
        c.execute(
            "INSERT INTO users(uuid, full_name, email, password_hash, role_id, department_id) VALUES (?,?,?,?,?,?)",
            (uuid7(), f"{fn} {ln}", email, viewer_password, role_id["department_viewer"], dept_id[dept]),
        )

    # ---- sample emails + analysis + routing + reviews ----
    # (sender, subject, body, category, request_type_idx, priority, dept, confidence, status)
    samples = [
        ("b.laurent@client.fr", "Onduleur en panne — plus de production",
         "Bonjour, mon installation ne produit plus rien depuis ce matin, l'onduleur affiche une erreur.",
         "maintenance", "critical", "IT", 0.97, "routed"),
        ("facture@fournisseur.com", "Facture FA-2026-0412 échéance 30/06",
         "Veuillez trouver ci-joint la facture FA-2026-0412 d'un montant de 4 250 € à régler avant le 30/06.",
         "invoices", "high", "Finance", 0.93, "routed"),
        ("marie.dubois@gmail.com", "Demande de devis — installation 6kWc",
         "Bonjour, je souhaite un devis pour une installation photovoltaïque de 6kWc sur ma maison.",
         "lead", "medium", "Sales", 0.95, "routed"),
        ("contact@inconnu.fr", "Re: suivi dossier (pièce jointe scannée)",
         "Voir document scanné en pièce jointe concernant le dossier client.",
         "support", "low", None, 0.61, "manual_review"),
        ("rh@candidats.fr", "Candidature — technicien photovoltaïque",
         "Je vous adresse ma candidature pour le poste de technicien.",
         "support", "low", "HR", 0.88, "routed"),
        ("avocat@cabinet.fr", "Mise en demeure — contrat maintenance",
         "Par la présente, mise en demeure relative au contrat de maintenance.",
         "support", "high", None, 0.74, "manual_review"),
        ("sav@client.fr", "Intervention technique — panneau fissuré",
         "Un panneau est fissuré après la tempête, une intervention sur site est nécessaire.",
         "maintenance", "high", "Technician", 0.91, "routed"),
        ("chantier@client.fr", "Planification pose — installation 9kWc",
         "Merci de planifier la pose de l'installation 9kWc la semaine prochaine.",
         "installation", "medium", "Technician", 0.90, "routed"),
        ("notaire@etude.fr", "Contrat de maintenance — clause de révision",
         "Demande de révision d'une clause du contrat de maintenance signé l'an dernier.",
         "support", "high", "Legal", 0.87, "routed"),
        ("conformite@partenaire.fr", "Registre des traitements — conformité",
         "Question concernant le registre des traitements et la conformité du sous-traitant.",
         "support", "medium", "Legal", 0.80, "routed"),
        ("p.martin@client.fr", "Demande de devis — ombrière de parking",
         "Nous souhaitons un devis pour une ombrière photovoltaïque sur notre parking d'entreprise.",
         "lead", "medium", "Sales", 0.94, "routed"),
        ("contact@mairie-ville.fr", "Appel d'offres — toiture solaire école",
         "Veuillez répondre à notre appel d'offres pour l'installation solaire de l'école primaire.",
         "lead", "high", "Sales", 0.89, "routed"),
        ("j.bernard@client.fr", "Production en baisse depuis la mise à jour",
         "Ma production a chuté de 30% depuis la dernière mise à jour de l'onduleur.",
         "maintenance", "high", "Technician", 0.90, "routed"),
        ("sav2@client.fr", "Voyant rouge sur l'onduleur",
         "Un voyant rouge clignote sur mon onduleur, que dois-je faire ?",
         "maintenance", "medium", "IT", 0.82, "routed"),
        ("compta@fournisseur.com", "Relance facture FA-2026-0321",
         "Relance concernant la facture FA-2026-0321 impayée d'un montant de 2 980 €.",
         "invoices", "high", "Finance", 0.92, "routed"),
        ("tresorerie@client.fr", "Demande d'échéancier de paiement",
         "Pouvons-nous mettre en place un échéancier pour le règlement de notre facture ?",
         "invoices", "medium", "Finance", 0.85, "routed"),
        ("recrutement@ecole.fr", "Candidature spontanée — commercial",
         "Je vous envoie ma candidature spontanée pour un poste de commercial.",
         "support", "low", "HR", 0.86, "routed"),
        ("stage@univ.fr", "Demande de stage — ingénierie",
         "Étudiant en ingénierie, je recherche un stage de 6 mois.",
         "support", "low", "HR", 0.83, "routed"),
        ("client.mecontent@mail.fr", "Réclamation — retard d'installation",
         "Je suis très mécontent du retard de plus de deux mois sur mon installation.",
         "support", "high", None, 0.68, "manual_review"),
        ("inconnu2@mail.fr", "(sans objet)",
         "Bonjour, voir pièce jointe.",
         "support", "low", None, 0.52, "manual_review"),
        ("avocat2@cabinet.fr", "Litige contractuel — pénalités",
         "Mise en demeure concernant l'application de pénalités de retard.",
         "support", "high", "Legal", 0.79, "routed"),
        ("dpo@partenaire.fr", "Demande d'accès RGPD",
         "Un client exerce son droit d'accès à ses données personnelles (RGPD).",
         "support", "medium", "Legal", 0.81, "routed"),
        ("direction@partenaire.fr", "Proposition de partenariat",
         "Nous proposons un partenariat de distribution sur la région.",
         "support", "medium", "Directors", 0.80, "routed"),
        ("ceo@groupe.fr", "Réunion stratégique Q3",
         "Merci de planifier la réunion stratégique du troisième trimestre.",
         "support", "low", "Directors", 0.84, "routed"),
        ("chantier2@client.fr", "Pose terminée — PV de réception",
         "La pose est terminée, merci d'envoyer le procès-verbal de réception.",
         "installation", "medium", "Technician", 0.90, "routed"),
        ("client.neuf@mail.fr", "Raccordement Enedis — délai",
         "Quel est le délai pour le raccordement Enedis de mon installation ?",
         "installation", "medium", "Technician", 0.88, "routed"),
        ("a.moreau@client.fr", "Devis batterie de stockage",
         "Je souhaite ajouter une batterie de stockage à mon installation existante.",
         "lead", "medium", "Sales", 0.91, "routed"),
        ("fournisseur.x@mail.com", "Nouveau catalogue panneaux 2026",
         "Veuillez trouver notre nouveau catalogue de panneaux pour 2026.",
         "support", "low", None, 0.60, "manual_review"),
        ("urgence@client.fr", "URGENT — fumée sur coffret électrique",
         "De la fumée se dégage du coffret électrique, c'est urgent !",
         "maintenance", "critical", "Technician", 0.96, "routed"),
        ("facture3@fournisseur.com", "Avoir AV-2026-0044",
         "Émission d'un avoir AV-2026-0044 de 450 € sur votre dernière commande.",
         "invoices", "low", "Finance", 0.87, "routed"),
    ]
    ATT_INDICES = {4, 6, 11, 16, 19, 23, 28, 30}   # emails that carry an attachment

    for i, (sender, subj, body, cat, prio, dept, conf, status) in enumerate(samples, start=1):
        has_att = i in ATT_INDICES
        c.execute(
            """INSERT INTO emails(uuid, message_id, sender_email, sender_name, subject, body,
                                  received_at, status, has_attachments, storage_ref)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (uuid7(), f"<msg-{i}@remi>", sender, sender.split("@")[0], subj, body,
             iso(hours_ago=i), status, 1 if has_att else 0, f"secure://emails/{i}"),
        )
        eid = c.lastrowid
        c.execute(
            """INSERT INTO email_analysis(email_id, category_id, priority_id, priority_score,
                                          confidence, summary, model_version)
               VALUES (?,?,?,?,?,?,?)""",
            (eid, cat_id[cat], prio_id[prio], conf, conf, subj[:60], "mistral-small-latest"),
        )
        aid = c.lastrowid

        if has_att:
            c.execute(
                """INSERT INTO attachments(email_id, filename, file_type, file_size, storage_ref)
                   VALUES (?,?,?,?,?)""",
                (eid, f"piece-jointe-{i}.pdf", "pdf", 90000 + i * 1234, f"secure://emails/{i}/att.pdf"),
            )
            att_id = c.lastrowid
            c.execute(
                """INSERT INTO ocr_results(attachment_id, model_version, extracted_text, confidence, status)
                   VALUES (?,?,?,?,?)""",
                (att_id, "mistral-ocr-latest",
                 f"[OCR] Document lié à : {subj}", 0.95, "success"),
            )

        if status == "routed" and dept:
            c.execute(
                """INSERT INTO routing_assignments(email_id, analysis_id, department_id, priority_id)
                   VALUES (?,?,?,?)""",
                (eid, aid, dept_id[dept], prio_id[prio]),
            )
        if status == "manual_review":
            reason = "low_confidence" if conf < 0.70 else "flagged_topic"
            c.execute(
                "INSERT INTO review_tasks(email_id, analysis_id, reason) VALUES (?,?,?)",
                (eid, aid, reason),
            )

        c.execute(
            """INSERT INTO audit_logs(uuid, email_id, model_version, action_type, entity_type, entity_id, details)
               VALUES (?,?,?,?,?,?,?)""",
            (uuid7(), eid, "mistral-small-latest", "classification", "email_analysis", aid,
             f'{{"category":"{cat}","priority":"{prio}","confidence":{conf}}}'),
        )

        # ---- AI usage metering for this email ----
        in_tok = max(20, len((subj + body).split()) * 2)
        out_tok = 60 + (i * 7)
        c.execute(
            """INSERT INTO ai_usage_events(email_id, kind, provider, model_version,
                                           input_tokens, output_tokens, confidence)
               VALUES (?,?,?,?,?,?,?)""",
            (eid, "classification", "mistral", "mistral-small-latest", in_tok, out_tok, conf),
        )
        if has_att:
            c.execute(
                """INSERT INTO ai_usage_events(email_id, kind, provider, model_version,
                                               pages, input_tokens, output_tokens, confidence)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (eid, "ocr", "mistral", "mistral-ocr-latest", 2, 512, 320, 0.95),
            )

    # ---- bulk audit / access logs (40 extra → ~70 total with per-email logs) ----
    user_ids = [r[0] for r in c.execute("SELECT id FROM users")]
    email_ids = [r[0] for r in c.execute("SELECT id FROM emails")]
    ocr_model = "mistral-ocr-latest"
    llm_model = "mistral-small-latest"
    actions = [
        ("login", None, "users", '{"result":"success"}'),
        ("access", None, "emails", '{"view":"detail"}'),
        ("classification", llm_model, "email_analysis", '{"category":"maintenance"}'),
        ("classification", llm_model, "email_analysis", '{"category":"invoices"}'),
        ("ocr_extraction", ocr_model, "attachments", '{"pages":2}'),
        ("field_extraction", llm_model, "extracted_fields", '{"fields":3}'),
        ("routing", None, "emails", '{"dept":"Sales"}'),
        ("routing", None, "emails", '{"dept":"Technician"}'),
        ("manual_override", None, "review_tasks", '{"decision":"corrected"}'),
        ("access", None, "app_settings", '{"action":"view_settings"}'),
        ("deletion", None, "emails", '{"reason":"retention_expired"}'),
    ]
    weights = [10, 16, 8, 6, 6, 5, 7, 5, 4, 4, 2]
    bulk = []
    for _ in range(40):
        act, model, entity, details = rng.choices(actions, weights=weights, k=1)[0]
        bulk.append((
            uuid7(),
            rng.choice(email_ids) if entity in ("emails", "email_analysis", "attachments", "extracted_fields", "review_tasks") else None,
            rng.choice(user_ids), model, act, entity,
            rng.choice(email_ids), details, f"10.0.{rng.randint(0,4)}.{rng.randint(2,254)}",
            iso(days_ago=rng.randint(0, 14), hours_ago=rng.randint(0, 23)),
        ))
    c.executemany(
        """INSERT INTO audit_logs(uuid, email_id, user_id, model_version, action_type, entity_type,
                                  entity_id, details, ip_address, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""", bulk)

    # ---- retention policies ----
    c.executemany(
        "INSERT INTO retention_policies(category_id, data_type, retention_days, action, description) VALUES (?,?,?,?,?)",
        [
            (cat_id["invoices"], "email_body", 3650, "scheduled", "Invoices kept 10 years (accounting obligation)."),
            (cat_id["lead"], "email_body", 365, "automated", "Leads kept 1 year then anonymised."),
            (None, "attachment", 730, "automated", "Attachments purged after 2 years."),
            (None, "log", 1825, "scheduled", "Audit logs retained 5 years."),
        ],
    )

    con.commit()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true", help="Drop and recreate the database.")
    args = parser.parse_args()

    if os.path.exists(DB_PATH) and args.reset:
        os.remove(DB_PATH)
    if os.path.exists(DB_PATH):
        print(f"Database already exists at {DB_PATH}. Use --reset to rebuild.")
        return

    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA foreign_keys = ON;")
    with open(SCHEMA, encoding="utf-8") as f:
        con.executescript(f.read())
    seed(con)
    con.close()

    print(f"\nDatabase created at {DB_PATH}\n")
    print("Demo accounts (email / password / role):")
    print("-" * 64)
    print("  admin@remi-solar.eu    / admin123    / Global admin (Niels Tilch)")
    print("  sales@remi-solar.eu    / sales123    / Department viewer (Sales)")
    print("  finance@remi-solar.eu  / finance123  / Department viewer (Finance)")
    print("  audit@remi-solar.eu    / audit123    / Audit admin")
    print("  verify@remi-solar.eu   / verify123   / Verification admin")
    print("  mail@remi-solar.eu     / mail123     / Email admin")
    print("  + 26 department viewers across all 7 departments  / viewer123")
    print("-" * 64)


if __name__ == "__main__":
    main()
