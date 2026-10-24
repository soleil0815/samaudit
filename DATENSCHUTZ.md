# Datenschutz bei SAMAUDIT

> **Wichtig:** Keine Software ist für sich allein „DSGVO-konform“. Verantwortlich für die Einhaltung der DSGVO ist, wer SAMAUDIT betreibt (Art. 24 DSGVO). SAMAUDIT ist nach dem Prinzip *Datenschutz durch Technikgestaltung und datenschutzfreundliche Voreinstellungen* (Art. 25 DSGVO) gebaut und liefert hier die Unterlagen, die Sie für Ihre Dokumentation brauchen. Dies ist keine Rechtsberatung – stimmen Sie den Einsatz mit Ihrer bzw. Ihrem Datenschutzbeauftragten ab.

## 1. Was SAMAUDIT technisch dafür tut

| Maßnahme | Umsetzung in SAMAUDIT |
|---|---|
| **Keine Datenübermittlung nach außen** | Keine externen Schriften, Skripte, CDNs, Analyse- oder Tracking-Dienste; Content-Security-Policy erlaubt nur eigene Inhalte. |
| **Ausgehende Verbindungen** | Programminterner Wächter (`EGRESS_GUARD`): SAMAUDIT verbindet sich nur zu den DCs, jede andere ausgehende Verbindung wird abgewiesen und protokolliert. Optional zusätzlich eigene Firewall-Regeln für das Docker-Netz `samaudit-net`. |
| **Datenminimierung** | Es werden nur sicherheitsrelevante Attribute gelesen. **Keine** Passwörter, Passwort-Hashes, LAPS-Passwörter, E-Mail-Inhalte oder Telefonnummern. Gespeichert werden in Befunden nur Kontonamen, Zeitpunkte und technische Merkmale. |
| **Speicherbegrenzung** | Automatische Löschung: Berichte nach `REPORT_RETENTION_DAYS` (Standard 365 Tage), Protokoll nach `AUDIT_RETENTION_DAYS` (Standard 90 Tage). Gelöschte Daten werden auch physisch aus der Datenbankdatei entfernt (VACUUM). Container-Logs sind auf 3 × 5 MB begrenzt. |
| **Zugriffskontrolle** | Nur Mitglieder der Prüfer-Gruppe; Admin-Konten werden abgewiesen. Sperre nach Fehlversuchen, Sitzungs-Timeout, CSRF-Schutz. |
| **Vertraulichkeit** | HTTPS; Passwort der Prüfer nur verschlüsselt im Arbeitsspeicher; Datenordner nur für den Programmbenutzer lesbar (`chmod 700`); Container ohne Root-Rechte, schreibgeschützt. |
| **Nachvollziehbarkeit** | Protokoll aller Anmeldungen (auch abgewiesener), Scans, Exporte, Löschungen und blockierten Verbindungen. |
| **Cookies** | Nur technisch notwendige (Sitzung, CSRF, Sprache, zuletzt gesehene Version der Neuigkeiten) – kein Einwilligungsbanner erforderlich (§ 25 Abs. 2 TDDDG). |
| **Transparenz** | Öffentliche Seite `/privacy` („Datenschutz“) mit Zweck, Datenarten, Speicherdauer und Rechten; Kontakt über `PRIVACY_CONTACT`. |
| **Löschung auf Anforderung** | Einzelne Berichte unter „Berichte“ löschbar; vollständige Löschung durch Entfernen des Ordners `data`. |

## 2. Vorlage für das Verzeichnis von Verarbeitungstätigkeiten (Art. 30 DSGVO)

| Feld | Eintrag (anpassen) |
|---|---|
| Bezeichnung | Sicherheitsprüfung des Active Directory mit SAMAUDIT |
| Verantwortlicher | *Name/Anschrift Ihrer Organisation* |
| Datenschutzbeauftragte/r | *Kontakt* |
| Zweck | Erkennen und Beheben von Sicherheitsschwachstellen im Verzeichnisdienst (IT-Sicherheit) |
| Rechtsgrundlage | *mit DSB festlegen* – typischerweise Art. 6 Abs. 1 lit. c i. V. m. Art. 32 DSGVO (Pflicht zur Sicherheit der Verarbeitung) und/oder Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse an IT-Sicherheit); im Beschäftigtenkontext ggf. Betriebs-/Dienstvereinbarung |
| Betroffene | Beschäftigte und sonstige Personen mit Konto im Active Directory; Prüfer (Nutzer von SAMAUDIT) |
| Datenkategorien | Kontoname, Anzeigename (nur bei Prüfern), Gruppenmitgliedschaften, Zeitpunkt letzte Anmeldung/Passwortänderung, Konto-Einstellungen, Computername/Betriebssystem; bei Prüfern zusätzlich IP-Adresse und Zeitpunkt der Nutzung |
| Besondere Kategorien (Art. 9) | keine |
| Empfänger | nur Mitglieder der Prüfer-Gruppe; keine externen Empfänger |
| Drittlandübermittlung | keine |
| Löschfristen | Berichte *365* Tage, Protokoll *90* Tage, Sitzungen max. 12 Stunden |
| Technische und organisatorische Maßnahmen | siehe Abschnitt 1 und 4 |

## 3. Vor dem Einsatz klären (Checkliste)

- [ ] **Datenschutzbeauftragte/n** einbinden, Rechtsgrundlage und Zweck festlegen, Eintrag ins Verzeichnis (Abschnitt 2).
- [ ] **Betriebs-/Personalrat:** SAMAUDIT zeigt u. a. Zeitpunkte der letzten Anmeldung. Das kann als technische Einrichtung gelten, die zur Verhaltens- oder Leistungskontrolle *geeignet* ist (§ 87 Abs. 1 Nr. 6 BetrVG bzw. Personalvertretungsrecht). Die Mitbestimmung vorher klären; ggf. Zweckbindung „ausschließlich IT-Sicherheit, keine Leistungs- oder Verhaltenskontrolle“ vereinbaren.
- [ ] **Datenschutz-Folgenabschätzung (Art. 35):** in der Regel nicht erforderlich (keine Profilbildung, keine systematische Überwachung), aber die Prüfung dokumentieren.
- [ ] **Prüfer-Gruppe** klein halten und regelmäßig überprüfen.
- [ ] **Löschfristen** an Ihr Löschkonzept anpassen (`REPORT_RETENTION_DAYS`, `AUDIT_RETENTION_DAYS`).
- [ ] **`PRIVACY_CONTACT`** in der `.env` setzen, damit die Datenschutzseite die richtige Stelle nennt.
- [ ] **PDF-Exporte und Sicherungen** unterliegen denselben Fristen – nicht unkontrolliert ablegen oder versenden.
- [ ] Auftragsverarbeitungsvertrag: **nicht nötig**, solange Sie SAMAUDIT selbst betreiben (keine Daten an Dritte). Betreibt ein Dienstleister den Server, ist ein AV-Vertrag (Art. 28) erforderlich.

## 4. Empfehlungen für den Betrieb

- Programminterne Sperre aktiv lassen (`EGRESS_GUARD=true`); bei Bedarf den Container zusätzlich mit der eigenen Firewall abschotten.
- Festplatte des Docker-Hosts verschlüsseln (z. B. LUKS), da die Datenbank selbst nicht verschlüsselt ist.
- Zugriff auf den Docker-Host (SSH, sudo) auf wenige Administratoren beschränken – wer Root auf dem Host hat, kann den Ordner `data` lesen.
- Eigenes TLS-Zertifikat aus Ihrer CA verwenden statt des selbstsignierten.
- Sicherungen des Ordners `data` verschlüsseln und mit derselben Frist löschen.
