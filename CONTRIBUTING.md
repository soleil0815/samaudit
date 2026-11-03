# Contributing to SAMAUDIT

*Deutsche Fassung unten.*

Thanks for your interest! SAMAUDIT is a hobby project maintained in spare time – contributions are welcome, but there are no promised response times.

## Reporting bugs and ideas

- Use the issue forms (**Issues → New issue**). Mention the SAMAUDIT version (shown under **Help**), Windows AD or Samba AD, and what you expected.
- **Never post real data** from your domain: no screenshots of real reports, no account or server names, no IP addresses, no passwords, no exported PDFs. Demo mode (`DEMO_MODE=true`) is ideal for showing a problem.
- **Security vulnerabilities in SAMAUDIT itself** do not belong in a public issue – please follow [SECURITY.md](SECURITY.md).

## Pull requests

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Keep changes focused; add or adjust tests in `tests/`.
3. The checks must pass locally and on GitHub:
   ```bash
   pip install --require-hashes -r requirements.txt -r requirements-dev.txt
   ruff check app tests tools run.py
   mypy
   python -m unittest discover -s tests -p 'test_*.py'
   python tests/smoke.py
   ```
4. Texts appear in German and English – please provide both (a rough translation is fine).
5. New security checks: describe the attack technique with a public reference (Microsoft, MITRE ATT&CK, vendor research). **Do not copy** texts, rule logic or code from other tools; write it yourself.
6. Pull requests are reviewed and merged by the maintainer – never automatically.

## Developer Certificate of Origin (DCO)

SAMAUDIT is licensed under the **AGPL-3.0-or-later**. By contributing you agree that your contribution is published under the same licence. To confirm that you have the right to submit it, sign off every commit (`git commit -s`), which adds a line like:

```
Signed-off-by: Your Name <your.address@example.com>
```

This certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/). You may use a pseudonym and your GitHub noreply address.

---

# Mitmachen bei SAMAUDIT

Danke für Ihr Interesse! SAMAUDIT ist ein Hobbyprojekt, das in der Freizeit gepflegt wird – Beiträge sind willkommen, Reaktionszeiten werden aber nicht zugesagt.

- **Fehler und Ideen:** über die Formulare unter **Issues → New issue**, mit SAMAUDIT-Version (unter **Hilfe**), Windows AD oder Samba AD und was Sie erwartet hätten.
- **Niemals echte Daten** aus Ihrer Domäne veröffentlichen: keine Bildschirmfotos echter Berichte, keine Konto- oder Servernamen, keine IP-Adressen, keine Kennwörter, keine PDF-Berichte. Zum Zeigen eignet sich der Demo-Modus (`DEMO_MODE=true`).
- **Sicherheitslücken in SAMAUDIT selbst** bitte nicht öffentlich melden, sondern wie in [SECURITY.md](SECURITY.md) beschrieben.
- **Pull Requests:** bei größeren Änderungen vorher ein Issue anlegen; Tests ergänzen; die Prüfungen oben müssen grün sein; Texte auf Deutsch und Englisch. Neue Prüfungen mit öffentlicher Quelle selbst formulieren – **keine** Texte, Regeln oder Code anderer Werkzeuge übernehmen. Zusammengeführt wird nur vom Projektbetreuer, nie automatisch.
- **DCO:** Mit einem Beitrag stimmen Sie zu, dass er unter der AGPL-3.0-or-later veröffentlicht wird. Bitte jeden Commit mit `git commit -s` abzeichnen (`Signed-off-by: …`, Developer Certificate of Origin 1.1). Ein Pseudonym und die GitHub-noreply-Adresse genügen.
