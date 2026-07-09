<h1 align="center">🤫 Shush</h1>

<p align="center"><b>Hush your files before you hand them to an AI.</b><br>
Strip PII &amp; secrets from any file before you paste it into ChatGPT, Claude, Gemini, or Copilot.<br>
100% local · no network · no AI · no signup.</p>

<p align="center">
  <img src="https://github.com/adityaarsharma/shush/actions/workflows/ci.yml/badge.svg" alt="tests">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/python-3.8+-blue" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/dependencies-0_core-brightgreen" alt="Zero core dependencies">
  <img src="https://img.shields.io/badge/detectors-89-orange" alt="89 detectors">
  <img src="https://img.shields.io/badge/network-none-red" alt="No network">
</p>

---

> **You wouldn't commit your `.env` to GitHub. Stop pasting it into ChatGPT.**

A free command-line tool that strips personal data, passwords, and API keys out of your files before you share them with an LLM. Point it at a file, folder, or zip — get a clean copy back. Nothing ever leaves your machine.

Shush is a **terminal command** (not a chatbot, not a website). You run it on your own computer — Mac Terminal, Windows PowerShell, or Linux shell. It reads a file, a folder, or a zip, replaces every sensitive value with a safe placeholder like `[EMAIL]`, `[IP]`, `[API_KEY]`, `[NATIONAL_ID]`, and writes a clean copy you can safely paste into **ChatGPT, Claude, Gemini, Copilot, DeepSeek, or a local Llama model.** Nothing ever leaves your machine.

**Keywords:** PII redaction · data anonymization · remove sensitive data before AI · sanitize logs for ChatGPT · strip API keys · GDPR · India DPDP · LGPD · CCPA · PDPA · POPIA · PIPL · HIPAA · secret scanner · CLI · offline · privacy.

---

## Why you need this (the real, everyday problem)

Every day, developers and support teams paste real data into AI tools to *"summarize this"* or *"help me fix this"* — and hand a third-party company their customers' private data without realizing it.

Here's what people actually dump into ChatGPT, and what leaks each time:

| What people paste into AI | What secretly leaks | Shush replaces it with |
|---|---|---|
| **A support ticket** ("customer can't log in…") | customer name, email, phone, order/account ID, sometimes their password | `[NAME] [EMAIL] [PHONE] [USER_ID] [PASSWORD]` |
| **A server / error log** | IP addresses, file paths, hostnames, session tokens | `[IPV4] [FILE_PATH] [DOMAIN] [JWT]` |
| **A database dump / CSV export** | thousands of emails, phones, national IDs, card numbers | `[EMAIL] [PHONE] [NATIONAL_ID] [CREDIT_CARD]` |
| **A `.env` or config file** | DB passwords, AWS/Stripe/OpenAI keys, connection strings | `[PASSWORD] [AWS_KEY] [DB_URL] [OPENAI_KEY]` |
| **A stack trace / bug report** | internal URLs, auth headers, user records | `[URL] [GENERIC_KEY] [EMAIL]` |
| **A spreadsheet of customers / leads** | names, emails, phones, addresses, tax IDs | `[NAME] [EMAIL] [PHONE] [STREET_ADDR] [TAX_ID]` |
| **A copied email thread** | sender/recipient identities, signatures, phone numbers | `[NAME] [EMAIL] [PHONE]` |

Under data-protection laws almost everywhere — the EU's **GDPR**, India's **DPDP Act**, Brazil's **LGPD**, California's **CCPA/CPRA**, and a dozen more (full list below) — sending that data to a third party can be a reportable breach. Most people doing it have no idea. The usual "fix" is a policy nobody reads, or an enterprise DLP suite that costs five figures. Shush is the one-command version you can run yourself, offline, and actually read in five minutes.

---

## What it removes — 89 detectors across 20+ countries

Modelled on the taxonomies used by Microsoft Presidio, AWS Comprehend, Google Cloud DLP, and HIPAA's 18 identifiers — then deliberately extended so it works for people everywhere, not only in the countries those tools were built around. National IDs are listed **A–Z by country**; no jurisdiction gets special billing.

| Category | Examples caught |
|---|---|
| **Contact / personal** | emails, intl phone numbers, names (salutations & `From:/Name:` labels), dates of birth, age, usernames/logins, street addresses, ZIP/postal codes |
| **Network / infra** | IPv4, IPv6, MAC addresses, URLs, domains, file paths (`/home/…`, `C:\Users\…`), GPS coordinates |
| **Credentials** | passwords, API keys, bearer/OAuth tokens, JWTs, SSH & PGP private keys, `.env` secrets, DB connection strings |
| **Cloud keys** | AWS, GCP, GitHub, Slack, Stripe, OpenAI, Twilio, SendGrid, Google OAuth |
| **Financial** | credit cards, CVV, PIN, IBAN, SWIFT/BIC, bank account & routing numbers, BTC & ETH addresses |
| **National IDs (A–Z)** | 🇦🇺 Australia (TFN, ABN) · 🇧🇩 Bangladesh (NID) · 🇧🇷 Brazil (CPF, CNPJ) · 🇨🇦 Canada (SIN) · 🇨🇳 China (resident ID) · 🇫🇷 France (INSEE/NIR) · 🇮🇳 India (Aadhaar, PAN, + 4 more) · 🇮🇩 Indonesia (NIK/KTP) · 🇮🇹 Italy (Codice Fiscale) · 🇯🇵 Japan (My Number) · 🇲🇽 Mexico (CURP, RFC) · 🇳🇬 Nigeria (NIN, BVN) · 🇵🇰 Pakistan (CNIC) · 🇸🇬 Singapore (NRIC) · 🇿🇦 South Africa (ID) · 🇰🇷 South Korea (RRN) · 🇪🇸 Spain (NIF/DNI) · 🇹🇷 Türkiye (TC Kimlik) · 🇦🇪 UAE (Emirates ID) · 🇬🇧 UK (NHS, National Insurance) · 🇺🇸 USA (SSN, ITIN) · + generic passport / driver's licence / tax ID |
| **Health** | Medicare number, medical record number (MRN), patient ID |
| **Vehicle / device** | VIN, licence plates, IMEI |
| **Identifiers** | UUIDs, user/customer IDs, long numeric IDs |

Bias is **fail-closed**: when a value is ambiguous, it redacts. Over-redaction is safe; a leak is not.

Don't see your country's ID? [Open an issue or PR](https://github.com/adityaarsharma/shush/issues) — adding one is a single line + a test. The goal is genuinely global coverage.

---

## Legal & compliance

Nearly every country now has a data-protection law that makes you responsible for personal data you hold — and pasting it into a third-party AI service is a *disclosure* to that service. Shush is a practical **technical safeguard** ("data minimisation" / "pseudonymisation") that helps you avoid that disclosure in the first place. Laws it's relevant to, A–Z by region:

| Region | Law | Shush helps you with |
|---|---|---|
| 🇦🇺 Australia | Privacy Act 1988 / Australian Privacy Principles | not disclosing personal information to an overseas processor |
| 🇧🇷 Brazil | **LGPD** (Lei Geral de Proteção de Dados) | minimising personal data before third-party processing |
| 🇨🇦 Canada | **PIPEDA** | limiting collection/disclosure to third parties |
| 🇨🇳 China | **PIPL** (Personal Information Protection Law) | avoiding cross-border transfer of personal information |
| 🇪🇺 EU / 🇬🇧 UK | **GDPR** / UK GDPR | data minimisation (Art. 5), pseudonymisation (Art. 32) |
| 🇮🇳 India | **DPDP Act 2023** | limiting processing of personal data by a Data Fiduciary |
| 🇯🇵 Japan | **APPI** | restricting third-party provision of personal data |
| 🇰🇷 South Korea | **PIPA** | limiting provision of personal information to third parties |
| 🇳🇬 Nigeria | **NDPA 2023** | lawful, minimised processing of personal data |
| 🇸🇬 Singapore | **PDPA** | limiting disclosure and cross-border transfer |
| 🇿🇦 South Africa | **POPIA** | minimality + limiting further processing |
| 🇦🇪 UAE | **PDPL** | controlling cross-border personal-data transfers |
| 🇺🇸 USA | **CCPA/CPRA** (California), **HIPAA** (health), **GLBA** (financial) | not sharing personal/health/financial data with a third party |

> **Not legal advice, and not a compliance certification.** Shush is an engineering control that *reduces* risk by keeping sensitive data on your machine. It does not make you compliant on its own, and — because free-form data is messy — it cannot guarantee 100% capture. For regulated data (health, financial, children's, biometric, or any large-scale personal data), have your privacy/DPO/compliance owner review your process, and always spot-check Shush's output before sharing. Use of this tool is at your own risk, under the [MIT license](LICENSE) (provided "as is", no warranty).

---

## How to run it in your terminal (step by step)

Shush runs in a **terminal / command line**. You don't install an app or sign into anything. If you've never used a terminal, follow your OS below exactly.

### Step 0 — Check you have Python (once)

Shush needs Python 3.8 or newer (Macs and most Linux already have it).

```bash
python3 --version
```

If that prints something like `Python 3.11.x`, you're ready. If it says "command not found", install Python from [python.org/downloads](https://www.python.org/downloads/) (on Windows, tick **"Add Python to PATH"** during install).

### 🍎 macOS — Terminal or iTerm

1. Open **Terminal** (press `Cmd + Space`, type "Terminal", hit Enter). iTerm works identically.
2. Get Shush and go into its folder:
   ```bash
   git clone https://github.com/adityaarsharma/shush.git
   cd shush
   ```
   (No git? Download the ZIP from GitHub, unzip it, then in Terminal type `cd ` and drag the unzipped folder onto the window.)
3. Run it on your file:
   ```bash
   python3 shush.py ~/Downloads/support-ticket.docx
   ```
   You'll get `support-ticket.scrubbed.txt` right next to it — that's the safe copy.

### 🪟 Windows — PowerShell or Command Prompt

1. Open **PowerShell** (Start menu → type "PowerShell" → Enter).
2. Get Shush:
   ```powershell
   git clone https://github.com/adityaarsharma/shush.git
   cd shush
   ```
3. Run it (on Windows the command is usually `python`, not `python3`):
   ```powershell
   python shush.py C:\Users\You\Downloads\export.csv
   ```

### 🐧 Linux — any shell

```bash
git clone https://github.com/adityaarsharma/shush.git && cd shush
python3 shush.py /path/to/logs.txt
```

### The four ways to use it

```bash
python3 shush.py ticket.docx                 # one file  -> ticket.scrubbed.txt
python3 shush.py ./exports  ./clean          # a whole folder (recurses) -> ./clean
python3 shush.py company-dump.zip  clean     # a zip      -> clean.zip
python3 shush.py data.csv --report           # DRY RUN: just show what it WOULD remove, write nothing
```

Then open the `.scrubbed` copy, **spot-check it**, and paste *that* into ChatGPT / Claude / any LLM. Done.

> 💡 **Tip:** run `--report` first on a sensitive file to see the counts of what it found before you trust the output.

---

## Supported file types

Works out of the box with **no extra install** (Python standard library only):

`.txt .md .log .csv .tsv .json .yaml .yml .html .xml .ini .conf .env .sql` and common source files, plus **`.docx`** (Word).

Add PDF and Excel with one command:

```bash
pip install pypdf openpyxl     # enables .pdf and .xlsx
```

Zip in → zip out. Folders recurse. Unreadable files are **skipped, never emitted raw** (fail-closed).

---

## What a run looks like

Input (`ticket.txt`):
```
From: Sarah Johnson <sarah.j@acmecorp.com>
Customer ID: 88452019
Server 10.0.0.42 at /home/deploy/app is down.
DB: postgres://admin:s3cr3tpass@db.internal:5432/prod
Card 4111 1111 1111 1111.  CVV: 123
Password: hunter2secret
```

Command:
```bash
python3 shush.py ticket.txt --report
```

Output (`ticket.scrubbed.txt`):
```
From: [NAME] <[EMAIL]>
[USER_ID]
Server [IPV4] at [FILE_PATH] is down.
DB: [DB_URL]
Card [CARD_SPACED].  [CVV]
[PASSWORD]
```

The sentence still makes sense to the AI — *"a server is down, a card payment failed"* — but every identity is gone. It also writes a `_shush_report.json` listing exactly what was removed.

---

## How it works (and why it's safe)

1. **Extract** the plain text from each file (Word/PDF/Excel formatting is discarded).
2. **Redact** every match, swapping it for a **sentinel** so a later pattern can never re-match an already-inserted placeholder.
3. **Restore** sentinels to readable `[LABEL]` placeholders.
4. **Write** the clean copy + a JSON report of what was removed.

Because it's plain regex running locally, **your data never touches a network or an AI model.** No API key, no telemetry, no cloud. Air-gap your laptop and it still works. You can read the entire tool in a few minutes — no black box.

---

## Honest limitations (read this — it's why you can trust it)

- **Regex, not magic.** It catches *structured* PII reliably (emails, IPs, keys, cards, national IDs). Free-form names buried in prose are the one thing regex can't guarantee — it catches names in salutations and `From:/Name:` labels, and you should **spot-check** the output before sharing anything sensitive.
- **Not legal advice.** This is an engineering tool that dramatically reduces risk. For regulated data (health, financial, children's, biometric, or any personal data under GDPR / DPDP / LGPD / CCPA / and the rest), have your privacy/compliance owner review before sharing externally.
- Tools that claim to catch *everything* are the ones nobody who's been burned will trust. Shush tells you exactly what it did.

---

## FAQ

### How do I remove personal data before pasting into ChatGPT?
Run Shush on the file first: `python3 shush.py yourfile.txt`. It writes a `.scrubbed.txt` copy with every email, phone, ID, key, and card replaced by a placeholder. Paste *that* into ChatGPT instead of the original.

### Is it safe to paste support tickets or logs into ChatGPT / Claude?
Not as-is — tickets and logs almost always contain customer emails, IPs, and sometimes passwords or keys, and pasting them sends that data to a third party. Scrub them first so only the redacted version leaves your machine.

### Does Shush send my data anywhere?
No. It's plain regex running locally — no network calls, no API key, no telemetry, no cloud. Turn off your Wi-Fi and it still works.

### How is this different from an enterprise DLP tool?
DLP suites cost five figures, need a security team, and run as a black box you rent. Shush is a single ~600-line Python file you can read in five minutes, own, and extend — free, MIT-licensed.

### Does it work with local LLMs like Llama or Ollama?
Yes. Shush doesn't care which model you use — it cleans the file *before* it reaches any AI, ChatGPT / Claude / Gemini / Copilot / a local model alike.

### Which countries' IDs does it detect?
20+ so far — see the [detector table](#what-it-removes--89-detectors-across-20-countries) above. Missing yours? It's a one-line PR.

---

## Development & tests

There's a full stdlib test suite (no pytest needed) — because for a redaction tool, a regression *is* a leak. Every test asserts both that the secret is gone **and** that it got the right label.

```bash
python3 -m unittest discover -s tests -v     # 38 tests, runs in <1s
```

CI runs the suite + a live CLI smoke test on Python 3.8–3.12 on every push and PR.

## Contribute a pattern (especially your country's IDs)

Found a PII type it misses — a national ID, a bank format, a vendor key? Add one line to `PATTERNS` in `shush.py`, add a test case in `tests/test_shush.py`, and open a PR. Coverage for more countries is explicitly welcome — the goal is a redaction tool that works for the whole world, wherever you and your users happen to be.

---

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it inside your company. If it stops one data leak, it did its job.
