# Shush — copy you can ship

Ready-to-paste pitches for different channels. All say the same true thing: **you leak private data into ChatGPT/Claude every day, and this stops it in one command, on your own machine.** Pick the one that fits the surface.

---

## One-liner (the hook)

> **Shush** — strip PII and secrets from any file before you paste it into an LLM. One command. 100% local. No AI, no network, no signup.

Alt one-liners:
- "The `.gitignore` for your ChatGPT prompts."
- "You wouldn't commit your `.env`. Stop pasting it into ChatGPT."
- "89 detectors. Zero data leaves your laptop. MIT."

---

## The problem (lead with the pain — it's real and universal)

Every day, developers and support teams paste real data into ChatGPT, Claude, and Copilot to "get help" or "summarize this":

- customer support exports
- server logs and stack traces
- database dumps and CSVs
- `.env` files "just to debug the config"

And they quietly hand over emails, IP addresses, passwords, API keys, credit cards, and national IDs to a third party. Under GDPR (EU), DPDP (India), LGPD (Brazil), CCPA (US), or a dozen other privacy laws, **that's a reportable data breach** — and most people doing it have no idea.

The usual "fix" is a policy doc no one reads, or an enterprise DLP tool that costs five figures and needs a security team to run.

## The fix (one paragraph)

**Shush** is a single Python file you run before you share. Point it at a file, a folder, or a zip. It finds every sensitive value with a battle-tested regex database — 89 detectors modelled on Microsoft Presidio, AWS Comprehend, Google Cloud DLP, and HIPAA's 18 identifiers — and swaps each one for a typed placeholder: `[EMAIL]`, `[IP]`, `[API_KEY]`, `[US_SSN]`. The sentence still reads perfectly, so the LLM still understands it. The identity is gone. **Nothing ever touches a network or an AI model** — you can read the whole tool in five minutes.

```
"SSL failed for acme.com from 8.8.8.8, user sarah@acme.com"
      ↓  python shush.py ticket.txt
"SSL failed for [DOMAIN] from [IPV4], user [EMAIL]"
```

---

## Why it wins (the differentiators, ranked)

1. **Local by construction, not by promise.** It's plain regex. There's no API call to trust, no telemetry to opt out of, no cloud to breach. Air-gap it and it still works.
2. **Zero friction.** One file, no install, no config, works on Python 3.8+. `git clone` → run. Docx works out of the box; `pip install pypdf openpyxl` adds PDF/Excel.
3. **Fail-closed.** When a value is ambiguous, it redacts. Over-redaction is safe; a leak is not — the opposite bias of "smart" AI redactors that miss things to look clean.
4. **Not a black box.** Every rule is a readable regex you can audit, extend, and PR. Enterprise DLP is a vendor you rent; Shush is a tool you own.
5. **Fits where the leak happens.** File, folder, or zip → clean copy + a JSON report of exactly what was removed. Drop it in a pre-commit hook, a CI step, or a support-team runbook.

---

## Show HN post

**Title:** Show HN: Shush – strip PII/secrets from any file before you paste it into an LLM

**Body:**

I kept watching people (including me) paste support tickets, logs, and `.env` files straight into ChatGPT to "get help fast" — and hand over customer emails, IPs, API keys, and card numbers to a third party without thinking. Under GDPR/HIPAA that's a breach.

Existing options were either a policy doc nobody follows or an enterprise DLP suite that costs a fortune and needs a security team. I wanted something a solo dev or a support agent could run in one command, offline, and actually trust — because they can read the whole thing.

So: **Shush**. A single Python file, stdlib-only for text/docx, no network, no AI. It has 89 regex detectors (modelled on Presidio / AWS Comprehend / Google DLP / HIPAA-18) covering emails, IPs, keys, cards, CVV/PIN, national IDs from 20+ countries, medical record numbers, GPS coords, and more. It replaces each hit with a typed placeholder (`[EMAIL]`, `[US_SSN]`) so the text still makes sense to the model. Point it at a file, folder, or zip; get a clean copy + a report of what was pulled.

It's fail-closed on purpose (redacts when unsure), and it's MIT. The honest limitation: regex nails *structured* PII (emails, keys, cards, IDs) but can't guarantee every free-form name in prose — so it catches names in salutations/labels and tells you to spot-check. Not a replacement for a compliance review, but it turns "I pasted the raw dump" into "I pasted the scrubbed dump" — which is the whole ballgame.

Repo: https://github.com/adityaarsharma/shush — patterns for more countries/vendors very welcome.

---

## Product Hunt tagline + description

**Tagline:** Redact PII & secrets before you feed files to AI — 100% local

**Description:**
Shush is the missing safety step between your files and ChatGPT/Claude/Copilot. Run one command on a file, folder, or zip and every email, IP, password, API key, credit card, and national ID becomes a clean placeholder — while the text stays readable so the AI still understands it. No network, no AI, no signup: it's a single auditable Python file with 89 detectors built from the same taxonomies enterprise DLP uses. Fail-closed, MIT-licensed, and small enough to read in five minutes. Stop leaking customer data to third parties by accident.

---

## X / Twitter thread

**1/**
You paste support tickets and logs into ChatGPT to "get help."
You just sent a stranger your customers' emails, IPs, and passwords.
Under GDPR that's a breach.

I built a one-command fix. It's free. 🧵

**2/**
Meet **Shush**: point it at a file, folder, or zip →
it swaps every email / IP / key / card / SSN for a clean `[LABEL]`
→ the text still reads fine, so the AI still gets it.

`python shush.py dump.zip clean`

**3/**
The part that matters: **it never touches the network.**
No API. No AI. No telemetry. Just 89 regex detectors you can read in 5 minutes.
Air-gap your laptop and it still works.

**4/**
Coverage is modelled on Presidio, AWS Comprehend, Google DLP, and HIPAA-18:
emails · IPs · API keys (AWS/GCP/Stripe/OpenAI…) · cards + CVV · passwords
national IDs for 20+ countries · medical record #s · GPS · VIN · more.

**5/**
It's **fail-closed** — unsure? it redacts. Over-redaction is safe; a leak isn't.
Single file. Python 3.8+. MIT. Drop it in a pre-commit hook.

git clone → run. Add patterns via PR: https://github.com/adityaarsharma/shush
https://github.com/adityaarsharma/shush

---

## Elevator pitch (spoken, 15 seconds)

"You know how everyone pastes logs and support tickets into ChatGPT now? They're leaking customer data to a third party every time — GDPR breach, and they don't even know. Shush is a one-command, fully offline tool that strips all of it — emails, keys, cards, IDs — before it ever leaves your machine. Free, single file, you can read the whole thing."

---

## Honest-limitations line (always include it — it builds trust and it's true)

> Shush catches *structured* PII reliably (emails, IPs, keys, cards, IDs). Free-form names buried in prose are the one thing regex can't guarantee — it catches them in salutations and labels, and tells you to spot-check the rest. It reduces risk dramatically; it isn't a substitute for a compliance review on regulated data.

Leading with the limitation is a feature. The tools that claim to catch *everything* are the ones nobody who's been burned will trust.
