#!/usr/bin/env python3
"""
Shush — hush your files before you hand them to an AI.

Strip PII & secrets from any file before you paste it into ChatGPT, Claude,
Gemini, Copilot, or a local model. 100% local. No network. No AI. Just a big,
well-tested regex database that replaces sensitive data with typed placeholders
(e.g. [EMAIL], [IP], [API_KEY], [AADHAAR_IN]) while leaving the text intact.

Point it at a file, a folder, or a zip. Get a clean copy + a report of what
was removed. Nothing ever leaves your machine.

    python shush.py <input> [output]

    python shush.py report.docx                 # -> report.scrubbed.txt
    python shush.py ./exports  ./clean          # a whole folder
    python shush.py dump.zip   clean            # -> clean.zip
    python shush.py data.csv --report           # print what was found

Supported inputs: .txt .md .log .csv .json .html .xml .yaml .docx  (+ .pdf, .xlsx if extras installed)
Zip in -> zip out. Folders recurse. Fail-closed: unreadable files are skipped, never emitted raw.

Repo: https://github.com/adityaarsharma/shush
License: MIT.  Contributions of new PII patterns welcome — especially your country's IDs.
"""
import os, re, sys, zipfile, html, json, tempfile, argparse
from collections import Counter

# ===========================================================================
# THE PII / SECRETS DATABASE
# Ordered most-specific first. Each entry: (LABEL, compiled regex).
# Group-capturing patterns replace only group(1) (keeps the prefix word).
# Bias is fail-closed: when in doubt, redact. Over-redaction is safe; a leak is not.
# ===========================================================================
def _c(p, flags=0): return re.compile(p, flags)
I = re.IGNORECASE

PATTERNS = [
    # ---- private keys & credential blocks (multi-line) -------------------
    ("PRIVATE_KEY",  _c(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----")),
    ("PGP_KEY",      _c(r"-----BEGIN PGP [A-Z ]+-----[\s\S]+?-----END PGP [A-Z ]+-----")),
    ("SSH_PUBKEY",   _c(r"ssh-(?:rsa|ed25519|dss|ecdsa)\s+[A-Za-z0-9+/=]{20,}(?:\s+\S+)?")),
    # ---- cloud / service API keys (specific formats) --------------------
    ("AWS_KEY",      _c(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b")),
    ("AWS_SECRET",   _c(r"(?i)\baws_secret[_a-z]*\s*[:=]\s*[A-Za-z0-9/+=]{40}\b")),
    ("GCP_KEY",      _c(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("GITHUB_TOKEN", _c(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("SLACK_TOKEN",  _c(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("STRIPE_KEY",   _c(r"\b(?:sk|pk|rk)_(?:test|live)_[A-Za-z0-9]{16,}\b")),
    ("OPENAI_KEY",   _c(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("GOOGLE_OAUTH", _c(r"\bya29\.[A-Za-z0-9_\-]{20,}\b")),
    ("TWILIO_KEY",   _c(r"\bSK[0-9a-fA-F]{32}\b")),
    ("SENDGRID_KEY", _c(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("JWT",          _c(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("GENERIC_KEY",  _c(r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|bearer)\b\s*[:=]?\s*[A-Za-z0-9/+_\-]{16,}")),
    # ---- passwords / connection strings ---------------------------------
    ("PASSWORD",     _c(r"(?i)\b(?:pass(?:word|wd)?|pwd|passphrase|credential)\b\s*[:=]\s*\S{3,}")),
    ("DB_URL",       _c(r"(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql|oracle)://\S+")),
    ("URL_CREDS",    _c(r"(?i)[a-z][a-z0-9+.\-]*://[^\s/:@]+:[^\s/:@]+@\S+")),
    ("ENV_SECRET",   _c(r"(?im)^\s*[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL)[A-Z0-9_]*\s*=\s*\S+")),
    # ---- financial ------------------------------------------------------
    ("IMEI",         _c(r"(?i)\bimei\s*[:#]?\s*\d{15}\b")),                  # device IMEI — before card patterns
    ("CREDIT_CARD",  _c(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")),
    ("IBAN",         _c(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")),
    ("SWIFT_BIC",    _c(r"(?i)\b(?:swift|bic)\s*(?:code)?\s*[:#]?\s*([A-Z]{6}[A-Z0-9]{2,5})\b")),
    ("BTC_ADDR",     _c(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")),
    ("ETH_ADDR",     _c(r"\b0x[a-fA-F0-9]{40}\b")),
    ("ROUTING_NUM",  _c(r"(?i)\brouting\s*(?:number|no|#)?\s*[:#]?\s*\d{9}\b")),
    ("BANK_ACCOUNT", _c(r"(?i)\b(?:account|acct|a/c)\s*(?:number|no|#)?\s*[:#]?\s*\d{8,17}\b")),
    ("CVV",          _c(r"(?i)\b(?:cvv|cvc|cvv2|cvc2|card\s*(?:security|verification)\s*(?:code|value)|csc)\s*[:#]?\s*\d{3,4}\b")),
    ("PIN",          _c(r"(?i)\bpin\s*(?:code|number|no)?\s*[:#]?\s*\d{4,6}\b")),
    # ---- government / national IDs --------------------------------------
    ("US_ITIN",      _c(r"\b9\d{2}-[7-9]\d-\d{4}\b")),                       # US taxpayer ID (9xx-7x-xxxx) — before SSN
    ("US_SSN",       _c(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("US_SSN_LOOSE", _c(r"(?i)\bssn\s*[:#]?\s*\d{9}\b")),
    # ---- India (full set — not just Aadhaar) ---------------------------
    ("GSTIN_IN",     _c(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b")),  # GST number (15 char)
    ("PAN_IN",       _c(r"\b[A-Z]{5}\d{4}[A-Z]\b")),                        # Permanent Account Number
    ("VOTER_EPIC_IN",_c(r"\b[A-Z]{3}\d{7}\b")),                             # Voter ID / EPIC
    ("IFSC_IN",      _c(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")),                      # bank branch IFSC code
    ("UPI_ID_IN",    _c(r"\b[a-zA-Z0-9.\-]{2,}@(?:ok\w+|ybl|paytm|apl|ibl|axl|upi|okaxis|oksbi|okicici|okhdfcbank)\b")),
    # ---- international national IDs (distinctive formats first) ---------
    ("CPF_BR",       _c(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")),                 # Brazil CPF
    ("CNPJ_BR",      _c(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b")),           # Brazil company CNPJ
    ("CURP_MX",      _c(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b")),       # Mexico CURP
    ("RFC_MX",       _c(r"(?i)\brfc\s*[:#]?\s*[A-Z&Ñ]{3,4}\d{6}[A-Z0-9]{3}\b")),
    ("CNIC_PK",      _c(r"\b\d{5}-\d{7}-\d\b")),                            # Pakistan CNIC
    ("RRN_KR",       _c(r"\b\d{6}-[1-4]\d{6}\b")),                          # South Korea resident reg. no
    ("EMIRATES_ID",  _c(r"\b784-?\d{4}-?\d{7}-?\d\b")),                     # UAE Emirates ID
    ("CN_RESIDENT",  _c(r"(?i)\b(?:id\s*card|resident\s*id|shenfenzheng)\s*[:#]?\s*\d{17}[\dXx]\b")),  # China
    ("NIK_ID",       _c(r"(?i)\b(?:nik|ktp)\s*[:#]?\s*\d{16}\b")),          # Indonesia
    ("NIN_NG",       _c(r"(?i)\bnin\s*[:#]?\s*\d{11}\b")),                  # Nigeria NIN
    ("BVN_NG",       _c(r"(?i)\bbvn\s*[:#]?\s*\d{11}\b")),                  # Nigeria bank verification
    ("NID_BD",       _c(r"(?i)\bnid\s*(?:no|number)?\s*[:#]?\s*\d{10,17}\b")), # Bangladesh
    ("ID_ZA",        _c(r"(?i)\b(?:said|sa\s*id|id\s*(?:no|number))\s*[:#]?\s*\d{13}\b")),  # South Africa
    ("TC_KIMLIK_TR", _c(r"(?i)\b(?:tc|kimlik)\s*(?:no)?\s*[:#]?\s*[1-9]\d{10}\b")),  # Turkey
    ("NIR_FR",       _c(r"\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2])\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b")),  # France INSEE/NIR
    # ---- generic catch-alls LAST (so labelled IDs above win) -----------
    ("MYNUMBER_JP",  _c(r"(?i)\bmy\s*number\s*[:#]?\s*\d{4}\s?\d{4}\s?\d{4}\b")),   # Japan (keyword before Aadhaar)
    ("CARD_SPACED",  _c(r"\b(?:\d[ \-]?){15,16}\b")),                      # generic 15-16 digit card (before 12-digit Aadhaar)
    ("AADHAAR_IN",   _c(r"\b\d{4}\s?\d{4}\s?\d{4}\b")),                     # 12-digit UID grouped (India)
    ("PASSPORT",     _c(r"(?i)\bpassport\s*(?:no|number|#)?\s*[:#]?\s*[A-Z0-9]{6,9}\b")),
    ("DRIVERS_LIC",  _c(r"(?i)\b(?:driver'?s?\s*licen[cs]e|dl)\s*(?:no|number|#)?\s*[:#]?\s*[A-Z0-9]{5,15}\b")),
    ("TAX_ID",       _c(r"(?i)\b(?:tax\s*id|ein|vat|tin)\s*(?:no|number|#)?\s*[:#]?\s*[A-Z0-9\-]{6,15}\b")),
    ("NHS_UK",       _c(r"(?i)\bnhs\s*(?:no|number|#)?\s*[:#]?\s*\d{3}\s?\d{3}\s?\d{4}\b")),
    ("NINO_UK",      _c(r"\b[ABCEGHJ-PRSTW][ABCEGHJ-NPRSTW]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b")),  # UK National Insurance
    ("SIN_CA",       _c(r"(?i)\b(?:sin)\s*[:#]?\s*\d{3}[\s\-]?\d{3}[\s\-]?\d{3}\b")),  # Canada Social Insurance
    ("NRIC_SG",      _c(r"\b[STFGM]\d{7}[A-Z]\b")),                          # Singapore NRIC/FIN
    ("FISCAL_IT",    _c(r"\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b")),  # Italian Codice Fiscale
    ("NIF_ES",       _c(r"(?i)\b(?:nif|dni)\s*[:#]?\s*\d{8}[A-Z]\b")),       # Spain DNI/NIF
    ("TFN_AU",       _c(r"(?i)\btfn\s*[:#]?\s*\d{3}\s?\d{3}\s?\d{2,3}\b")),   # Australian Tax File Number
    ("ABN_AU",       _c(r"(?i)\babn\s*[:#]?\s*\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b")),  # Australian Business Number
    ("MEDICARE",     _c(r"(?i)\bmedicare\s*(?:no|number|#)?\s*[:#]?\s*\d[\s\-]?\d{3}[\s\-]?\d{5}[\s\-]?\d\b")),
    ("MED_RECORD",   _c(r"(?i)\b(?:mrn|medical\s*record(?:\s*(?:no|number|#))?|patient\s*id)\s*[:#]?\s*[A-Z0-9\-]{5,15}\b")),
    ("VOTER_ID",     _c(r"(?i)\bvoter\s*(?:id|number|#)?\s*[:#]?\s*[A-Z0-9]{6,12}\b")),
    ("NATIONAL_ID",  _c(r"(?i)\b(?:national\s*id|id\s*card|identity\s*(?:card|no)|citizen\s*id)\s*(?:no|number|#)?\s*[:#]?\s*[A-Z0-9\-]{5,18}\b")),
    # ---- vehicle / geo / device ----------------------------------------
    ("VIN",          _c(r"(?i)\b(?:vin)\s*[:#]?\s*[A-HJ-NPR-Z0-9]{17}\b")),  # vehicle ID (keyword-anchored; excludes I,O,Q)
    ("LICENSE_PLATE",_c(r"(?i)\b(?:licen[cs]e\s*plate|number\s*plate|reg(?:istration)?\s*(?:no|number|plate))\s*[:#]?\s*[A-Z0-9\- ]{4,10}\b")),
    ("GPS_COORDS",   _c(r"(?<![\d.])[-+]?\d{1,3}\.\d{3,},\s*[-+]?\d{1,3}\.\d{3,}(?![\d])")),  # lat,long geolocation
    # ---- contact: phone before generic digit patterns -------------------
    # international (+country): catches +91 98765 43210, +1 415 555 2671, +44 20 7946 0958
    ("PHONE",        _c(r"(?<![\w+])\+\d{1,3}[\s.\-]?\(?\d{2,5}\)?[\s.\-]?\d{2,5}(?:[\s.\-]?\d{2,4}){0,2}(?![\w])")),
    # North-American / 3-3-4 grouped: (415) 555-2671, 415-555-2671, 415.555.2671
    ("PHONE",        _c(r"(?<!\d)\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}(?!\d)")),
    # local mobile after a phone/mobile/tel/cell keyword (any grouping)
    ("PHONE",        _c(r"(?i)\b(?:phone|mobile|tel|cell|contact|whatsapp)\s*(?:no|number|#)?\s*[:#]?\s*\+?\d[\d\s.\-]{6,15}\d")),
    # ---- network / infra ------------------------------------------------
    ("IPV4",         _c(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("IPV6",         _c(r"\b(?:[A-Fa-f0-9]{1,4}:){3,7}[A-Fa-f0-9]{1,4}\b")),
    ("MAC",          _c(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b")),
    ("URL",          _c(r"https?://[^\s<>\"'\)\]]+", I)),
    ("FILE_PATH",    _c(r"(?:~|/(?:home|users|var|etc|srv|opt|usr|root|www|data|mnt|tmp)|[A-Z]:\\Users)[/\\][^\s:'\"\)\]<>]+", I)),
    # ---- contact / personal --------------------------------------------
    ("EMAIL",        _c(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("STREET_ADDR",  _c(r"(?im)\b\d{1,5}\s+(?:[A-Z][a-z]+\.?\s){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Terrace|Ter|Circle|Cir|Highway|Hwy|Parkway|Pkwy)\b\.?")),
    ("ZIP_CODE",     _c(r"(?i)\b(?:zip|postal)\s*(?:code)?\s*[:#]?\s*[A-Z0-9][A-Z0-9\- ]{2,8}\b")),
    ("USERNAME",     _c(r"(?im)\b(?:username|user\s*name|login|handle|screen\s*name)\s*[:#]\s*\S{2,}")),
    ("AGE",          _c(r"(?i)\bage\s*[:#]\s*\d{1,3}\b")),
    ("DOB",          _c(r"(?i)\b(?:d\.?o\.?b\.?|date of birth|born)\s*[:#]?\s*\d{1,4}[/\-.]\d{1,2}[/\-.]\d{1,4}\b")),
    ("DOMAIN",       _c(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+(?:com|net|org|io|co|dev|app|xyz|info|biz|me|site|online|store|shop|cloud|tech|blog|us|uk|ca|au|de|fr|in|nl|es|it|ph|sg|my|id|website|space|live|pro|agency|studio|design|ai|gg)\b", I)),
    # ---- identifiers ----------------------------------------------------
    ("UUID",         _c(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("USER_ID",      _c(r"(?i)\b(?:user|customer|account|client|member|uid)(?:\s*id)?\s*[#:]?\s*\d{4,}\b")),
    ("LONG_ID",      _c(r"\b\d{9,}\b")),
]

# Grouped patterns — replace only the captured token, keep the prefix/label word.
GROUPED = [
    # names after a salutation OR a From:/To:/Name:/By: label
    ("NAME", _c(r"(?:\b(?:Hi|Hello|Hey|Dear)\b[,\s]+|(?:Regards|Thanks|Thank you|Best regards|Best|Cheers|Sincerely|Kind regards|Yours)[,\s]+)([A-Z][a-z]+(?:\s[A-Z][a-z]+)?)")),
    ("NAME", _c(r"(?im)\b(?:from|to|name|by|author|contact|customer|requester|reporter|assignee|agent)\s*[:#]\s*([A-Z][a-z]+(?:\s[A-Z][a-z]+){0,2})")),
]

# ===========================================================================
# Redaction core
# ===========================================================================
def redact(text):
    """Sentinel-protected: matched PII becomes \\x00<idx>\\x01 during processing so a
    later pattern can never re-match an already-inserted placeholder. Restored to
    [LABEL] at the very end."""
    counts = Counter()
    store = []
    def stash(lbl):
        counts[lbl] += 1
        store.append(lbl)
        return f"\x00{len(store)-1}\x01"
    for label, pat in PATTERNS:
        text = pat.sub(lambda m, l=label: stash(l), text)
    for label, pat in GROUPED:
        text = pat.sub(lambda m, l=label: m.group(0).replace(m.group(1), stash(l)), text)
    text = re.sub(r"\x00(\d+)\x01", lambda m: f"[{store[int(m.group(1))]}]", text)
    return text, counts

# ===========================================================================
# File extractors (text out of various formats). Stdlib where possible.
# ===========================================================================
def from_docx(path):
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml").decode("utf-8", "ignore")
    xml = re.sub(r"</w:p>", "\n", xml)
    xml = re.sub(r"<w:br\s*/?>", "\n", xml)
    xml = re.sub(r"<w:tab\s*/?>", "\t", xml)
    txt = html.unescape(re.sub(r"<[^>]+>", "", xml))
    return re.sub(r"[ \t]+", " ", txt).strip()

def from_pdf(path):
    try:
        from pypdf import PdfReader
    except ImportError:
        raise RuntimeError("PDF support needs: pip install pypdf")
    return "\n".join((p.extract_text() or "") for p in PdfReader(path).pages)

def from_xlsx(path):
    try:
        import openpyxl
    except ImportError:
        raise RuntimeError("XLSX support needs: pip install openpyxl")
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        out = []
        for ws in wb.worksheets:
            for row in ws.iter_rows(values_only=True):
                out.append("\t".join("" if c is None else str(c) for c in row))
        return "\n".join(out)
    finally:
        wb.close()

def from_plain(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        return f.read()

EXTRACTORS = {
    ".docx": from_docx, ".pdf": from_pdf, ".xlsx": from_xlsx,
    ".txt": from_plain, ".md": from_plain, ".log": from_plain, ".csv": from_plain,
    ".json": from_plain, ".html": from_plain, ".htm": from_plain, ".xml": from_plain,
    ".yaml": from_plain, ".yml": from_plain, ".tsv": from_plain, ".ini": from_plain,
    ".conf": from_plain, ".env": from_plain, ".sql": from_plain, ".py": from_plain,
    ".js": from_plain, ".ts": from_plain, ".rb": from_plain, ".php": from_plain,
}

def scrub_file(path, out_path):
    ext = os.path.splitext(path)[1].lower()
    ex = EXTRACTORS.get(ext)
    if not ex:
        return None, f"unsupported:{ext}"
    text = ex(path)
    if not text.strip():
        return None, "empty"
    clean, counts = redact(text)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(clean)
    return counts, None

# ===========================================================================
# Orchestration: file / folder / zip
# ===========================================================================
def gather(src):
    if os.path.isfile(src) and src.lower().endswith(".zip"):
        tmp = tempfile.mkdtemp(prefix="shush_")
        with zipfile.ZipFile(src) as z:
            # Zip-Slip guard: refuse entries that escape the temp dir.
            base = os.path.realpath(tmp)
            for m in z.namelist():
                dest = os.path.realpath(os.path.join(tmp, m))
                if dest != base and not dest.startswith(base + os.sep):
                    raise RuntimeError(f"unsafe zip path blocked: {m}")
            z.extractall(tmp)
        return tmp, True
    return src, False

def run(src, dst, report_only=False, workers=8):
    import shutil
    root, was_zip = gather(src)
    try:
        files = []
        if os.path.isfile(root):
            files = [root]
        else:
            for r, _, fs in os.walk(root):
                for f in fs:
                    if os.path.splitext(f)[1].lower() in EXTRACTORS:
                        files.append(os.path.join(r, f))
        if not files:
            print("No supported files found."); return

        # single-file convenience: no output given, input is one file, not a zip
        # -> write a sibling "<name>.scrubbed.txt" (matches the documented UX).
        single = (len(files) == 1 and os.path.isfile(root) and not was_zip and not dst)
        if single and not report_only:
            inp = files[0]
            outp = os.path.splitext(inp)[0] + ".scrubbed.txt"
            try:
                counts, err = scrub_file(inp, outp)
            except Exception as e:                       # fail-closed: never crash on one bad file
                counts, err = None, f"unreadable ({type(e).__name__})"
            print("\n" + "=" * 52)
            if err:
                print(f"Skipped ({err}): {os.path.basename(inp)}")
                return
            print(f"Scrubbed 1 file -> {outp}")
            print("\nSensitive items removed:")
            for label, n in Counter(counts).most_common():
                print(f"  {label:14} {n:>8}")
            if not counts: print("  (none found)")
            print("\nDone. Everything ran locally — nothing left your machine.")
            print("Spot-check the output before sharing.")
            return

        # decide whether the final artifact is a zip, and pick a working dir that is
        # ALWAYS a real directory distinct from the .zip file path.
        want_zip = bool((dst and dst.lower().endswith(".zip")) or (was_zip and not dst))
        if want_zip:
            zpath = dst if (dst and dst.lower().endswith(".zip")) else (os.path.splitext(src)[0] + "_scrubbed.zip")
            out_dir = os.path.splitext(zpath)[0] + "_tmp"
        else:
            zpath = None
            out_dir = dst if dst else (os.path.splitext(src)[0] + "_scrubbed")
        if not report_only:
            os.makedirs(out_dir, exist_ok=True)
        total = Counter(); ok = skip = 0
        from concurrent.futures import ThreadPoolExecutor
        import threading
        lock = threading.Lock()
        def work(path):
            nonlocal ok, skip
            base = os.path.splitext(os.path.basename(path))[0] + ".txt"
            outp = os.path.join(out_dir, base) if not report_only else os.devnull
            try:
                counts, err = scrub_file(path, outp)
                with lock:
                    if err: skip += 1
                    else: total.update(counts); ok += 1
            except Exception:
                with lock: skip += 1
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for i, _ in enumerate(ex.map(work, files), 1):
                if i % 500 == 0: print(f"  {i}/{len(files)}...", flush=True)

        print("\n" + "=" * 52)
        dest_label = zpath if want_zip else out_dir
        print(f"Scrubbed {ok} files" + (f" -> {dest_label}" if not report_only else " (report only)"))
        if skip: print(f"Skipped (empty/unsupported/unreadable): {skip}")
        print("\nSensitive items removed:")
        for label, n in total.most_common():
            print(f"  {label:14} {n:>8}")
        if not total:
            print("  (none found)")
        # write a report
        if not report_only:
            with open(os.path.join(out_dir, "_shush_report.json"), "w") as f:
                json.dump({"files_scrubbed": ok, "skipped": skip, "removed": dict(total)}, f, indent=2)
            # zip the results if the target is a zip, then remove the working dir
            if want_zip:
                with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
                    for r, _, fs in os.walk(out_dir):
                        for f in fs:
                            z.write(os.path.join(r, f), os.path.relpath(os.path.join(r, f), out_dir))
                shutil.rmtree(out_dir, ignore_errors=True)
                print(f"\nZipped -> {zpath}")
        print("\nDone. Everything ran locally — nothing left your machine.")
        print("Spot-check a few outputs before sharing.")
    finally:
        # SECURITY: a zip input is extracted RAW (un-redacted) into a temp dir.
        # Always remove it, even on error, so sensitive originals never linger.
        if was_zip:
            shutil.rmtree(root, ignore_errors=True)

def main():
    ap = argparse.ArgumentParser(prog="shush",
        description="Shush — strip PII/secrets from files before sharing with an AI. 100% local, no network, no AI.")
    ap.add_argument("input", help="a file, folder, or .zip")
    ap.add_argument("output", nargs="?", help="output folder or .zip (default: <input>_scrubbed)")
    ap.add_argument("--report", action="store_true", help="only report what would be removed, write nothing")
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    run(a.input, a.output, report_only=a.report, workers=a.workers)

if __name__ == "__main__":
    main()
