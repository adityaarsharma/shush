"""
Shush test suite — stdlib unittest only (no pytest, keeps the zero-dep promise).

Run:  python3 -m unittest discover -s tests -v
      (or:  python3 tests/test_shush.py)

For a redaction tool a regression IS a leak, so these tests assert two things on
every case: (1) the sensitive value is GONE from the output, and (2) it carries
the CORRECT label. Fake/example data only — nothing here is a real secret.
"""
import importlib.util
import os
import shutil
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
_spec = importlib.util.spec_from_file_location("shush", os.path.join(ROOT, "shush.py"))
shush = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shush)


class RedactBasics(unittest.TestCase):
    def r(self, text):
        return shush.redact(text)[0]

    def assertRedacted(self, raw, label, secret):
        """Output must contain [label] and must NOT contain the raw secret."""
        out = self.r(raw)
        self.assertIn(f"[{label}]", out, f"{label} not applied to: {raw!r} -> {out!r}")
        self.assertNotIn(secret, out, f"LEAK: {secret!r} survived in {out!r}")

    def test_email(self):
        self.assertRedacted("ping me at jane.doe@example.com ok", "EMAIL", "jane.doe@example.com")

    def test_ipv4(self):
        self.assertRedacted("server 192.168.10.5 down", "IPV4", "192.168.10.5")

    def test_credit_card_spaced(self):
        self.assertRedacted("card 4111 1111 1111 1111", "CARD_SPACED", "4111 1111 1111 1111")

    def test_cvv(self):
        self.assertRedacted("CVV: 123", "CVV", "123")

    def test_password(self):
        self.assertRedacted("Password: hunter2secret", "PASSWORD", "hunter2secret")

    def test_db_url(self):
        raw = "DB: postgres://admin:s3cr3tpass@db.internal:5432/prod"
        self.assertRedacted(raw, "DB_URL", "s3cr3tpass")

    def test_aws_key(self):
        # build the fake key by concatenation so no secret-shaped literal is committed.
        # bare token (no "key=" prefix) isolates the AWS_KEY detector; with a prefix it
        # would legitimately match ENV_SECRET instead — still redacted, just labelled.
        fake = "AKIA" + "IOSFODNN7" + "EXAMPLE"
        self.assertRedacted(f"deploy uses {fake} for s3 access", "AWS_KEY", fake)

    def test_file_path(self):
        self.assertRedacted("crash at /home/deploy/app/main.py line 3", "FILE_PATH", "/home/deploy/app/main.py")

    def test_us_ssn(self):
        self.assertRedacted("SSN 123-45-6789", "US_SSN", "123-45-6789")


class InternationalIDs(unittest.TestCase):
    """The whole point of the anti-bias work: non-US/UK IDs must be caught + labelled."""
    def check(self, raw, label, secret):
        out = shush.redact(raw)[0]
        self.assertIn(f"[{label}]", out, f"{label}: {raw!r} -> {out!r}")
        self.assertNotIn(secret, out, f"LEAK {secret!r} in {out!r}")

    def test_india_aadhaar(self):   self.check("Aadhaar 2345 6789 0123", "AADHAAR_IN", "2345 6789 0123")
    def test_india_pan(self):       self.check("PAN ABCPD1234E", "PAN_IN", "ABCPD1234E")
    def test_india_voter(self):     self.check("Voter WBX1234567", "VOTER_EPIC_IN", "WBX1234567")
    def test_india_gstin(self):     self.check("GST 27AAPFU0939F1ZV", "GSTIN_IN", "27AAPFU0939F1ZV")
    def test_india_ifsc(self):      self.check("IFSC HDFC0001234", "IFSC_IN", "HDFC0001234")
    def test_india_upi(self):       self.check("pay rahul@okhdfcbank now", "UPI_ID_IN", "rahul@okhdfcbank")
    def test_brazil_cpf(self):      self.check("CPF 123.456.789-09", "CPF_BR", "123.456.789-09")
    def test_pakistan_cnic(self):   self.check("CNIC 35202-1234567-8", "CNIC_PK", "35202-1234567-8")
    def test_uae_emirates(self):    self.check("Emirates ID 784-1985-1234567-1", "EMIRATES_ID", "784-1985-1234567-1")
    def test_korea_rrn(self):       self.check("RRN 900101-1234567", "RRN_KR", "900101-1234567")
    def test_indonesia_nik(self):   self.check("NIK: 3201012345678901", "NIK_ID", "3201012345678901")


class PhoneFormats(unittest.TestCase):
    def one(self, raw):
        out = shush.redact(raw)[0]
        self.assertIn("[PHONE]", out, f"phone missed: {raw!r} -> {out!r}")

    def test_india_mobile(self):    self.one("call +91 98765 43210")
    def test_us_intl(self):         self.one("call +1 415 555 2671")
    def test_na_parens(self):       self.one("(415) 555-2671")
    def test_na_dashes(self):       self.one("415-555-2671")
    def test_uk_intl(self):         self.one("+44 20 7946 0958")
    def test_keyword_bare(self):    self.one("Mobile: 9876543210")


class FalsePositiveGuards(unittest.TestCase):
    """Over-redaction is safe, but these common non-PII tokens should survive intact."""
    def test_date_not_phone(self):
        out = shush.redact("released 2024-01-15")[0]
        self.assertIn("2024-01-15", out)

    def test_semver_not_phone(self):
        out = shush.redact("upgraded to build 3.2.1 today")[0]
        self.assertIn("3.2.1", out)


class OrderingAndSentinel(unittest.TestCase):
    def test_itin_labelled_not_ssn(self):
        out = shush.redact("ITIN 912-73-4521")[0]
        self.assertIn("[US_ITIN]", out)
        self.assertNotIn("912-73-4521", out)

    def test_spaced_card_beats_aadhaar(self):
        # a 16-digit spaced card must be CARD_SPACED, not split by the 12-digit Aadhaar rule
        out = shush.redact("card 4111 1111 1111 1111")[0]
        self.assertIn("[CARD_SPACED]", out)
        self.assertNotIn("[AADHAAR_IN]", out)
        self.assertNotIn("1111", out)

    def test_no_leftover_sentinels(self):
        out = shush.redact("mail a@b.com ip 10.0.0.1 pass Password: x9y8z7w6")[0]
        self.assertNotIn("\x00", out)
        self.assertNotIn("\x01", out)

    def test_placeholder_not_rematched(self):
        # a redacted password value must not itself get re-labelled by a later rule
        out = shush.redact("Password: ABCDEF12345678")[0]
        self.assertEqual(out, "[PASSWORD]")


class MultiLeakScan(unittest.TestCase):
    def test_kitchen_sink_no_leaks(self):
        raw = (
            "From: Sarah Johnson <sarah.j@acme.com>\n"
            "Aadhaar 2345 6789 0123 PAN ABCPD1234E\n"
            "IP 10.0.0.42 path /home/x/app CPF 123.456.789-09\n"
            "card 4111 1111 1111 1111 CVV: 123 phone +91 98765 43210"
        )
        out = shush.redact(raw)[0]
        for secret in ["sarah.j@acme.com", "2345 6789 0123", "ABCPD1234E",
                       "10.0.0.42", "/home/x/app", "123.456.789-09",
                       "4111 1111 1111 1111", "+91 98765 43210"]:
            self.assertNotIn(secret, out, f"LEAK: {secret!r} in {out!r}")


class FileModes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="shushtest_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_single_file_writes_sibling(self):
        p = os.path.join(self.tmp, "t.txt")
        with open(p, "w") as f:
            f.write("reach me at raj@acme.in +91 98765 43210\n")
        shush.run(p, None)
        out = os.path.join(self.tmp, "t.scrubbed.txt")
        self.assertTrue(os.path.exists(out), "sibling .scrubbed.txt not written")
        content = open(out).read()
        self.assertIn("[EMAIL]", content)
        self.assertIn("[PHONE]", content)

    def test_corrupt_docx_does_not_raise(self):
        p = os.path.join(self.tmp, "bad.docx")
        with open(p, "w") as f:
            f.write("this is not a real docx")
        # must fail closed (no exception, no output file)
        try:
            shush.run(p, None)
        except Exception as e:  # pragma: no cover
            self.fail(f"corrupt file raised instead of skipping: {e}")
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "bad.scrubbed.txt")))

    def test_zip_leaves_no_temp_extraction(self):
        src = os.path.join(self.tmp, "src.txt")
        with open(src, "w") as f:
            f.write("secret raj@acme.in\n")
        zpath = os.path.join(self.tmp, "in.zip")
        with zipfile.ZipFile(zpath, "w") as z:
            z.write(src, "src.txt")
        before = set(g for g in os.listdir(tempfile.gettempdir()) if g.startswith("shush_"))
        shush.run(zpath, os.path.join(self.tmp, "out.zip"))
        after = set(g for g in os.listdir(tempfile.gettempdir()) if g.startswith("shush_"))
        self.assertEqual(before, after, "zip extraction temp dir not cleaned up (raw files linger)")

    def test_zip_output_is_redacted(self):
        src = os.path.join(self.tmp, "src.txt")
        with open(src, "w") as f:
            f.write("email raj@acme.in ip 10.0.0.9\n")
        zin = os.path.join(self.tmp, "in.zip")
        with zipfile.ZipFile(zin, "w") as z:
            z.write(src, "src.txt")
        zout = os.path.join(self.tmp, "out.zip")
        shush.run(zin, zout)
        self.assertTrue(os.path.exists(zout))
        with zipfile.ZipFile(zout) as z:
            body = z.read("src.txt").decode()
        self.assertNotIn("raj@acme.in", body)
        self.assertNotIn("10.0.0.9", body)


class ZipSlipGuard(unittest.TestCase):
    def test_malicious_zip_path_blocked(self):
        tmp = tempfile.mkdtemp(prefix="shushtest_")
        try:
            evil = os.path.join(tmp, "evil.zip")
            with zipfile.ZipFile(evil, "w") as z:
                z.writestr("../../escape.txt", "pwned")
            with self.assertRaises(RuntimeError):
                shush.gather(evil)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
