# Eval dataset and scorer

A starter labeled set of 33 emails for measuring the triage agent. It is the seed for the
~200-email set planned in M3, not a replacement for it.

## What is in it

| Label | Count | Categories | Dev / test |
|---|---|---|---|
| phishing | 13 | credential_phishing (8), bec (3), malware_delivery (2) | 4 / 9 |
| spam | 8 | spam | 2 / 6 |
| benign | 12 | benign (10 of them are "hard benign") | 3 / 9 |

- **All emails are synthetic** (`synthetic=true` in `labels.csv`). Disclose this in the README
  when reporting numbers.
- **No real people or domains.** Every domain is under the reserved `.example` TLD (RFC 2606),
  every IP is from documentation ranges (RFC 5737). Brand names in display names exist only to
  test impersonation detection.
- **No real malware.** Attachments are short text placeholders. `Invoice_88213.pdf.exe` and
  `Salary_Structure_2027.docm` only *look* dangerous by name and content type.
- **Hard benign cases** (password reset, sign-in alert, invoice with PDF, tracked newsletter,
  IT notice, mailing list with DMARC fail but ARC pass, etc.) keep the false-positive rate honest.
- **Hard phishing cases**: lookalike domains that pass SPF/DKIM/DMARC, BEC with no links at all,
  and two prompt-injection emails (`phish_012`, `phish_013`) that tell an AI to say "benign".
- Each email's `Authentication-Results` header is written as if added by our own receiving
  server `mx1.testmailbox.example`.
- Not covered yet: quishing (QR in images), image-only phishing, non-English mail, malformed MIME.

## labels.csv

`file, label, category, source, synthetic, split, notes`

- `label`: `phishing | spam | benign` (ground truth for the main question)
- `category`: same values as the verdict schema (`credential_phishing | bec | malware_delivery | spam | benign`)
- `split`: `dev` (~30%, tune prompts and thresholds here) or `test` (~70%, final numbers only)

## Running the scorer

Stdlib only, Python 3.10+.

```bash
# Automatic: any function that takes a Path to a .eml and returns verdict + category
python eval/run_eval.py --split dev --predictor triage.baseline:predict

# Manual: fill a CSV by hand (or from another tool) and score it
python eval/run_eval.py --split dev --predictions eval/my_predictions.csv
```

The predictor may return a dict `{"verdict": ..., "category": ...}` or the pydantic `Verdict`
object; if it has `meta.cost_usd` the average cost is reported too. Latency is measured
per email. A predictor that crashes is recorded as an error, not skipped.

Results go to `eval/results/<timestamp>_<split>_<name>.json` and `.md`.

## How the numbers are defined

- **Phishing precision / recall / F1 / FPR**: binary "is it phishing?". A prediction counts as
  phishing when its `category` is `credential_phishing`, `bec` or `malware_delivery`. Spam is
  a negative here, so calling spam "phishing" is a false positive.
- **Benign flag rate**: share of legitimate emails whose `verdict` was not `benign`. This is
  the analyst-fatigue number a SOC cares about.
- **Category accuracy**: exact match on `category` across all emails.
- **Confusion matrix**: truth label vs predicted label (phishing / spam / benign / error).

## Manual checklist (before the agent can run end to end)

1. Copy the `file` column of the dev rows into `eval/my_predictions.csv` with headers
   `file,verdict,category`.
2. For each email, run whatever part of the agent exists (or classify by hand as a
   human baseline) and fill in `verdict` and `category`.
3. Run `python eval/run_eval.py --split dev --predictions eval/my_predictions.csv`.
4. Read the "Mistakes" list in the report; every miss has a note in `labels.csv` saying what
   the email is testing.
5. Touch the test split only for numbers you intend to report.
