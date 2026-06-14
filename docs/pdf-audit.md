# PDF Deep Audit

`pdf-audit` checks PDF surfaces that ordinary text extraction can miss.

```bash
openscholarguard pdf-audit paper.pdf
openscholarguard pdf-audit paper.pdf --format html --output reports/pdf.deep.html
openscholarguard pdf-audit paper.pdf --enable-ocr --format json --output reports/pdf.deep.json
```

## Signals

- `hidden_pdf_span`: tiny, near-white, transparent, or off-page text spans.
- `ocr_candidate_page`: image-heavy page with little extractable text.
- `visual_text_mismatch`: rendered page appears nonblank but the text layer is sparse.
- `ocr_text_delta`: optional OCR adds substantial content beyond the PDF text layer.

The command exits with code `1` when any signal reaches `--fail-on` severity. The default
threshold is `high`, which makes the command useful in CI without failing on every OCR
candidate page.

## OCR Notes

OCR is optional because it depends on local PyMuPDF and Tesseract support. Without
`--enable-ocr`, the audit still identifies pages that should be OCR-scanned before AI review
or RAG ingestion.
