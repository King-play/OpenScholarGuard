# PDF Attack Gallery

OpenScholarGuard can generate a synthetic PDF attack gallery for demos, regression tests,
paper figures, and public project pages.

```bash
openscholarguard pdf-gallery --output-dir pdf-gallery-output --overwrite
```

The generated directory contains:

- `index.html`: gallery page with screenshots and links.
- `manifest.json`: machine-readable case metadata.
- `samples/*.pdf`: synthetic PDF cases.
- `screenshots/*.png`: rendered first-page previews.
- `reports/*.scan.html`: normal scanner reports.
- `reports/*.deep.html`: PDF deep-audit reports.

## Cases

The first gallery includes ten reproducible cases:

- white text instruction
- transparent instruction
- tiny font payload
- off-page text
- PDF metadata injection
- OCR candidate page
- image text instruction
- hidden LaTeX pattern
- invisible Unicode control
- encoded payload

All cases are synthetic. They are meant to show the difference between human-visible
content, model-visible text extraction, PDF metadata, visual rendering, and OCR-oriented
surfaces without publishing real submissions or private reviews.

## Static Site

The project-site generator includes the gallery automatically:

```bash
openscholarguard site --output-dir site-output --overwrite
```

Open:

```text
site-output/pdf-gallery/index.html
```

