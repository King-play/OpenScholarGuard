# Roadmap

OpenScholarGuard is past the basic MVP stage. The next goal is to make the project easy to
try, cite, reproduce, and integrate.

## Phase 1: Public Release Proof

Status: in progress.

- Publish the generated site through GitHub Pages.
- Keep `docs/assets/demo-preview.gif`, `docs/assets/site-preview.png`, and
  `docs/assets/leaderboard-preview.png` current.
- Tag `v0.1.0` after CI, release check, demo generation, and package build pass.
- Publish the package to PyPI after the first public tag.
- Add a launch post that explains the threat model, demo, and benchmark in one page.

Definition of done:

- A new visitor can open the Pages URL, inspect the demo, and copy a working install command
  in under one minute.

## Phase 2: Real Model Evaluation

Status: planned.

- Freeze the first public model-evaluation protocol.
- Record model name, provider, version/date, temperature, prompt template, and run date.
- Collect response JSONL for at least GPT, Claude, Gemini, Qwen, DeepSeek, and Llama-class
  models where access is available.
- Run the deterministic judge and store judge artifacts.
- Render a public leaderboard and include a README screenshot.
- Document known judge limitations and manual-review policy.

Definition of done:

- The benchmark page contains reproducible prompts, response records, judge output, and a
  leaderboard that can be cited from a paper or issue discussion.

## Phase 3: PDF Attack Gallery

Status: planned.

- Add ten reproducible PDF attack samples.
- Cover white text, transparent text, tiny font, off-page spans, metadata injection, OCR
  layer injection, image text, hidden LaTeX, invisible Unicode, and encoded payloads.
- For each sample, store the source recipe, generated PDF, screenshot, scan report, deep
  audit report, and sanitizer output.
- Add a gallery page to the static site.
- Keep all samples synthetic and safe to publish.

Definition of done:

- A reader can see the human-visible page, the model-visible risk, and the exact detector
  evidence side by side.

## Phase 4: Ecosystem Entry Points

Status: planned.

- Add a GitHub Action for repository/document audits.
- Add a LangChain document transformer or loader wrapper.
- Add a LlamaIndex ingestion guard.
- Add promptfoo and PyRIT examples for red-team workflows.
- Add OpenReview-style and conference-submission workflow examples.
- Evaluate Dify and Langfuse integration after the core ingestion hooks are stable.

Definition of done:

- Users can place OpenScholarGuard in an existing document or RAG pipeline without writing
  custom glue code.

## Phase 5: Paper And Research Release

Status: planned.

- Turn the generated paper skeleton into a complete systems paper.
- Write the threat model, detector taxonomy, benchmark construction, experiments, ablations,
  case studies, limitations, ethics, and related work.
- Publish artifacts for benchmark samples, model responses, detector outputs, and PDF
  gallery cases.
- Prepare an arXiv version and short launch materials for research and security
  communities.

Definition of done:

- The repository, benchmark artifacts, and paper support each other as one reproducible
  research package.

