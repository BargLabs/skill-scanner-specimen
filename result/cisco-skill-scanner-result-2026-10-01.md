# Cisco skill-scanner on a constructed known-answer corpus — result

## Limits, first

This is one scanner version (`cisco-ai-skill-scanner` 2.1.0) with its default analyzers only. The corpus is constructed: each defective case is one base skill with a single explicit insertion, so these rates are not an estimate of recall on real malicious packages. The comparison with Cisco's published recall flatters the scanner, because a single explicit insertion is easier to find than a real-world malicious package, whose malicious content is mixed into working code, spread across files, or written to evade exactly these rules.

## Corpus

Bases from `https://github.com/alirezarezvani/claude-skills` at `19392f7a08264ed00486a251f5b2098321771f94`, seed `cisco-skill-scanner-specimen-2026-10-01`. Candidates 846, eligible 386, excluded {   "hidden_path": 0,   "nested_skill": 2,   "symlinked_skill_md": 458,   "unreproducible_entry": 0 }. Cases 480 (80 bases, 400 variants), read from the manifest. Corpus digest `40b18ec8a386c6e7fad8c8adc6ce33ab90c0d955b603704dc1b7bf828b752a9d`. The built corpus is not published; the generator, the base list at its pinned commit and this digest rebuild it byte for byte.

## Predictions

| # | Prediction | Measured | Interval | Verdict | Note |
|---|---|---|---|---|---|
| P1 | Detection of `pipe_shell` is at least 90%. | 80/80 (100.0%) | [95.4%, 100.0%] | `supported` |  |
| P2 | Detection of `prose_exfil` is at most 50%. | 0/80 (0.0%) | [0.0%, 4.6%] | `supported` |  |
| P3 | Detection of `obfuscated_shell` is at least 30 percentage points lower than detection of `pipe_shell`. | 0.0 points | [-4.6, 4.6] points (Newcombe) | `contradicted` |  |
| P4 | Detection of `remote_content` is at most 10%. | 0/80 (0.0%) | [0.0%, 4.6%] | `supported` |  |
| P5 | High or critical findings on the 80 presumed-clean bases are at most 5% of bases. | 5/80 (6.3%) | [2.7%, 13.8%] | `not_evaluable` |  |
| P6 | Detection pooled across the four package-visible categories (`pipe_shell`, `prose_exfil`, `prompt_injection`, `obfuscated_shell`) is above 19.88%, Cisco's published core-only recall. | 240/320 (75.0%) | [70.0%, 79.4%] | `supported` |  |
| P7 | Two full runs of the scanner over the corpus produce byte-identical normalised output. | 480/480 identical | n/a | `supported` |  |

## Detection per category (high or critical, in the inserted file and lines)

| Cell | n | Errored | Detected | Rate | Wilson 95% | Refused |
|---|---|---|---|---|---|---|
| `pipe_shell` | 80 | 0 | 80 | 100.0% | [95.4%, 100.0%] |  |
| `prose_exfil` | 80 | 0 | 0 | 0.0% | [0.0%, 4.6%] |  |
| `prompt_injection` | 80 | 0 | 80 | 100.0% | [95.4%, 100.0%] |  |
| `obfuscated_shell` | 80 | 0 | 80 | 100.0% | [95.4%, 100.0%] |  |
| `remote_content` | 80 | 0 | 0 | 0.0% | [0.0%, 4.6%] |  |
| `pooled_package_visible` | 320 | 0 | 240 | 75.0% | [70.0%, 79.4%] |  |
| `base` | 80 | 0 | 5 | 6.3% | [2.7%, 13.8%] |  |

Prediction 3 difference (`pipe_shell` minus `obfuscated_shell`): 0.0 points, Newcombe 95% [-4.6, 4.6].

Detections resting only on findings that report no line: `pipe_shell` 0, `prose_exfil` 0, `prompt_injection` 0, `obfuscated_shell` 0, `remote_content` 0.

## CEL shadow (descriptive, not scored)

Every bundled CEL rule runs in `shadow`, which annotates findings (`metadata.cel.decision`) and never adds, removes or re-grades one, so shadow decisions do not enter the primary. Detections whose every supporting finding carries a CEL `would_suppress`: `pipe_shell` 0, `prose_exfil` 0, `prompt_injection` 0, `obfuscated_shell` 0, `remote_content` 0.

## Secondary table (any severity, in the inserted file and lines)

| Cell | n | Errored | Detected | Rate | Wilson 95% | Refused |
|---|---|---|---|---|---|---|
| `pipe_shell` | 80 | 0 | 80 | 100.0% | [95.4%, 100.0%] |  |
| `prose_exfil` | 80 | 0 | 70 | 87.5% | [78.5%, 93.1%] |  |
| `prompt_injection` | 80 | 0 | 80 | 100.0% | [95.4%, 100.0%] |  |
| `obfuscated_shell` | 80 | 0 | 80 | 100.0% | [95.4%, 100.0%] |  |
| `remote_content` | 80 | 0 | 36 | 45.0% | [34.6%, 55.9%] |  |
| `pooled_package_visible` | 320 | 0 | 310 | 96.9% | [94.3%, 98.3%] |  |
| `base` | 80 | 0 | 40 | 50.0% | [39.3%, 60.7%] |  |

## Findings on the presumed-clean bases

| Case | Base | Rule | Severity | File | Line | Analyzer |
|---|---|---|---|---|---|---|
| b02 | `project-management/skills/senior-pm` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b04 | `engineering-team/playwright-pro/skills/pw-review` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b05 | `engineering-team/skills/senior-data-engineer` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b05 | `engineering-team/skills/senior-data-engineer` | `FILE_MAGIC_MISMATCH` | MEDIUM | `references/troubleshooting.md` |  | static |
| b05 | `engineering-team/skills/senior-data-engineer` | `COMMAND_INJECTION_EVAL` | CRITICAL | `scripts/pipeline_orchestrator.py` | 339 | static |
| b05 | `engineering-team/skills/senior-data-engineer` | `COMMAND_INJECTION_EVAL` | CRITICAL | `scripts/pipeline_orchestrator.py` | 452 | static |
| b05 | `engineering-team/skills/senior-data-engineer` | `COMMAND_INJECTION_EVAL` | CRITICAL | `scripts/pipeline_orchestrator.py` | 579 | static |
| b05 | `engineering-team/skills/senior-data-engineer` | `SQL_INJECTION_STRING_FORMAT` | CRITICAL | `scripts/pipeline_orchestrator.py` | 676 | static |
| b07 | `engineering-team/skills/embedded-iot-mentor` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b09 | `engineering/skills/pr-review-expert` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b12 | `engineering/skills/focused-fix` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b13 | `engineering/skills/full-page-screenshot` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b13 | `engineering/skills/full-page-screenshot` | `DATA_EXFIL_JS_FS_ACCESS` | LOW | `scripts/full-page-screenshot.mjs` | 85 | static |
| b13 | `engineering/skills/full-page-screenshot` | `DATA_EXFIL_JS_FS_ACCESS` | LOW | `scripts/full-page-screenshot.mjs` | 405 | static |
| b13 | `engineering/skills/full-page-screenshot` | `DATA_EXFIL_JS_FS_ACCESS` | LOW | `scripts/full-page-screenshot.mjs` | 424 | static |
| b13 | `engineering/skills/full-page-screenshot` | `DATA_EXFIL_JS_FS_ACCESS` | LOW | `scripts/full-page-screenshot.mjs` | 443 | static |
| b13 | `engineering/skills/full-page-screenshot` | `COMMAND_INJECTION_JS_CHILD_PROCESS` | CRITICAL | `scripts/full-page-screenshot.mjs` | 445 | static |
| b13 | `engineering/skills/full-page-screenshot` | `DATA_EXFIL_JS_NETWORK` | MEDIUM | `scripts/full-page-screenshot.mjs` | 513 | static |
| b13 | `engineering/skills/full-page-screenshot` | `DATA_EXFIL_JS_NETWORK` | MEDIUM | `scripts/full-page-screenshot.mjs` | 585 | static |
| b13 | `engineering/skills/full-page-screenshot` | `DATA_EXFIL_JS_NETWORK` | MEDIUM | `scripts/full-page-screenshot.mjs` | 609 | static |
| b13 | `engineering/skills/full-page-screenshot` | `DATA_EXFIL_JS_NETWORK` | MEDIUM | `scripts/full-page-screenshot.mjs` | 619 | static |
| b13 | `engineering/skills/full-page-screenshot` | `DATA_EXFIL_JS_NETWORK` | MEDIUM | `scripts/full-page-screenshot.mjs` | 626 | static |
| b13 | `engineering/skills/full-page-screenshot` | `DATA_EXFIL_JS_NETWORK` | MEDIUM | `scripts/full-page-screenshot.mjs` | 633 | static |
| b13 | `engineering/skills/full-page-screenshot` | `DATA_EXFIL_JS_NETWORK` | MEDIUM | `scripts/full-page-screenshot.mjs` | 640 | static |
| b13 | `engineering/skills/full-page-screenshot` | `COMMAND_INJECTION_JS_CHILD_PROCESS` | CRITICAL | `scripts/full-page-screenshot.mjs` | 774 | static |
| b13 | `engineering/skills/full-page-screenshot` | `DATA_EXFIL_JS_FS_ACCESS` | LOW | `scripts/full-page-screenshot.mjs` | 834 | static |
| b13 | `engineering/skills/full-page-screenshot` | `COMMAND_INJECTION_JS_CHILD_PROCESS` | CRITICAL | `scripts/full-page-screenshot.mjs` | 836 | static |
| b14 | `product-team/agile-product-owner/skills/agile-product-owner` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b15 | `c-level-agents/skills/cco-review` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b16 | `engineering-team/skills/security-pen-testing` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b18 | `engineering/skills/ship-gate` | `COMMAND_INJECTION_EVAL` | CRITICAL | `scripts/ship_gate_scanner.py` | 308 | static |
| b18 | `engineering/skills/ship-gate` | `COMMAND_INJECTION_EVAL` | CRITICAL | `scripts/ship_gate_scanner.py` | 500 | static |
| b19 | `engineering/agenthub/skills/eval` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b21 | `compliance-os/skills/fda-qsr-audit-prep` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b24 | `engineering-team/skills/ms365-tenant-manager` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b25 | `productivity/swedish-mentor` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b28 | `business-growth/skills/contract-and-proposal-writer` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b32 | `compliance-os/skills/soc2-audit-prep` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b33 | `c-level-agents/skills/cdo-review` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b34 | `product-team/skills/product-analytics` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b37 | `engineering-team/playwright-pro/skills/testrail` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b41 | `engineering/skills/browser-automation` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b43 | `engineering/skills/mcp-server-builder` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b43 | `engineering/skills/mcp-server-builder` | `PIPELINE_TAINT_FLOW` | MEDIUM | `SKILL.md` | 1 | pipeline |
| b46 | `engineering/agenthub/skills/agenthub` | `PATH_TRAVERSAL_OPEN` | CRITICAL | `scripts/board_manager.py` | 100 | static |
| b46 | `engineering/agenthub/skills/agenthub` | `PATH_TRAVERSAL_OPEN` | CRITICAL | `scripts/board_manager.py` | 157 | static |
| b46 | `engineering/agenthub/skills/agenthub` | `COMMAND_INJECTION_SHELL_TRUE` | HIGH | `scripts/result_ranker.py` | 84 | static |
| b47 | `c-level-agents/skills/cmo-review` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b50 | `engineering-team/skills/named-persona-adversarial-review` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b51 | `marketing-skill/skills/app-store-optimization` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b55 | `engineering/skills/monorepo-navigator` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b56 | `c-level-agents/skills/gc-review` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b57 | `engineering/minimalist` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b58 | `product-team/skills/saas-scaffolder` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b60 | `engineering-team/skills/senior-backend` | `TOOL_ABUSE_UNDECLARED_NETWORK` | MEDIUM | `SKILL.md` |  | static |
| b60 | `engineering-team/skills/senior-backend` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b62 | `engineering/skills/spec-driven-workflow` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b64 | `engineering/skills/changelog-generator` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b64 | `engineering/skills/changelog-generator` | `PIPELINE_TAINT_FLOW` | MEDIUM | `SKILL.md` | 2 | pipeline |
| b67 | `engineering/agenthub/skills/hub-status` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b69 | `product-team/skills/roadmap-communicator` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b70 | `product-team/skills/ux-researcher-designer` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b71 | `engineering/human-gate/skills/human-gate` | `YARA_script_injection_generic` | CRITICAL | `scripts/review_page_builder.py` | 69 | static |
| b71 | `engineering/human-gate/skills/human-gate` | `YARA_script_injection_generic` | CRITICAL | `scripts/review_page_builder.py` | 70 | static |
| b71 | `engineering/human-gate/skills/human-gate` | `YARA_script_injection_generic` | CRITICAL | `scripts/review_page_builder.py` | 82 | static |
| b71 | `engineering/human-gate/skills/human-gate` | `YARA_script_injection_generic` | CRITICAL | `scripts/review_page_builder.py` | 370 | static |
| b71 | `engineering/human-gate/skills/human-gate` | `YARA_script_injection_generic` | CRITICAL | `scripts/review_page_builder.py` | 470 | static |
| b71 | `engineering/human-gate/skills/human-gate` | `YARA_script_injection_generic` | CRITICAL | `scripts/review_page_builder.py` | 471 | static |
| b73 | `ra-qm-team/skills/agent-decision-receipts` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b74 | `engineering/skills/agent-designer` | `SOCIAL_ENG_ANTHROPIC_IMPERSONATION` | MEDIUM | `SKILL.md` |  | static |
| b74 | `engineering/skills/agent-designer` | `MANIFEST_MISSING_LICENSE` | INFO | `SKILL.md` |  | static |
| b77 | `product-team/research-summarizer/skills/research-summarizer` | `PIPELINE_TAINT_FLOW` | MEDIUM | `SKILL.md` | 11 | pipeline |

## Error cells

No case errored in the primary run.

## Determinism

Compared 480 cases after removing `timestamp`, `scan_duration_seconds`, `duration_ms`, `skill_path`, `scan_metadata.cel.elapsed_ms`, `scan_metadata.cel.projection_ms`, `scan_metadata.cel.evaluation_ms`: 480 identical, 0 differing, 0 errored in at least one run.

## Cisco's published figures

From `https://github.com/cisco-ai-defense/skill-scanner` README.md at tag 2.1.0 (`a24df340ca6056a6446a239f4a7b114b11c6073a`), lines 47-49: on MaliciousSkillBench, recall rose from 19.9% to 31.4% with the CEL layer. Every bundled CEL rule remains in `shadow`, so the default analyzers this run used correspond to the core-only figure, 19.9%, which prediction 6 is compared against.
