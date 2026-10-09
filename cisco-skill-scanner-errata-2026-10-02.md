# Cisco skill-scanner specimen — erratum 1 (reading notes on the unedited result)

Date: 2026-10-02
Applies to: `docs/experiments/cisco-skill-scanner-result-2026-10-01/` (harness `15ee0adf`, preregistration `7f15c835`)

This erratum changes no figure, verdict or file in the result. The result is published exactly as the harness wrote it. These notes record three things found when the result was reviewed, so that no reader takes a figure for more than it shows.

## 1. Most of the any-severity table's `remote_content` detections, and some of its `prose_exfil` detections, are not detections of the insertion

The frozen location rule says: "A finding with no `line_number` is located by its file alone." The scanner reports some findings about `SKILL.md` as a whole, with no line number. The most common one is `MANIFEST_MISSING_LICENSE` (INFO), which fires on every base whose frontmatter lacks a licence field. Under the frozen rule, such a finding counts as located in the inserted file. In the any-severity table, it therefore counts as detecting whatever was inserted.

From the raw run-1 output:
- **`remote_content`:** 37 cases have any finding on `SKILL.md`. In 34 of them, every finding has no line number. The table's 36 of 80 is therefore almost entirely the base's own missing-licence finding, not a response to the inserted link.
- **`prose_exfil`:** 70 cases have any finding on `SKILL.md`. In 11 of them, every finding has no line number.
- **The other three categories:** their detections rest on line-located findings. These are `CORRELATED_NETWORK_EXECUTION_FLOW` for `pipe_shell`, `PROMPT_INJECTION_IGNORE_INSTRUCTIONS` for `prompt_injection`, and `YARA_SUSP_Lnx_EncodedShell_DecodeExec_Sep26`, `CORRELATED_OBFUSCATION_EXECUTION_FLOW` and `PIPELINE_TAINT_FLOW` for `obfuscated_shell`.

The primary table (high or critical) is not affected. The result's own count of primary detections resting only on lineless findings is 0 in every category. The any-severity table was descriptive and carried no prediction. The defect is in the preregistered rule, not in the harness: a whole-file finding should not have been allowed to locate an insertion. A future specimen excludes lineless findings from location, or reports them in a separate column for every table.

## 2. `prose_exfil` is flagged, but below the detection threshold

At high or critical, `prose_exfil` is 0 of 80. At any severity, most cases do carry a finding on the inserted text: `YARA_tool_chaining_abuse_generic` at MEDIUM, on 59 cases. The scanner sees the instruction to send a credentials file to a remote host, and grades it MEDIUM. Prediction 2 is scored on high or critical, as preregistered.

## 3. Cisco's figures are rounded in one sentence of the rendered result

The closing paragraph of the result's Markdown says 19.9% and 31.4%. The README at tag 2.1.0 (lines 47-49) says 19.88% and 31.43%. The scored threshold for prediction 6 is the exact figure, 0.1988 (`frozen.ts`, and `cisco.coreOnlyRecall` in the result JSON). The rounding is in the rendered sentence only.

## Run history

A first attempt at run 1, on 2026-10-02 at about 00:32 BST, was interrupted after 32 of 480 cases: the dispatching agent's session ended and the background scan stopped with it. That partial run is kept outside the repository, at `~/.cache/alfred-cisco-specimen/aborted/run-1-interrupted-20261002T0032`. It was not scored and is not part of the result. Runs 1 and 2 were then made in full, in order, from a clean checkout of `origin/main` at `15ee0adf`, with the signed preregistration `7f15c835` as an ancestor:
- run 1, 23:35 to 23:57 UTC, 480 of 480 ok;
- run 2, 23:57 to 00:18 UTC, 480 of 480 ok.

Both runs scanned the corpus with digest `40b18ec8a386c6e7fad8c8adc6ce33ab90c0d955b603704dc1b7bf828b752a9d`.
