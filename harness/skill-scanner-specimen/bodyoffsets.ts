/**
 * The scanner's own `SKILL.md` body offset, per case.
 *
 * Some of the scanner's code paths report a `SKILL.md` line counted from the first line after the
 * frontmatter. Converting those to physical lines needs the exact offset the scanner computed,
 * which depends on python-frontmatter's handling of the frontmatter block. Rather than re-implement
 * that, the score asks the pinned package itself: one call to `SkillLoader._parse_skill_md`
 * (loader.py:294-346) per case, in the pinned venv, with an empty environment. It reads only the
 * corpus files and makes no network call.
 */

import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

import type { CorpusManifest } from './corpus.js';

export const BODY_OFFSET_PROBE = `
import json, sys
from pathlib import Path
from skill_scanner.core.loader import SkillLoader
out = {}
for case_id, skill_dir in json.loads(sys.stdin.read()):
    d = Path(skill_dir)
    try:
        _manifest, _body, offset = SkillLoader()._parse_skill_md(d / "SKILL.md", package_root=d)
    except Exception:
        continue
    out[case_id] = offset
print(json.dumps(out))
`;

export type BodyOffsetProbe = (
  venvPython: string,
  cases: [string, string][],
) => Record<string, number>;

export const runBodyOffsetProbe: BodyOffsetProbe = (venvPython, cases) =>
  JSON.parse(
    execFileSync(venvPython, ['-I', '-c', BODY_OFFSET_PROBE], {
      env: {},
      encoding: 'utf8',
      input: JSON.stringify(cases),
      maxBuffer: 1 << 26,
    }),
  ) as Record<string, number>;

export function bodyOffsetsFor(
  manifest: CorpusManifest,
  corpusDir: string,
  venvPython: string,
  probe: BodyOffsetProbe = runBodyOffsetProbe,
): Record<string, number> {
  const cases = manifest.cases
    .filter((c) => c.variant !== null)
    .map((c): [string, string] => [c.caseId, resolve(corpusDir, c.skillDir)]);
  // A case whose frontmatter the strict loader rejects gets no offset. The scanner scores such a
  // case in its inert fallback, which the runner records as `analyzer_failed`, so no offset is
  // read for it; the scorer refuses loudly if one is ever needed and absent.
  return probe(venvPython, cases);
}
