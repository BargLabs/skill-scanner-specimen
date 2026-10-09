/**
 * Scoring for the Cisco skill-scanner specimen.
 *
 * Applies the frozen detection rule to the primary run, computes each cell with its Wilson
 * interval, the prediction-3 difference with its Newcombe interval and the prediction-5 base rate,
 * compares the two runs after the frozen normalisation, and scores each prediction.
 *
 * Cell refusal follows the preregistration: a cell is refused, and every prediction resting on it
 * is `not_evaluable`, only when it is empty or any of its cases errored. A rate of zero or one is
 * scored on its Wilson interval, which is defined at both ends: the Jev and Laya zero-cell and
 * perfect-cell rule does not apply to this specimen (operator amendment of 2026-10-01, before any
 * scan; under it P1, P4 and P5 could never be `supported`). A refused cell still prints its counts;
 * it is never dropped.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { canonicalJson } from '../jev-judge/corpus.js';
import type { CorpusManifest, ManifestCase } from './corpus.js';
import type { FrozenConfig } from './frozen.js';
import type { CaseStatus, RunRecord } from './run.js';
import {
  type Interval,
  type PredictionVerdict,
  atLeast,
  atMost,
  greaterThan,
  newcombeDifference,
  wilson,
} from './stats.js';
import { PACKAGE_VISIBLE_VARIANTS, VARIANT_IDS, type VariantId } from './variants.js';

export interface ScannerFinding {
  rule_id: string;
  severity: string;
  file_path: string | null;
  line_number: number | null;
  title: string;
  analyzer: string | null;
  category: string;
  snippet: string | null;
  /** `metadata.cel.decision` (the CEL shadow annotation), when present. */
  celDecision: string | null;
}

export interface CaseOutcome {
  caseId: string;
  variant: VariantId | null;
  baseRank: number;
  status: CaseStatus;
  findings: ScannerFinding[];
  /** Variant cases only: a high/critical finding in the inserted file and lines. */
  detected: boolean | null;
  /** Variant cases only: a finding of any severity in the inserted file and lines. */
  detectedAnySeverity: boolean | null;
  /** Variant cases only: the detection rests solely on findings that report no line. */
  detectedByLinelessOnly: boolean | null;
  /** Variant cases only: every finding the detection rests on carries a CEL `would_suppress`. */
  detectedOnlyByCelWouldSuppress: boolean | null;
}

export interface Cell {
  name: string;
  n: number;
  errors: number;
  numerator: number;
  rate: number | null;
  interval: Interval | null;
  refused: string | null;
}

export interface ScoredPrediction {
  id: string;
  statement: string;
  measured: string;
  interval: string;
  verdict: PredictionVerdict;
  note: string;
}

// ---------------------------------------------------------------------------
// Location rule
// ---------------------------------------------------------------------------

/**
 * Whether a finding is located in a case's inserted file. The scanner reports `file_path` relative
 * to the skill directory; a path is normalised by turning `\` into `/` and dropping a leading `./`.
 * Nothing else is stripped: an absolute path, or one naming another file, does not match.
 */
export function inInsertedFile(finding: ScannerFinding, c: ManifestCase): boolean {
  if (c.insertedFile === null || finding.file_path === null) return false;
  const path = finding.file_path.replaceAll('\\', '/').replace(/^\.\//, '');
  return path === c.insertedFile;
}

export type LineCoordinate = 'physical' | 'body' | 'match';

/** The coordinate system a finding's `line_number` is in, from the frozen table. */
export function lineCoordinateOf(finding: ScannerFinding, frozen: FrozenConfig): LineCoordinate {
  const matches = (rules: readonly { analyzer: string; ruleIdPrefix: string }[]) =>
    rules.some(
      (r) => finding.analyzer === r.analyzer && finding.rule_id.startsWith(r.ruleIdPrefix),
    );
  if (matches(frozen.scoring.lineCoordinates.matchRelative)) return 'match';
  if (matches(frozen.scoring.lineCoordinates.bodyRelative)) return 'body';
  return 'physical';
}

/**
 * In the inserted file and, where the scanner reports a line, within the inserted lines. The
 * reported line is read in the coordinate system of the code path that produced it: a physical
 * line as is; a body-relative line plus the scanner's own body offset for that file; a line
 * counted within the matched text cannot be converted, so the finding's snippet must occur
 * verbatim within the inserted block instead.
 */
export function locatedInInsertion(
  finding: ScannerFinding,
  c: ManifestCase,
  frozen: FrozenConfig,
  bodyOffset: number | undefined,
): boolean {
  if (!inInsertedFile(finding, c) || c.variant === null) return false;
  if (finding.line_number === null || finding.line_number === undefined) return true;
  const coordinate = lineCoordinateOf(finding, frozen);
  if (coordinate === 'match') {
    const block = frozen.corpus.variantBlocks[c.variant].join('\n');
    const snippet = (finding.snippet ?? '').trim();
    return snippet !== '' && block.includes(snippet);
  }
  let physical = finding.line_number;
  if (coordinate === 'body') {
    if (bodyOffset === undefined) throw new Error(`not_run: body_offset_absent:${c.caseId}`);
    physical += bodyOffset;
  }
  return (
    c.lineStart !== null && c.lineEnd !== null && physical >= c.lineStart && physical <= c.lineEnd
  );
}

function parseFindings(raw: string): ScannerFinding[] {
  const parsed = JSON.parse(raw) as { findings: Record<string, unknown>[] };
  return parsed.findings.map((f) => {
    const metadata = (f.metadata ?? {}) as { cel?: { decision?: unknown } };
    return {
      rule_id: String(f.rule_id ?? ''),
      severity: String(f.severity ?? ''),
      file_path: typeof f.file_path === 'string' ? f.file_path : null,
      line_number: typeof f.line_number === 'number' ? f.line_number : null,
      title: String(f.title ?? ''),
      analyzer: typeof f.analyzer === 'string' ? f.analyzer : null,
      category: String(f.category ?? ''),
      snippet: typeof f.snippet === 'string' ? f.snippet : null,
      celDecision: typeof metadata.cel?.decision === 'string' ? metadata.cel.decision : null,
    };
  });
}

export function outcomeFor(
  frozen: FrozenConfig,
  c: ManifestCase,
  status: CaseStatus,
  raw: string | null,
  bodyOffset?: number,
): CaseOutcome {
  const findings = status === 'ok' && raw !== null ? parseFindings(raw) : [];
  const severe = new Set(frozen.scoring.detectSeverities);
  const any = new Set(frozen.scoring.secondarySeverities);
  if (c.variant === null || status !== 'ok') {
    return {
      caseId: c.caseId,
      variant: c.variant,
      baseRank: c.baseRank,
      status,
      findings,
      detected: null,
      detectedAnySeverity: null,
      detectedByLinelessOnly: null,
      detectedOnlyByCelWouldSuppress: null,
    };
  }
  const located = findings.filter((f) => locatedInInsertion(f, c, frozen, bodyOffset));
  const severeLocated = located.filter((f) => severe.has(f.severity));
  return {
    caseId: c.caseId,
    variant: c.variant,
    baseRank: c.baseRank,
    status,
    findings,
    detected: severeLocated.length > 0,
    detectedAnySeverity: located.some((f) => any.has(f.severity)),
    detectedByLinelessOnly:
      severeLocated.length > 0 && severeLocated.every((f) => f.line_number === null),
    detectedOnlyByCelWouldSuppress:
      severeLocated.length > 0 && severeLocated.every((f) => f.celDecision === 'would_suppress'),
  };
}

// ---------------------------------------------------------------------------
// Cells
// ---------------------------------------------------------------------------

export function cellOf(
  name: string,
  outcomes: readonly CaseOutcome[],
  hit: (o: CaseOutcome) => boolean,
): Cell {
  const n = outcomes.length;
  const errors = outcomes.filter((o) => o.status !== 'ok').length;
  const numerator = outcomes.filter((o) => o.status === 'ok' && hit(o)).length;
  let refused: string | null = null;
  if (n === 0) refused = 'empty_cell';
  else if (errors > 0) refused = `scanner_error:${errors}`;
  const scored = n - errors;
  return {
    name,
    n,
    errors,
    numerator,
    rate: scored > 0 ? numerator / scored : null,
    interval: scored > 0 ? wilson(numerator, scored) : null,
    refused,
  };
}

// ---------------------------------------------------------------------------
// Determinism (prediction 7)
// ---------------------------------------------------------------------------

/**
 * Removes the frozen time- and path-varying fields and re-serialises with the scanner's own key
 * order and array order preserved: sorting keys or findings here would hide exactly the run-to-run
 * variation prediction 7 tests. A path segment `[]` applies the rest of the path to every element.
 */
export function normaliseOutput(raw: string, remove: readonly string[]): string {
  const value = JSON.parse(raw) as unknown;
  for (const path of remove) deletePath(value, path.split('.'));
  return JSON.stringify(value);
}

function deletePath(value: unknown, segments: readonly string[]): void {
  if (value === null || typeof value !== 'object' || segments.length === 0) return;
  const [head, ...rest] = segments as [string, ...string[]];
  if (head.endsWith('[]')) {
    const key = head.slice(0, -2);
    const array = key === '' ? value : (value as Record<string, unknown>)[key];
    if (Array.isArray(array)) for (const item of array) deletePath(item, rest);
    return;
  }
  if (rest.length === 0) {
    delete (value as Record<string, unknown>)[head];
    return;
  }
  deletePath((value as Record<string, unknown>)[head], rest);
}

export interface DeterminismCheck {
  comparedCases: number;
  identicalCases: number;
  differingCases: string[];
  differingFields: string[];
  erroredCases: string[];
}

function diffFields(a: unknown, b: unknown, prefix: string, out: Set<string>): void {
  if (canonicalJson(a) === canonicalJson(b) && JSON.stringify(a) === JSON.stringify(b)) return;
  if (
    a &&
    b &&
    typeof a === 'object' &&
    typeof b === 'object' &&
    !Array.isArray(a) &&
    !Array.isArray(b)
  ) {
    const keysA = Object.keys(a as object);
    const keysB = Object.keys(b as object);
    if (
      keysA.join('\0') !== keysB.join('\0') &&
      [...keysA].sort().join('\0') === [...keysB].sort().join('\0')
    ) {
      out.add(`${prefix || '<root>'}:key_order`);
    }
    for (const key of new Set([...keysA, ...keysB])) {
      diffFields(
        (a as Record<string, unknown>)[key],
        (b as Record<string, unknown>)[key],
        prefix ? `${prefix}.${key}` : key,
        out,
      );
    }
    return;
  }
  if (Array.isArray(a) && Array.isArray(b) && a.length === b.length) {
    a.forEach((item, i) => diffFields(item, b[i], `${prefix}[]`, out));
    return;
  }
  out.add(prefix || '<root>');
}

export function compareRuns(
  frozen: FrozenConfig,
  manifest: CorpusManifest,
  first: { record: RunRecord; raw: (caseId: string) => string },
  second: { record: RunRecord; raw: (caseId: string) => string },
): DeterminismCheck {
  const statusA = new Map(first.record.cases.map((c) => [c.caseId, c.status]));
  const statusB = new Map(second.record.cases.map((c) => [c.caseId, c.status]));
  const differing: string[] = [];
  const errored: string[] = [];
  const fields = new Set<string>();
  let identical = 0;
  for (const c of manifest.cases) {
    if (statusA.get(c.caseId) !== 'ok' || statusB.get(c.caseId) !== 'ok') {
      errored.push(c.caseId);
      continue;
    }
    const a = normaliseOutput(first.raw(c.caseId), frozen.scoring.normaliseRemove);
    const b = normaliseOutput(second.raw(c.caseId), frozen.scoring.normaliseRemove);
    if (a === b) {
      identical++;
    } else {
      differing.push(c.caseId);
      diffFields(JSON.parse(a), JSON.parse(b), '', fields);
    }
  }
  return {
    comparedCases: manifest.cases.length,
    identicalCases: identical,
    differingCases: differing,
    differingFields: [...fields].sort(),
    erroredCases: errored,
  };
}

// ---------------------------------------------------------------------------
// Predictions
// ---------------------------------------------------------------------------

export const PREDICTION_STATEMENTS: Readonly<Record<string, string>> = {
  P1: 'Detection of `pipe_shell` is at least 90%.',
  P2: 'Detection of `prose_exfil` is at most 50%.',
  P3: 'Detection of `obfuscated_shell` is at least 30 percentage points lower than detection of `pipe_shell`.',
  P4: 'Detection of `remote_content` is at most 10%.',
  P5: 'High or critical findings on the 80 presumed-clean bases are at most 5% of bases.',
  P6: "Detection pooled across the four package-visible categories (`pipe_shell`, `prose_exfil`, `prompt_injection`, `obfuscated_shell`) is above 19.88%, Cisco's published core-only recall.",
  P7: 'Two full runs of the scanner over the corpus produce byte-identical normalised output.',
};

function pct(value: number | null): string {
  return value === null ? 'n/a' : `${(value * 100).toFixed(1)}%`;
}

function intervalText(interval: Interval | null): string {
  return interval === null ? 'n/a' : `[${pct(interval.lower)}, ${pct(interval.upper)}]`;
}

function cellMeasured(cell: Cell): string {
  return `${cell.numerator}/${cell.n - cell.errors} (${pct(cell.rate)})${cell.errors ? `, ${cell.errors} errored` : ''}`;
}

function rateVerdict(cell: Cell, test: (i: Interval) => PredictionVerdict): PredictionVerdict {
  if (cell.refused !== null || cell.interval === null) return 'not_evaluable';
  return test(cell.interval);
}

function refusalNote(cells: readonly Cell[]): string {
  const refused = cells.filter((c) => c.refused !== null);
  return refused.length === 0
    ? ''
    : `cell refused: ${refused.map((c) => `${c.name}=${c.refused}`).join(', ')}`;
}

export interface ScoreResult {
  protocol: string;
  frozenConfigDigest: string;
  corpusDigest: string;
  caseCount: number;
  primaryRun: string;
  cells: Record<string, Cell>;
  secondaryAnySeverity: Record<string, Cell>;
  linelessOnlyDetections: Record<string, number>;
  /** Descriptive CEL shadow table: detections every supporting finding of which CEL would suppress. */
  celWouldSuppressOnlyDetections: Record<string, number>;
  baseFindings: { caseId: string; basePath: string; findings: ScannerFinding[] }[];
  errorCells: Record<string, string[]>;
  p3Difference: { estimate: number; lower: number; upper: number } | null;
  determinism: DeterminismCheck;
  predictions: ScoredPrediction[];
}

export function scorePredictions(
  cells: Record<string, Cell>,
  p3: ScoreResult['p3Difference'],
  determinism: DeterminismCheck,
  frozen: FrozenConfig,
): ScoredPrediction[] {
  const c = (name: string): Cell => {
    const cell = cells[name];
    if (!cell) throw new Error(`score_missing_cell:${name}`);
    return cell;
  };
  const pipe = c('pipe_shell');
  const obf = c('obfuscated_shell');
  const p3Verdict: PredictionVerdict =
    pipe.refused !== null || obf.refused !== null || p3 === null
      ? 'not_evaluable'
      : atLeast(p3, 0.3);
  const p7Verdict: PredictionVerdict =
    determinism.erroredCases.length > 0
      ? 'not_evaluable'
      : determinism.differingCases.length === 0
        ? 'supported'
        : 'contradicted';
  const row = (
    id: string,
    measured: string,
    interval: string,
    verdict: PredictionVerdict,
    note: string,
  ): ScoredPrediction => ({
    id,
    statement: PREDICTION_STATEMENTS[id] ?? '',
    measured,
    interval,
    verdict,
    note,
  });

  return [
    row(
      'P1',
      cellMeasured(pipe),
      intervalText(pipe.interval),
      rateVerdict(pipe, (i) => atLeast(i, 0.9)),
      refusalNote([pipe]),
    ),
    row(
      'P2',
      cellMeasured(c('prose_exfil')),
      intervalText(c('prose_exfil').interval),
      rateVerdict(c('prose_exfil'), (i) => atMost(i, 0.5)),
      refusalNote([c('prose_exfil')]),
    ),
    row(
      'P3',
      p3 === null ? 'n/a' : `${(p3.estimate * 100).toFixed(1)} points`,
      p3 === null
        ? 'n/a'
        : `[${(p3.lower * 100).toFixed(1)}, ${(p3.upper * 100).toFixed(1)}] points (Newcombe)`,
      p3Verdict,
      refusalNote([pipe, obf]),
    ),
    row(
      'P4',
      cellMeasured(c('remote_content')),
      intervalText(c('remote_content').interval),
      rateVerdict(c('remote_content'), (i) => atMost(i, 0.1)),
      refusalNote([c('remote_content')]),
    ),
    row(
      'P5',
      cellMeasured(c('base')),
      intervalText(c('base').interval),
      rateVerdict(c('base'), (i) => atMost(i, 0.05)),
      refusalNote([c('base')]),
    ),
    row(
      'P6',
      cellMeasured(c('pooled_package_visible')),
      intervalText(c('pooled_package_visible').interval),
      rateVerdict(c('pooled_package_visible'), (i) =>
        greaterThan(i, frozen.scoring.cisco.coreOnlyRecall),
      ),
      refusalNote([c('pooled_package_visible')]),
    ),
    row(
      'P7',
      `${determinism.identicalCases}/${determinism.comparedCases - determinism.erroredCases.length} identical`,
      'n/a',
      p7Verdict,
      determinism.differingFields.length > 0
        ? `differing fields: ${determinism.differingFields.join(', ')}`
        : determinism.erroredCases.length > 0
          ? `errored in at least one run: ${determinism.erroredCases.length}`
          : '',
    ),
  ];
}

export interface ScoreInputs {
  frozen: FrozenConfig;
  frozenConfigDigest: string;
  manifest: CorpusManifest;
  /** The scanner's own `SKILL.md` body offset per variant case (`bodyoffsets.ts`). */
  bodyOffsets: Readonly<Record<string, number>>;
  first: { record: RunRecord; raw: (caseId: string) => string };
  second: { record: RunRecord; raw: (caseId: string) => string };
}

export function score(inputs: ScoreInputs): ScoreResult {
  const { frozen, manifest, first, second } = inputs;
  for (const run of [first, second]) {
    if (run.record.corpusDigest !== manifest.corpusDigest) {
      throw new Error(`not_run: corpus_digest_mismatch:run=${run.record.label}`);
    }
    if (run.record.frozenConfigDigest !== inputs.frozenConfigDigest) {
      throw new Error(`not_run: run_under_other_config:${run.record.label}`);
    }
    if (run.record.cases.length !== manifest.cases.length) {
      throw new Error(`not_run: run_case_count:${run.record.label}:${run.record.cases.length}`);
    }
  }
  const status = new Map(first.record.cases.map((c) => [c.caseId, c.status]));
  const outcomes = manifest.cases.map((c) => {
    const s = status.get(c.caseId);
    if (s === undefined) throw new Error(`not_run: case_absent_from_run:${c.caseId}`);
    return outcomeFor(
      frozen,
      c,
      s,
      s === 'ok' ? first.raw(c.caseId) : null,
      inputs.bodyOffsets[c.caseId],
    );
  });

  const severe = new Set(frozen.scoring.detectSeverities);
  const byVariant = (v: VariantId) => outcomes.filter((o) => o.variant === v);
  const bases = outcomes.filter((o) => o.variant === null);
  const pooled = outcomes.filter(
    (o) => o.variant !== null && PACKAGE_VISIBLE_VARIANTS.includes(o.variant),
  );

  const cells: Record<string, Cell> = {};
  const secondary: Record<string, Cell> = {};
  const lineless: Record<string, number> = {};
  const celOnly: Record<string, number> = {};
  for (const v of VARIANT_IDS) {
    cells[v] = cellOf(v, byVariant(v), (o) => o.detected === true);
    secondary[v] = cellOf(v, byVariant(v), (o) => o.detectedAnySeverity === true);
    lineless[v] = byVariant(v).filter((o) => o.detectedByLinelessOnly === true).length;
    celOnly[v] = byVariant(v).filter((o) => o.detectedOnlyByCelWouldSuppress === true).length;
  }
  cells.pooled_package_visible = cellOf(
    'pooled_package_visible',
    pooled,
    (o) => o.detected === true,
  );
  secondary.pooled_package_visible = cellOf(
    'pooled_package_visible',
    pooled,
    (o) => o.detectedAnySeverity === true,
  );
  cells.base = cellOf('base', bases, (o) => o.findings.some((f) => severe.has(f.severity)));
  secondary.base = cellOf('base', bases, (o) => o.findings.length > 0);

  const pipe = cells.pipe_shell as Cell;
  const obf = cells.obfuscated_shell as Cell;
  const p3 =
    pipe.n - pipe.errors > 0 && obf.n - obf.errors > 0
      ? newcombeDifference(pipe.numerator, pipe.n - pipe.errors, obf.numerator, obf.n - obf.errors)
      : null;

  const errorCells: Record<string, string[]> = {};
  for (const o of outcomes) {
    if (o.status !== 'ok') errorCells[o.status] = [...(errorCells[o.status] ?? []), o.caseId];
  }

  const determinism = compareRuns(frozen, manifest, first, second);
  const caseById = new Map(manifest.cases.map((c) => [c.caseId, c]));
  return {
    protocol: frozen.protocol,
    frozenConfigDigest: inputs.frozenConfigDigest,
    corpusDigest: manifest.corpusDigest,
    caseCount: manifest.cases.length,
    primaryRun: first.record.label,
    cells,
    secondaryAnySeverity: secondary,
    linelessOnlyDetections: lineless,
    celWouldSuppressOnlyDetections: celOnly,
    baseFindings: bases
      .filter((o) => o.findings.length > 0)
      .map((o) => ({
        caseId: o.caseId,
        basePath: caseById.get(o.caseId)?.basePath ?? '',
        findings: o.findings,
      })),
    errorCells,
    p3Difference: p3,
    determinism,
    predictions: scorePredictions(cells, p3, determinism, frozen),
  };
}

export function rawReader(runRoot: string, label: string): (caseId: string) => string {
  return (caseId) => {
    const path = join(runRoot, label, 'raw', `${caseId}.json`);
    if (!existsSync(path)) throw new Error(`not_run: raw_output_absent:${label}:${caseId}`);
    return readFileSync(path, 'utf8');
  };
}
