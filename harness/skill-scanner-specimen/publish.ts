/**
 * Renders the specimen result as JSON and Markdown from one `ScoreResult`.
 *
 * Every figure in the Markdown is formatted from the same object the JSON serialises, so the two
 * cannot disagree; `assertMarkdownMatchesJson` re-derives each prediction row from the JSON and
 * refuses if the Markdown does not carry it verbatim. The limits paragraph comes first, as the
 * preregistration requires. The corpus itself is never written here: only its digest.
 */

import { canonicalJson } from '../jev-judge/corpus.js';
import type { CorpusManifest } from './corpus.js';
import type { FrozenConfig } from './frozen.js';
import type { RunRecord } from './run.js';
import type { Cell, ScoreResult } from './score.js';
import { VARIANT_IDS } from './variants.js';

export interface PublicationContext {
  frozen: FrozenConfig;
  manifest: CorpusManifest;
  runs: RunRecord[];
}

export interface Publication {
  json: string;
  markdown: string;
}

function pct(value: number | null | undefined): string {
  return value === null || value === undefined ? 'n/a' : `${(value * 100).toFixed(1)}%`;
}

function cellRow(cell: Cell): string {
  const interval =
    cell.interval === null ? 'n/a' : `[${pct(cell.interval.lower)}, ${pct(cell.interval.upper)}]`;
  return `| \`${cell.name}\` | ${cell.n} | ${cell.errors} | ${cell.numerator} | ${pct(cell.rate)} | ${interval} | ${cell.refused ?? ''} |`;
}

const CELL_HEADER = [
  '| Cell | n | Errored | Detected | Rate | Wilson 95% | Refused |',
  '|---|---|---|---|---|---|---|',
];

function perVariant(counts: Readonly<Record<string, number>>): string {
  return VARIANT_IDS.map((v) => `\`${v}\` ${counts[v] ?? 0}`).join(', ');
}

export function predictionRow(p: ScoreResult['predictions'][number]): string {
  return `| ${p.id} | ${p.statement} | ${p.measured} | ${p.interval} | \`${p.verdict}\` | ${p.note} |`;
}

export function renderPublication(result: ScoreResult, context: PublicationContext): Publication {
  const { frozen, manifest, runs } = context;
  const cellOrder = [...VARIANT_IDS, 'pooled_package_visible', 'base'];
  const document = {
    ...result,
    subject: {
      distribution: frozen.subject.distribution,
      version: frozen.subject.version,
      wheelSha256: frozen.subject.wheelSha256,
      sourceCommit: frozen.subject.sourceCommit,
    },
    corpus: {
      baseRepository: manifest.baseRepository,
      baseCommit: manifest.baseCommit,
      seed: manifest.seed,
      selection: manifest.selection,
      counts: manifest.counts,
      corpusDigest: manifest.corpusDigest,
    },
    runs: runs.map((r) => ({
      label: r.label,
      harnessCommit: r.harnessCommit,
      preregistrationCommit: r.preregistration.commit,
      startedAt: r.startedAt,
      finishedAt: r.finishedAt,
    })),
    cisco: frozen.scoring.cisco,
  };

  const lines: string[] = [
    '# Cisco skill-scanner on a constructed known-answer corpus — result',
    '',
    '## Limits, first',
    '',
    `This is one scanner version (\`${frozen.subject.distribution}\` ${frozen.subject.version}) with its default analyzers only. The corpus is constructed: each defective case is one base skill with a single explicit insertion, so these rates are not an estimate of recall on real malicious packages. The comparison with Cisco's published recall flatters the scanner, because a single explicit insertion is easier to find than a real-world malicious package, whose malicious content is mixed into working code, spread across files, or written to evade exactly these rules.`,
    '',
    '## Corpus',
    '',
    `Bases from \`${manifest.baseRepository}\` at \`${manifest.baseCommit}\`, seed \`${manifest.seed}\`. Candidates ${manifest.selection.candidateCount}, eligible ${manifest.selection.eligibleCount}, excluded ${canonicalJson(manifest.selection.excludedCounts).replaceAll('\n', ' ')}. Cases ${manifest.counts.cases} (${manifest.counts.bases} bases, ${manifest.counts.variants} variants), read from the manifest. Corpus digest \`${manifest.corpusDigest}\`. The built corpus is not published; the generator, the base list at its pinned commit and this digest rebuild it byte for byte.`,
    '',
    '## Predictions',
    '',
    '| # | Prediction | Measured | Interval | Verdict | Note |',
    '|---|---|---|---|---|---|',
    ...result.predictions.map(predictionRow),
    '',
    '## Detection per category (high or critical, in the inserted file and lines)',
    '',
    ...CELL_HEADER,
    ...cellOrder
      .map((name) => result.cells[name])
      .filter((c): c is Cell => c !== undefined)
      .map(cellRow),
    '',
    `Prediction 3 difference (\`pipe_shell\` minus \`obfuscated_shell\`): ${result.p3Difference === null ? 'n/a' : `${(result.p3Difference.estimate * 100).toFixed(1)} points, Newcombe 95% [${(result.p3Difference.lower * 100).toFixed(1)}, ${(result.p3Difference.upper * 100).toFixed(1)}]`}.`,
    '',
    `Detections resting only on findings that report no line: ${perVariant(result.linelessOnlyDetections)}.`,
    '',
    '## CEL shadow (descriptive, not scored)',
    '',
    `Every bundled CEL rule runs in \`shadow\`, which annotates findings (\`metadata.cel.decision\`) and never adds, removes or re-grades one, so shadow decisions do not enter the primary. Detections whose every supporting finding carries a CEL \`would_suppress\`: ${perVariant(result.celWouldSuppressOnlyDetections)}.`,
    '',
    '## Secondary table (any severity, in the inserted file and lines)',
    '',
    ...CELL_HEADER,
    ...cellOrder
      .map((name) => result.secondaryAnySeverity[name])
      .filter((c): c is Cell => c !== undefined)
      .map(cellRow),
    '',
    '## Findings on the presumed-clean bases',
    '',
    ...(result.baseFindings.length === 0
      ? ['No finding of any severity on any base.']
      : [
          '| Case | Base | Rule | Severity | File | Line | Analyzer |',
          '|---|---|---|---|---|---|---|',
          ...result.baseFindings.flatMap((b) =>
            b.findings.map(
              (f) =>
                `| ${b.caseId} | \`${b.basePath}\` | \`${f.rule_id}\` | ${f.severity} | \`${f.file_path ?? ''}\` | ${f.line_number ?? ''} | ${f.analyzer ?? ''} |`,
            ),
          ),
        ]),
    '',
    '## Error cells',
    '',
    ...(Object.keys(result.errorCells).length === 0
      ? ['No case errored in the primary run.']
      : Object.entries(result.errorCells).map(
          ([status, ids]) => `- \`${status}\`: ${ids.length} (${ids.join(', ')})`,
        )),
    '',
    '## Determinism',
    '',
    `Compared ${result.determinism.comparedCases} cases after removing ${frozen.scoring.normaliseRemove.map((f) => `\`${f}\``).join(', ')}: ${result.determinism.identicalCases} identical, ${result.determinism.differingCases.length} differing, ${result.determinism.erroredCases.length} errored in at least one run.${result.determinism.differingFields.length > 0 ? ` Differing fields: ${result.determinism.differingFields.map((f) => `\`${f}\``).join(', ')}.` : ''}`,
    '',
    "## Cisco's published figures",
    '',
    `From \`${frozen.subject.sourceRepository}\` ${frozen.scoring.cisco.readmePath} at tag ${frozen.subject.sourceTag} (\`${frozen.subject.sourceCommit}\`), lines ${frozen.scoring.cisco.readmeLines}: on MaliciousSkillBench, recall rose from ${pct(frozen.scoring.cisco.coreOnlyRecall)} to ${pct(frozen.scoring.cisco.coreCelRecall)} with the CEL layer. Every bundled CEL rule remains in \`shadow\`, so the default analyzers this run used correspond to the core-only figure, ${pct(frozen.scoring.cisco.coreOnlyRecall)}, which prediction 6 is compared against.`,
    '',
  ];
  return { json: `${canonicalJson(document)}\n`, markdown: `${lines.join('\n')}` };
}

/** Refuses unless every prediction row derived from the JSON appears verbatim in the Markdown. */
export function assertMarkdownMatchesJson(publication: Publication): void {
  const parsed = JSON.parse(publication.json) as ScoreResult;
  for (const p of parsed.predictions) {
    if (!publication.markdown.includes(predictionRow(p))) {
      throw new Error(`publication_disagrees:${p.id}`);
    }
  }
}
