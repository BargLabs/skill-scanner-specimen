/**
 * Base-skill selection for the Cisco skill-scanner specimen.
 *
 * The rule is written before selection and never reads a scanner result:
 *
 *   candidates  every directory in the pinned tree that holds an entry named `SKILL.md`;
 *   exclusions  content-neutral and structural only (below), applied in a fixed order so each
 *               excluded candidate is attributed to exactly one reason;
 *   order       ascending sha256 hex of `<seed>:<path>`, with the seed frozen in the
 *               preregistration;
 *   selection   the first `count`.
 *
 * Exclusions, in order:
 *
 *   symlinked_skill_md      the `SKILL.md` entry is a symbolic link (git mode 120000): a mirror of
 *                           another candidate, not a distinct skill;
 *   hidden_path             a component of the directory path starts with `.` (tool-specific
 *                           mirror trees and hidden directories);
 *   nested_skill            the directory is an ancestor or a descendant of another candidate that
 *                           survived the two rules above, so scanning it would scan two skills, or
 *                           one skill's fixture as if it were a skill;
 *   unreproducible_entry    the directory holds a symbolic link or a submodule (git modes 120000
 *                           and 160000), which a byte-for-byte rebuild from git blobs cannot carry.
 */

import { createHash } from 'node:crypto';

export interface TreeEntry {
  /** Git mode as printed by `git ls-tree`: 100644, 100755, 120000, 160000. */
  mode: string;
  /** `blob` or `commit` (submodule). */
  type: string;
  /** Object id. */
  oid: string;
  /** Path from the repository root, `/`-separated. */
  path: string;
}

export const EXCLUSION_REASONS = [
  'symlinked_skill_md',
  'hidden_path',
  'nested_skill',
  'unreproducible_entry',
] as const;
export type ExclusionReason = (typeof EXCLUSION_REASONS)[number];

export interface SelectedBase {
  /** 1-based rank in the frozen order. */
  rank: number;
  /** Directory path from the repository root. */
  path: string;
  /** sha256 hex of `<seed>:<path>`. */
  orderKey: string;
}

export interface SelectionResult {
  candidateCount: number;
  excluded: Record<ExclusionReason, string[]>;
  eligible: string[];
  selected: SelectedBase[];
}

const SKILL_FILE = 'SKILL.md';

function skillDirOf(path: string): string | null {
  if (path === SKILL_FILE) return '';
  if (path.endsWith(`/${SKILL_FILE}`)) return path.slice(0, -(SKILL_FILE.length + 1));
  return null;
}

function isWithin(dir: string, path: string): boolean {
  return dir === '' || path.startsWith(`${dir}/`);
}

export function orderKey(seed: string, path: string): string {
  return createHash('sha256').update(`${seed}:${path}`, 'utf8').digest('hex');
}

/**
 * Applies the frozen rule to a full recursive tree listing. Refuses, rather than returning a short
 * list, when fewer than `count` candidates are eligible: a corpus of the wrong size is not the
 * preregistered corpus.
 */
export function selectBases(
  tree: readonly TreeEntry[],
  seed: string,
  count: number,
): SelectionResult {
  const candidates = new Map<string, TreeEntry>();
  for (const entry of tree) {
    const dir = skillDirOf(entry.path);
    if (dir !== null) candidates.set(dir, entry);
  }

  const excluded = Object.fromEntries(EXCLUSION_REASONS.map((r) => [r, [] as string[]])) as Record<
    ExclusionReason,
    string[]
  >;

  let surviving: string[] = [];
  for (const [dir, entry] of [...candidates.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (entry.mode === '120000') {
      excluded.symlinked_skill_md.push(dir);
    } else if (dir.split('/').some((part) => part.startsWith('.'))) {
      excluded.hidden_path.push(dir);
    } else {
      surviving.push(dir);
    }
  }

  const nested = new Set(
    surviving.filter((dir) =>
      surviving.some((other) => other !== dir && (isWithin(dir, other) || isWithin(other, dir))),
    ),
  );
  excluded.nested_skill.push(...surviving.filter((dir) => nested.has(dir)));
  surviving = surviving.filter((dir) => !nested.has(dir));

  const unreproducible = new Set(
    surviving.filter((dir) =>
      tree.some(
        (entry) =>
          isWithin(dir, entry.path) && (entry.mode === '120000' || entry.mode === '160000'),
      ),
    ),
  );
  excluded.unreproducible_entry.push(...surviving.filter((dir) => unreproducible.has(dir)));
  const eligible = surviving.filter((dir) => !unreproducible.has(dir));

  if (eligible.length < count) {
    throw new Error(`not_run: selection_short:eligible=${eligible.length}:required=${count}`);
  }

  const ordered = eligible
    .map((path) => ({ path, orderKey: orderKey(seed, path) }))
    .sort((a, b) => (a.orderKey < b.orderKey ? -1 : a.orderKey > b.orderKey ? 1 : 0));

  return {
    candidateCount: candidates.size,
    excluded,
    eligible,
    selected: ordered.slice(0, count).map((entry, index) => ({ rank: index + 1, ...entry })),
  };
}

/** Parses `git ls-tree -r -z <commit>` output. */
export function parseLsTree(output: string): TreeEntry[] {
  return output
    .split('\0')
    .filter(Boolean)
    .map((record) => {
      const tab = record.indexOf('\t');
      const [mode, type, oid] = record.slice(0, tab).split(' ');
      if (!mode || !type || !oid) throw new Error(`ls_tree_unparseable:${record}`);
      return { mode, type, oid, path: record.slice(tab + 1) };
    });
}
