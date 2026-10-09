# Imports from outside this directory

The harness is copied verbatim from `packages/bede/src/` in the Barg Labs alfred repository at `041109a7989725ff28578250134d3225a829a7db`. It is not packaged to run on its own. It imports three helpers from elsewhere in that tree; each is reproduced here verbatim, with its source path and lines at the same commit. The test file also imports a git-fixture helper (`scripts/lib/test-git-fixture.mjs`), which is not published.

## `../jev-judge/corpus.js`: `canonicalJson`, `sha256Hex` (`packages/bede/src/jev-judge/corpus.ts`, lines 13 and 50-66)

```ts
import { createHash } from 'node:crypto';

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value), null, 2);
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, entry]) => [key, sortKeys(entry)]),
  );
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}
```

## `../in-scope-cejel-recall-v4/report.js`: `wilsonInterval` (`packages/bede/src/in-scope-cejel-recall-v4/report.ts`, lines 10-15 and 50-72; `WILSON_Z_95` from `constants.ts`, line 46)

```ts
export const WILSON_Z_95 = 1.959963984540054;

export interface WilsonInterval {
  confidence: 0.95;
  z: number;
  lower: number;
  upper: number;
}

export function wilsonInterval(numerator: number, denominator: number): WilsonInterval {
  if (!Number.isInteger(numerator) || !Number.isInteger(denominator)) {
    throw new Error('wilson_counts_must_be_integers');
  }
  if (denominator <= 0 || numerator < 0 || numerator > denominator) {
    throw new Error('wilson_counts_out_of_range');
  }
  const proportion = numerator / denominator;
  const zSquared = WILSON_Z_95 ** 2;
  const denominatorAdjustment = 1 + zSquared / denominator;
  const center = (proportion + zSquared / (2 * denominator)) / denominatorAdjustment;
  const margin =
    (WILSON_Z_95 / denominatorAdjustment) *
    Math.sqrt(
      (proportion * (1 - proportion)) / denominator + zSquared / (4 * denominator * denominator),
    );
  return {
    confidence: 0.95,
    z: WILSON_Z_95,
    lower: center - margin,
    upper: center + margin,
  };
}
```
