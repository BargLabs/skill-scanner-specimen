/**
 * Interval estimates and interval-decided verdicts for the specimen.
 *
 * A threshold-shaped prediction is decided by its 95% interval, never by its point estimate,
 * exactly as in the Jev and Laya publications: when the interval straddles the threshold the data
 * has not decided the prediction and the verdict is `not_evaluable`.
 */

import { wilsonInterval } from '../in-scope-cejel-recall-v4/report.js';

export type PredictionVerdict = 'supported' | 'contradicted' | 'not_evaluable';

export interface Interval {
  lower: number;
  upper: number;
}

export function wilson(numerator: number, denominator: number): Interval {
  const { lower, upper } = wilsonInterval(numerator, denominator);
  return { lower: Math.max(0, lower), upper: Math.min(1, upper) };
}

/**
 * Newcombe's hybrid score interval for p1 - p2 from two independent proportions (Newcombe 1998,
 * Statistics in Medicine 17:873, method 10), built from the two Wilson intervals.
 */
export function newcombeDifference(
  x1: number,
  n1: number,
  x2: number,
  n2: number,
): Interval & { estimate: number } {
  const p1 = x1 / n1;
  const p2 = x2 / n2;
  const w1 = wilson(x1, n1);
  const w2 = wilson(x2, n2);
  const estimate = p1 - p2;
  return {
    estimate,
    lower: estimate - Math.sqrt((p1 - w1.lower) ** 2 + (w2.upper - p2) ** 2),
    upper: estimate + Math.sqrt((w1.upper - p1) ** 2 + (p2 - w2.lower) ** 2),
  };
}

export function atLeast(interval: Interval, threshold: number): PredictionVerdict {
  if (interval.lower >= threshold) return 'supported';
  if (interval.upper < threshold) return 'contradicted';
  return 'not_evaluable';
}

export function atMost(interval: Interval, threshold: number): PredictionVerdict {
  if (interval.upper <= threshold) return 'supported';
  if (interval.lower > threshold) return 'contradicted';
  return 'not_evaluable';
}

export function greaterThan(interval: Interval, threshold: number): PredictionVerdict {
  if (interval.lower > threshold) return 'supported';
  if (interval.upper <= threshold) return 'contradicted';
  return 'not_evaluable';
}
