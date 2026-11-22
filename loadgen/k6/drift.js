// HotelReservation mixed workload: burst-free drifting baseline (false-positive rate under
// production-like load).
//
// After a flat SETTLE_S at BASELINE_RATE, the offered rate follows
//     rate(t) = trend(t) * (1 + wander(t))
// for TAIL_S seconds:
//   trend  : one half-sine swell BASELINE_RATE -> DRIFT_PEAK_RATE -> BASELINE_RATE (a compressed
//            diurnal cycle).
//   wander : mean-reverting random walk, new knot every WANDER_STEP_S, uniform step of
//            +-WANDER_STEP_PCT (sd ~ 0.58x that), clamped to +-WANDER_PCT. Seeded, so SEED fully
//            reproduces the schedule.
// ramping-arrival-rate interpolates linearly between knots, so there are no step edges. Wander is
// kept well below the smallest burst we score (+33% staircase step) and changes over seconds, not
// sub-second, so every detection in this scenario is unambiguously a false positive.
//
// Total duration is SETTLE_S + TAIL_S, the same contract as bursts.js with N_BURSTS=0, so run.sh
// and score_run.py's baseline-only path work unchanged. No "plan: NNN" lines are emitted.

import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';
import {
  envNum, baseK6Options, mulberry32, pickRequest, utcNanos, commonSummaryLines,
} from './workload-lib.js';

// ── configuration ────────────────────────────────────────────────────────────

const TARGET = __ENV.TARGET || 'http://172.18.0.2:30500';
const BASELINE_RATE = envNum('BASELINE_RATE', 2500);
const DRIFT_PEAK_RATE = envNum('DRIFT_PEAK_RATE', 3000);
const WANDER_PCT = envNum('WANDER_PCT', 8);          // 0 = pure trend, no wander
const WANDER_STEP_PCT = envNum('WANDER_STEP_PCT', 3.5);
const WANDER_PHI = envNum('WANDER_PHI', 0.9);        // mean reversion per knot (1 = pure walk)
const WANDER_STEP_S = envNum('WANDER_STEP_S', 2);
const SETTLE_S = envNum('SETTLE_S', 4);              // matches experiments/configs/w*.conf
const TAIL_S = envNum('TAIL_S', 900);
const PRE_ALLOC_VUS = envNum('PRE_ALLOC_VUS', 400);
const MAX_VUS = envNum('MAX_VUS', 500);
const SEED = envNum('SEED', 1339);

// ── schedule ─────────────────────────────────────────────────────────────────

// Deterministic from SEED: every VU's init context rebuilds the identical list.
function buildKnots() {
  const rng = mulberry32(SEED);
  const n = Math.ceil(TAIL_S / WANDER_STEP_S);
  const knots = [];
  let w = 0;
  for (let k = 1; k <= n; k++) {
    const t = Math.min(k * WANDER_STEP_S, TAIL_S);
    w = WANDER_PHI * w + (rng() * 2 - 1) * (WANDER_STEP_PCT / 100);
    w = Math.max(-WANDER_PCT / 100, Math.min(WANDER_PCT / 100, w));
    const trend = BASELINE_RATE + (DRIFT_PEAK_RATE - BASELINE_RATE) * Math.sin((Math.PI * t) / TAIL_S);
    knots.push({ t, rate: Math.round(trend * (1 + w)) });
  }
  return knots;
}

const KNOTS = buildKnots();

function buildStages() {
  const stages = [{ target: BASELINE_RATE, duration: `${SETTLE_S}s` }];
  let prev = 0;
  for (const k of KNOTS) {
    stages.push({ target: k.rate, duration: `${Math.round((k.t - prev) * 1000)}ms` });
    prev = k.t;
  }
  return stages;
}

export const options = {
  ...baseK6Options(),
  scenarios: {
    mixed: {
      executor: 'ramping-arrival-rate',
      startRate: BASELINE_RATE,
      timeUnit: '1s',
      preAllocatedVUs: PRE_ALLOC_VUS,
      maxVUs: MAX_VUS,
      stages: buildStages(),
      gracefulStop: '5s',
    },
  },
};

// ── execution ────────────────────────────────────────────────────────────────

let rng = null;

export function setup() {
  const rates = KNOTS.map((k) => k.rate);
  console.log(`drift: baseline=${BASELINE_RATE}rps peak=${DRIFT_PEAK_RATE}rps settle=${SETTLE_S}s ` +
    `duration=${TAIL_S}s wander=+-${WANDER_PCT}% step=+-${WANDER_STEP_PCT}% phi=${WANDER_PHI} ` +
    `every ${WANDER_STEP_S}s seed=${SEED} min=${Math.min(...rates)} max=${Math.max(...rates)} target=${TARGET}`);
  // Offered-rate path, seconds after the settle phase ends. Not "plan: NNN" (score_run.py's PLAN_RE).
  for (const k of KNOTS) console.log(`drift_knot: ${k.t} ${k.rate}`);
}

export default function () {
  if (rng === null) rng = mulberry32(SEED + exec.vu.idInTest);

  if (exec.scenario.iterationInInstance === 0) {
    const st = exec.scenario.startTime;
    console.log(`scenario_start: ${st * 1e6} ns  ${utcNanos(st)} UTC`);
  }

  const elapsed = Date.now() - exec.scenario.startTime;
  const req = pickRequest(rng);
  const res = http.request(req.method, TARGET + req.path, null, {
    tags: { phase: elapsed < SETTLE_S * 1000 ? 'settle' : 'drift', kind: req.kind, name: req.kind },
  });
  check(res, { 'status is 200': (r) => r.status === 200 });
}

export function handleSummary(data) {
  return { stdout: commonSummaryLines(data).join('\n') + '\n\n' };
}
