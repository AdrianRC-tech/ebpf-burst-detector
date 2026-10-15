// HotelReservation mixed workload: staircase scenario (D).
//
// Steps abruptly from below-baseline, through baseline, up to the burst-size rate we want the
// CUSUM detector to catch, then back down through the same steps — one level held for STEP_MS
// per transition. See CLAUDE.md Testing / the k6 README for the scenario rationale.

import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';
import {
  envNum, pad3, baseK6Options, mulberry32, pickRequest, utcNanos, commonSummaryLines, val,
} from './workload-lib.js';

// ── configuration ────────────────────────────────────────────────────────────

const TARGET = __ENV.TARGET || 'http://172.18.0.2:30500';
const STEP_MS = envNum('STEP_MS', 500);
const N_CYCLES = envNum('N_CYCLES', 1);
const GAP_S = envNum('GAP_S', 5);
const SETTLE_S = envNum('SETTLE_S', 100);
const TAIL_S = envNum('TAIL_S', 30);
const PRE_ALLOC_VUS = envNum('PRE_ALLOC_VUS', 20);
const MAX_VUS = envNum('MAX_VUS', 80);
const SEED = envNum('SEED', 1338);

const SETTLE_MS = SETTLE_S * 1000;
const GAP_MS = GAP_S * 1000;

// The staircase itself: below-baseline, up through baseline, to the burst-size rate the detector
// should catch, then back down through the same levels. This array is the single source of truth
// for the scenario's shape — not env-tunable, since STEP_MS is the only axis worth varying
// per run; everything below (settle/gap hold rate, startRate, per-step reporting) derives from it.
const LEVELS = [50, 100, 150, 200, 150, 100, 50];
const STEPS_PER_CYCLE = LEVELS.length;
const CYCLE_MS = STEPS_PER_CYCLE * STEP_MS + GAP_MS;
const FLOOR_RATE = LEVELS[0];
const PEAK_RATE = Math.max(...LEVELS);

// ── schedule ─────────────────────────────────────────────────────────────────

// Every level transition is abrupt: a zero-duration stage jumps the arrival rate, then a
// STEP_MS-long stage holds it. A GAP_MS hold at FLOOR_RATE separates cycles.
function buildStages() {
  const stages = [{ target: FLOOR_RATE, duration: `${SETTLE_MS}ms` }];
  for (let c = 0; c < N_CYCLES; c++) {
    for (let s = 0; s < LEVELS.length; s++) {
      stages.push({ target: LEVELS[s], duration: '0s' });
      stages.push({ target: LEVELS[s], duration: `${STEP_MS}ms` });
    }
    stages.push({ target: FLOOR_RATE, duration: '0s' });
    stages.push({ target: FLOOR_RATE, duration: `${GAP_MS}ms` });
  }
  stages.push({ target: FLOOR_RATE, duration: `${TAIL_S}s` });
  return stages;
}

// Steps are numbered globally (cycle * STEPS_PER_CYCLE + step-within-cycle), matching bursts.js's
// flat burst_NNN numbering convention.
function phaseAt(elapsedMs) {
  if (elapsedMs < SETTLE_MS) return 'settle';
  const t = elapsedMs - SETTLE_MS;
  const cycleIdx = Math.floor(t / CYCLE_MS);
  if (cycleIdx >= N_CYCLES) return 'base';
  const tc = t % CYCLE_MS;
  if (tc >= STEPS_PER_CYCLE * STEP_MS) return 'base'; // inter-cycle GAP_MS hold
  const stepIdx = Math.floor(tc / STEP_MS);
  return `step_${pad3(cycleIdx * STEPS_PER_CYCLE + stepIdx)}`;
}

const TOTAL_STEPS = N_CYCLES * STEPS_PER_CYCLE;

// See bursts.js: these are threshold declarations (count>=0 can never fail), not assertions —
// declaring them is what makes the tag-filtered sub-metric exist in handleSummary.
function buildThresholds() {
  const t = { dropped_iterations: ['count>=0'] };
  for (let i = 0; i < TOTAL_STEPS; i++) {
    t[`http_reqs{phase:step_${pad3(i)}}`] = ['count>=0'];
  }
  return t;
}

export const options = {
  ...baseK6Options(),
  scenarios: {
    staircase: {
      executor: 'ramping-arrival-rate',
      startRate: FLOOR_RATE,
      timeUnit: '1s',
      preAllocatedVUs: PRE_ALLOC_VUS,
      maxVUs: MAX_VUS,
      stages: buildStages(),
      gracefulStop: '5s',
    },
  },
  thresholds: buildThresholds(),
};

// ── execution ────────────────────────────────────────────────────────────────

let rng = null;

export function setup() {
  const t0 = Date.now();
  console.log(`plan: floor=${FLOOR_RATE}rps peak=${PEAK_RATE}rps ` +
    `levels=[${LEVELS.join(',')}] step=${STEP_MS}ms cycles=${N_CYCLES} gap=${GAP_S}s target=${TARGET}`);
  console.log('plan: step_idx  target_rps  start_ns  end_ns  start_utc  end_utc  (anchored at setup)');
  for (let c = 0; c < N_CYCLES; c++) {
    for (let s = 0; s < LEVELS.length; s++) {
      const i = c * STEPS_PER_CYCLE + s;
      const start = t0 + SETTLE_MS + c * CYCLE_MS + s * STEP_MS;
      const end = start + STEP_MS;
      console.log(
        `plan: ${pad3(i)}  ${LEVELS[s]}  ${start * 1e6}  ${end * 1e6}  ${utcNanos(start)}  ${utcNanos(end)}`
      );
    }
  }
  return { t0 };
}

export default function () {
  if (rng === null) rng = mulberry32(SEED + exec.vu.idInTest);

  // The executor owns step timing; this only labels the request for per-step accounting.
  const elapsed = Date.now() - exec.scenario.startTime;

  if (exec.scenario.iterationInInstance === 0) {
    const st = exec.scenario.startTime;
    console.log(`scenario_start: ${st * 1e6} ns  ${utcNanos(st)} UTC`);
  }

  const req = pickRequest(rng);
  const res = http.request(req.method, TARGET + req.path, null, {
    tags: { phase: phaseAt(elapsed), kind: req.kind, name: req.kind },
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}

// ── reporting ────────────────────────────────────────────────────────────────

export function handleSummary(data) {
  const out = commonSummaryLines(data);

  if (TOTAL_STEPS > 0) {
    out.push('');
    out.push('  step   target_rps   requests   expected');
    for (let i = 0; i < TOTAL_STEPS; i++) {
      const level = LEVELS[i % STEPS_PER_CYCLE];
      const expected = (level * STEP_MS) / 1000;
      const c = val(data, `http_reqs{phase:step_${pad3(i)}}`, 'count');
      out.push(
        `  ${pad3(i)}   ${String(level).padStart(10)}   ${String(c).padStart(8)}   ` +
          `${String(expected).padStart(8)}`
      );
    }
  }
  out.push('');

  return { stdout: out.join('\n') + '\n' };
}
