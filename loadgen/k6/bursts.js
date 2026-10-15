// HotelReservation mixed workload: baseline with repeated bursty windows.
//
// Covers scenarios A (N_BURSTS=0, baseline-only FP-rate check), B/C (bursts spaced GAP_S apart,
// abrupt edges), and E (RAMP_MS>0, gradual onset/drain instead of abrupt — see README.md).
//
// Baseline and every bursty window live in ONE ramping-arrival-rate scenario, so there is no
// per-burst process startup. That is what makes subsecond windows measurable: run-burst-load.sh
// forked a fresh wrk per burst, and the fork+exec+LuaJIT-load cost showed up as a ~15 ms
// window-size-independent intercept in every onset latency (conclusions from first experiments).

import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';
import {
  envNum, pad3, baseK6Options, mulberry32, pickRequest, parseMix, utcNanos, commonSummaryLines, val,
} from './workload-lib.js';

// ── configuration ────────────────────────────────────────────────────────────

const TARGET = __ENV.TARGET || 'http://172.18.0.2:30500';
const BASELINE_RATE = envNum('BASELINE_RATE', 100);
const BURSTY_WINDOW_RPS = envNum('BURSTY_WINDOW_RPS', 100);
const BURSTY_WINDOW_SIZE_MS = envNum('BURSTY_WINDOW_SIZE_MS', 800);
const N_BURSTS = envNum('N_BURSTS', 5);
const GAP_S = envNum('GAP_S', 5);
const SETTLE_S = envNum('SETTLE_S', 5);
const TAIL_S = envNum('TAIL_S', 30);
const PRE_ALLOC_VUS = envNum('PRE_ALLOC_VUS', 100);
const MAX_VUS = envNum('MAX_VUS', 100);
const SEED = envNum('SEED', 1337);
// 0 = abrupt onset/drain (scenarios A/B/C, unchanged from the original single-scenario script).
// Scenario E sets this to a few seconds so onset/drain ramp linearly instead of stepping.
const RAMP_MS = envNum('RAMP_MS', 0);
// Optional request mix for the burst's added traffic, "search,recommend,user,reserve" fractions
// summing to 1 (e.g. "0.1,0.1,0.4,0.4"). Unset = burst traffic uses the default mix.
const BURST_MIX = __ENV.BURST_MIX ? parseMix(__ENV.BURST_MIX) : null;

// Rates are additive so they read like the two-wrk2-process setup, but a k6 stage target is a
// total offered rate. Convert here, once.
const PEAK_RATE = BASELINE_RATE + BURSTY_WINDOW_RPS;

const SETTLE_MS = SETTLE_S * 1000;
const GAP_MS = GAP_S * 1000;
// Each cycle is: ramp up, hold at peak, ramp down, hold at baseline. RAMP_MS=0 collapses the
// ramp segments to zero width, reproducing the original abrupt-edge cycle exactly.
const CYCLE_MS = 2 * RAMP_MS + BURSTY_WINDOW_SIZE_MS + GAP_MS;
const EXPECTED_PER_BURST = (PEAK_RATE * BURSTY_WINDOW_SIZE_MS) / 1000;

// ── schedule ─────────────────────────────────────────────────────────────────

function buildStages() {
  const stages = [{ target: BASELINE_RATE, duration: `${SETTLE_MS}ms` }];
  for (let i = 0; i < N_BURSTS; i++) {
    stages.push({ target: PEAK_RATE, duration: `${RAMP_MS}ms` });
    stages.push({ target: PEAK_RATE, duration: `${BURSTY_WINDOW_SIZE_MS}ms` });
    stages.push({ target: BASELINE_RATE, duration: `${RAMP_MS}ms` });
    stages.push({ target: BASELINE_RATE, duration: `${GAP_MS}ms` });
  }
  stages.push({ target: BASELINE_RATE, duration: `${TAIL_S}s` });
  return stages;
}

// With RAMP_MS=0 the ramp_up/ramp_down branches are zero-width and never taken, so tagging is
// unchanged from the original abrupt-edge script.
function phaseAt(elapsedMs) {
  if (elapsedMs < SETTLE_MS) return 'settle';
  const t = elapsedMs - SETTLE_MS;
  const i = Math.floor(t / CYCLE_MS);
  if (i >= N_BURSTS) return 'base';
  const tc = t % CYCLE_MS;
  if (tc < RAMP_MS) return `ramp_up_${pad3(i)}`;
  if (tc < RAMP_MS + BURSTY_WINDOW_SIZE_MS) return `burst_${pad3(i)}`;
  if (tc < RAMP_MS + BURSTY_WINDOW_SIZE_MS + RAMP_MS) return `ramp_down_${pad3(i)}`;
  return 'base';
}

// A tag-filtered sub-metric only exists if a threshold declares it, so these thresholds are
// declarations rather than assertions — count>=0 can never fail. Without them,
// data.metrics['http_reqs{phase:burst_000}'] is absent in handleSummary and per-burst delivery
// cannot be checked. ramp_up/ramp_down are declared unconditionally too, even under RAMP_MS=0
// where they'll just always read 0 — harmless, and one less thing to toggle when switching
// scenarios.
function buildThresholds() {
  const t = { dropped_iterations: ['count>=0'] };
  for (let i = 0; i < N_BURSTS; i++) {
    t[`http_reqs{phase:burst_${pad3(i)}}`] = ['count>=0'];
    t[`http_reqs{phase:ramp_up_${pad3(i)}}`] = ['count>=0'];
    t[`http_reqs{phase:ramp_down_${pad3(i)}}`] = ['count>=0'];
  }
  return t;
}

export const options = {
  ...baseK6Options(),
  scenarios: {
    mixed: {
      executor: 'ramping-arrival-rate',
      // Required. Stages ramp linearly from the previous target and startRate defaults to 0, so
      // without this the settle stage is a slow ramp from zero rather than a flat baseline.
      startRate: BASELINE_RATE,
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
  console.log(`plan: baseline=${BASELINE_RATE}rps peak=${PEAK_RATE}rps ` +
    `window=${BURSTY_WINDOW_SIZE_MS}ms ramp=${RAMP_MS}ms n=${N_BURSTS} gap=${GAP_S}s target=${TARGET}`);
  console.log(`plan: expected ${EXPECTED_PER_BURST} requests per bursty window`);
  console.log('plan: burst_idx  start_ns  end_ns  start_utc  end_utc  (anchored at setup; ' +
    'hold-at-peak segment, excludes ramp)');
  for (let i = 0; i < N_BURSTS; i++) {
    const s = t0 + SETTLE_MS + i * CYCLE_MS + RAMP_MS;
    const e = s + BURSTY_WINDOW_SIZE_MS;
    console.log(
      `plan: ${pad3(i)}  ${s * 1e6}  ${e * 1e6}  ${utcNanos(s)}  ${utcNanos(e)}`
    );
  }
  return { t0 };
}

export default function () {
  if (rng === null) rng = mulberry32(SEED + exec.vu.idInTest);

  // The executor owns burst timing; this only labels the request for per-burst accounting.
  const elapsed = Date.now() - exec.scenario.startTime;

  if (exec.scenario.iterationInInstance === 0) {
    const st = exec.scenario.startTime;
    console.log(`scenario_start: ${st * 1e6} ns  ${utcNanos(st)} UTC`);
  }

  const phase = phaseAt(elapsed);
  // Baseline traffic keeps the default mix even during a burst; only the added traffic (its
  // BURSTY_WINDOW_RPS/PEAK_RATE share of the arrival stream) uses BURST_MIX. No extra rng()
  // draw when BURST_MIX is unset, so default runs stay identical for a given SEED.
  let mix;
  if (BURST_MIX !== null && phase.startsWith('burst_') &&
      rng() < BURSTY_WINDOW_RPS / PEAK_RATE) {
    mix = BURST_MIX;
  }
  const req = pickRequest(rng, mix);
  const res = http.request(req.method, TARGET + req.path, null, {
    tags: { phase, kind: req.kind, name: req.kind },
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}

// ── reporting ────────────────────────────────────────────────────────────────

export function handleSummary(data) {
  const out = commonSummaryLines(data);

  if (N_BURSTS > 0) {
    const counts = [];
    out.push('');
    out.push('  burst   requests   expected');
    for (let i = 0; i < N_BURSTS; i++) {
      const c = val(data, `http_reqs{phase:burst_${pad3(i)}}`, 'count');
      counts.push(c);
      out.push(
        `  ${pad3(i)}   ${String(c).padStart(8)}   ${String(EXPECTED_PER_BURST).padStart(8)}`
      );
    }
    const mean = counts.reduce((a, b) => a + b, 0) / counts.length;
    const sd = Math.sqrt(
      counts.reduce((a, b) => a + (b - mean) * (b - mean), 0) / counts.length
    );
    out.push(
      `  across ${N_BURSTS} bursts: mean ${mean.toFixed(1)}  sd ${sd.toFixed(1)}  ` +
        `cv ${((sd / mean) * 100).toFixed(1)}%  min ${Math.min(...counts)}  max ${Math.max(...counts)}`
    );
  }
  out.push('');

  return { stdout: out.join('\n') + '\n' };
}
