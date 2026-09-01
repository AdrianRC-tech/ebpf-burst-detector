// HotelReservation mixed workload with subsecond bursty windows.
//
// Baseline and every bursty window live in ONE ramping-arrival-rate scenario, so there is no
// per-burst process startup. That is what makes subsecond windows measurable: run-burst-load.sh
// forked a fresh wrk per burst, and the fork+exec+LuaJIT-load cost showed up as a ~15 ms
// window-size-independent intercept in every onset latency (conclusions from first experiments).

import http from 'k6/http';
import exec from 'k6/execution';

// ── configuration ────────────────────────────────────────────────────────────

function envNum(name, dflt) {
  const v = __ENV[name];
  return v === undefined || v === '' ? dflt : Number(v);
}

const TARGET = __ENV.TARGET || 'http://172.18.0.2:30500';
const BASELINE_RATE = envNum('BASELINE_RATE', 100);
const BURSTY_WINDOW_RPS = envNum('BURSTY_WINDOW_RPS', 100);
const BURSTY_WINDOW_SIZE_MS = envNum('BURSTY_WINDOW_SIZE_MS', 800);
const N_BURSTS = envNum('N_BURSTS', 10);
const GAP_S = envNum('GAP_S', 5);
const SETTLE_S = envNum('SETTLE_S', 100);
const TAIL_S = envNum('TAIL_S', 30);
const PRE_ALLOC_VUS = envNum('PRE_ALLOC_VUS', 20);
const MAX_VUS = envNum('MAX_VUS', 80);
const SEED = envNum('SEED', 1337);

// Rates are additive so they read like the two-wrk2-process setup, but a k6 stage target is a
// total offered rate. Convert here, once.
const PEAK_RATE = BASELINE_RATE + BURSTY_WINDOW_RPS;

const SETTLE_MS = SETTLE_S * 1000;
const GAP_MS = GAP_S * 1000;
const CYCLE_MS = BURSTY_WINDOW_SIZE_MS + GAP_MS;
const EXPECTED_PER_BURST = (PEAK_RATE * BURSTY_WINDOW_SIZE_MS) / 1000;

// ── schedule ─────────────────────────────────────────────────────────────────

function pad3(i) {
  return String(i).padStart(3, '0');
}

// Zero-duration stages step instantly; every other stage ramps linearly from the previous target.
function buildStages() {
  const stages = [{ target: BASELINE_RATE, duration: `${SETTLE_MS}ms` }];
  for (let i = 0; i < N_BURSTS; i++) {
    stages.push({ target: PEAK_RATE, duration: '0s' });
    stages.push({ target: PEAK_RATE, duration: `${BURSTY_WINDOW_SIZE_MS}ms` });
    stages.push({ target: BASELINE_RATE, duration: '0s' });
    stages.push({ target: BASELINE_RATE, duration: `${GAP_MS}ms` });
  }
  stages.push({ target: BASELINE_RATE, duration: `${TAIL_S}s` });
  return stages;
}

function phaseAt(elapsedMs) {
  if (elapsedMs < SETTLE_MS) return 'settle';
  const t = elapsedMs - SETTLE_MS;
  const i = Math.floor(t / CYCLE_MS);
  if (i >= N_BURSTS) return 'base';
  return t % CYCLE_MS < BURSTY_WINDOW_SIZE_MS ? `burst_${pad3(i)}` : 'base';
}

// A tag-filtered sub-metric only exists if a threshold declares it, so these thresholds are
// declarations rather than assertions — count>=0 can never fail. Without them,
// data.metrics['http_reqs{phase:burst_000}'] is absent in handleSummary and per-burst delivery
// cannot be checked.
function buildThresholds() {
  const t = { dropped_iterations: ['count>=0'] };
  for (let i = 0; i < N_BURSTS; i++) {
    t[`http_reqs{phase:burst_${pad3(i)}}`] = ['count>=0'];
  }
  return t;
}

export const options = {
  // Bodies still cross the wire and are still counted at the netkit peer; this only stops k6
  // from materialising them, which keeps loader-side jitter off the burst edge.
  discardResponseBodies: true,
  // p(99) is not in k6's default trend set; the capacity probe in docs/experiment-methodology.md
  // gates on it, so ask for it explicitly.
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
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

// ── workload ─────────────────────────────────────────────────────────────────

function mulberry32(a) {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Lua's math.random(m, n) includes both bounds.
function randInt(rng, m, n) {
  return m + Math.floor(rng() * (n - m + 1));
}

// LuaJIT's tostring() on a number is sprintf("%.14g"), while JS String() is shortest-round-trip.
// The coordinates below land on values where those differ (Lua "38.005" vs JS
// "38.004999999999995"), which would shift bytes-per-request and therefore mu_0.
function fmtG14(x) {
  let s = x.toPrecision(14);
  if (s.indexOf('e') === -1 && s.indexOf('.') !== -1) {
    s = s.replace(/0+$/, '').replace(/\.$/, '');
  }
  return s;
}

function aprilDate(day) {
  return day <= 9 ? `2015-04-0${day}` : `2015-04-${day}`;
}

function getUser(rng) {
  const id = randInt(rng, 0, 500);
  return { username: `Cornell_${id}`, password: String(id).repeat(10) };
}

function randLat(rng) {
  return fmtG14(38.0235 + (randInt(rng, 0, 481) - 240.5) / 1000.0);
}

function randLon(rng) {
  return fmtG14(-122.095 + (randInt(rng, 0, 325) - 157.0) / 1000.0);
}

function searchHotel(rng) {
  const inDate = randInt(rng, 9, 23);
  const outDate = randInt(rng, inDate + 1, 24);
  return {
    kind: 'search',
    method: 'GET',
    path:
      `/hotels?inDate=${aprilDate(inDate)}&outDate=${aprilDate(outDate)}` +
      `&lat=${randLat(rng)}&lon=${randLon(rng)}`,
  };
}

function recommend(rng) {
  // Ported verbatim: the thresholds are 0.33 / 0.66, so "price" gets 34% rather than a third.
  const coin = rng();
  let req = 'price';
  if (coin < 0.33) req = 'dis';
  else if (coin < 0.66) req = 'rate';
  return {
    kind: 'recommend',
    method: 'GET',
    path: `/recommendations?require=${req}&lat=${randLat(rng)}&lon=${randLon(rng)}`,
  };
}

function userLogin(rng) {
  const u = getUser(rng);
  return {
    kind: 'user',
    method: 'POST',
    path: `/user?username=${u.username}&password=${u.password}`,
  };
}

function reserve(rng) {
  const inDate = randInt(rng, 9, 23);
  const outDate = inDate + randInt(rng, 1, 5);
  const u = getUser(rng);
  // The Lua reserve() reads `lat`/`lon`, which are locals of search_hotel()/recommend(). They
  // resolve to nil globals there, so every reservation URL ever sent in these experiments has
  // literally contained lat=nil&lon=nil. Reproduced so results stay comparable — do not "fix".
  return {
    kind: 'reserve',
    method: 'POST',
    path:
      `/reservation?inDate=${aprilDate(inDate)}&outDate=${aprilDate(outDate)}` +
      `&lat=nil&lon=nil&hotelId=${randInt(rng, 1, 80)}&customerName=${u.username}` +
      `&username=${u.username}&password=${u.password}&number=1`,
  };
}

// Choose one of searchHotel / recommend / userLogin / reserve per call and return its result.
// The Lua target mix is 60% search, 39% recommend, 0.5% login, 0.5% reserve.
function pickRequest(rng) {
  const SEARCH_RATIO    = 0.6;
  const RECOMMEND_RATIO = 0.39;
  const USER_RATIO      = 0.005;
  // reserve gets the remaining 0.005

  const coin = rng();

  if (coin < SEARCH_RATIO) {
    return searchHotel(rng);
  } else if (coin < SEARCH_RATIO + RECOMMEND_RATIO) {
    return recommend(rng);
  } else if (coin < SEARCH_RATIO + RECOMMEND_RATIO + USER_RATIO) {
    return userLogin(rng);
  } else {
    return reserve(rng);
  }
}

// ── execution ────────────────────────────────────────────────────────────────

let rng = null;

export function setup() {
  const t0 = Date.now();
  console.log(`plan: baseline=${BASELINE_RATE}rps peak=${PEAK_RATE}rps ` +
    `window=${BURSTY_WINDOW_SIZE_MS}ms n=${N_BURSTS} gap=${GAP_S}s target=${TARGET}`);
  console.log(`plan: expected ${EXPECTED_PER_BURST} requests per bursty window`);
  console.log('plan: burst_idx  start_ns  end_ns  start_utc  end_utc  (anchored at setup)');
  for (let i = 0; i < N_BURSTS; i++) {
    const s = t0 + SETTLE_MS + i * CYCLE_MS;
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

  const req = pickRequest(rng);
  http.request(req.method, TARGET + req.path, null, {
    tags: { phase: phaseAt(elapsed), kind: req.kind },
  });
}

// ── reporting ────────────────────────────────────────────────────────────────

// Millisecond source padded to nanosecond width, to match the detector's time_utc column
// (walltime.TimeOnlyNanos = "15:04:05.000000000", which carries no date).
function utcNanos(ms) {
  const d = new Date(ms);
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  const frac = String(d.getUTCMilliseconds()).padStart(3, '0') + '000000';
  return `${hh}:${mm}:${ss}.${frac}`;
}

function val(data, key, field) {
  const m = data.metrics[key];
  return m && m.values && m.values[field] !== undefined ? m.values[field] : 0;
}

export function handleSummary(data) {
  const out = [];

  // Exporting handleSummary suppresses k6's default summary, so reprint what matters here rather
  // than importing textSummary from jslib (a remote fetch at init that fails a run with no network).
  out.push('');
  out.push('  requests        ' + val(data, 'http_reqs', 'count') +
    '  (' + val(data, 'http_reqs', 'rate').toFixed(1) + '/s)');
  out.push('  failed          ' + (val(data, 'http_req_failed', 'rate') * 100).toFixed(2) + '%');
  out.push('  duration        avg ' + val(data, 'http_req_duration', 'avg').toFixed(1) +
    'ms  p95 ' + val(data, 'http_req_duration', 'p(95)').toFixed(1) +
    'ms  p99 ' + val(data, 'http_req_duration', 'p(99)').toFixed(1) + 'ms');
  // Connection setup is the mechanism behind the ~200 ms harness intercept the wrk2 loop suffered.
  // A near-zero avg with a small max means VUs reused warm connections across bursty windows.
  out.push('  connecting      avg ' + val(data, 'http_req_connecting', 'avg').toFixed(2) +
    'ms  max ' + val(data, 'http_req_connecting', 'max').toFixed(2) + 'ms');
  out.push('  dropped_iters   ' + val(data, 'dropped_iterations', 'count'));
  out.push('  vus_max         ' + val(data, 'vus_max', 'max'));

  if (N_BURSTS > 0) {
    const counts = [];
    out.push('');
    out.push('  burst   requests   expected   delta');
    for (let i = 0; i < N_BURSTS; i++) {
      const c = val(data, `http_reqs{phase:burst_${pad3(i)}}`, 'count');
      counts.push(c);
      const delta = ((c - EXPECTED_PER_BURST) / EXPECTED_PER_BURST) * 100;
      const flag = Math.abs(delta) > 5 ? '  !!' : '';
      out.push(
        `  ${pad3(i)}   ${String(c).padStart(8)}   ${String(EXPECTED_PER_BURST).padStart(8)}   ` +
          `${(delta >= 0 ? '+' : '') + delta.toFixed(1)}%${flag}`
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
    out.push('  (!! marks >5% off expected — check these against any missed CUSUM detection)');
  }
  out.push('');

  return { stdout: out.join('\n') + '\n' };
}
