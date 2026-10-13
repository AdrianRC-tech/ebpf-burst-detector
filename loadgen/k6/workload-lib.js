// Shared code for the k6 scenario scripts (bursts.js, staircase.js): the HotelReservation
// request mix, its seeded RNG, and the summary-reporting helpers. Kept bursty scenario-agnostic

// ── env helpers ──────────────────────────────────────────────────────────────

export function envNum(name, dflt) {
  const v = __ENV[name];
  return v === undefined || v === '' ? dflt : Number(v);
}

export function pad3(i) {
  return String(i).padStart(3, '0');
}

// ── shared k6 options fragment ──────────────────────────────────────────────

export function baseK6Options() {
  return {
    // Bodies still cross the wire and are still counted at the netkit peer; this only stops k6
    // from materialising them, which keeps loader-side jitter off the burst edge.
    discardResponseBodies: true,
    // p(99) is not in k6's default trend set; the capacity probe in docs/experiment-methodology.md
    // gates on it, so ask for it explicitly.
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  };
}

// ── RNG + HotelReservation request mix ──────────────────────────────────────

export function mulberry32(a) {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Lua's math.random(m, n) includes both bounds.
export function randInt(rng, m, n) {
  return m + Math.floor(rng() * (n - m + 1));
}

// LuaJIT's tostring() on a number is sprintf("%.14g"), while JS String() is shortest-round-trip.
// The coordinates below land on values where those differ (Lua "38.005" vs JS
// "38.004999999999995"), which would shift bytes-per-request and therefore mu_0.
export function fmtG14(x) {
  let s = x.toPrecision(14);
  if (s.indexOf('e') === -1 && s.indexOf('.') !== -1) {
    s = s.replace(/0+$/, '').replace(/\.$/, '');
  }
  return s;
}

export function aprilDate(day) {
  return day <= 9 ? `2015-04-0${day}` : `2015-04-${day}`;
}

export function getUser(rng) {
  const id = randInt(rng, 0, 500);
  return { username: `Cornell_${id}`, password: String(id).repeat(10) };
}

export function randLat(rng) {
  return fmtG14(38.0235 + (randInt(rng, 0, 481) - 240.5) / 1000.0);
}

export function randLon(rng) {
  return fmtG14(-122.095 + (randInt(rng, 0, 325) - 157.0) / 1000.0);
}

export function searchHotel(rng) {
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

export function recommend(rng) {
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

export function userLogin(rng) {
  const u = getUser(rng);
  return {
    kind: 'user',
    method: 'POST',
    path: `/user?username=${u.username}&password=${u.password}`,
  };
}

export function reserve(rng) {
  const inDate = randInt(rng, 9, 23);
  const outDate = inDate + randInt(rng, 1, 5);
  const u = getUser(rng);
  // The Lua reserve() reads `lat`/`lon`, which are locals of search_hotel()/recommend(). They
  // resolve to nil globals there, so every reservation URL ever sent in these experiments has
  // literally contained lat=nil&lon=nil. Reproduced so results stay comparable to hotel-reservation default workload.
  return {
    kind: 'reserve',
    method: 'POST',
    path:
      `/reservation?inDate=${aprilDate(inDate)}&outDate=${aprilDate(outDate)}` +
      `&lat=nil&lon=nil&hotelId=${randInt(rng, 1, 80)}&customerName=${u.username}` +
      `&username=${u.username}&password=${u.password}&number=1`,
  };
}

// Parse "0.6,0.3,0.05,0.05" (order: search,recommend,user,reserve). Throws on anything but 4
// non-negative numbers summing to 1, so a bad value aborts in init rather than skewing a run.
export function parseMix(str) {
  const parts = str.split(',');
  const mix = parts.map((p) => (p.trim() === '' ? NaN : Number(p)));
  if (parts.length !== 4 || mix.some((x) => !Number.isFinite(x) || x < 0)) {
    throw new Error(`mix "${str}" must be 4 comma-separated non-negative numbers: search,recommend,user,reserve`);
  }
  const sum = mix.reduce((a, b) => a + b, 0);
  if (Math.abs(sum - 1) > 1e-6) {
    throw new Error(`mix "${str}" sums to ${sum}, must sum to 1`);
  }
  return mix;
}

// Choose one of searchHotel / recommend / userLogin / reserve per call and return its result.
// Without `mix`, the Lua target mix applies: 60% search, 39% recommend, 0.5% login, 0.5% reserve.
// With `mix` ([search, recommend, user, reserve], as returned by parseMix), those ratios are used.
export function pickRequest(rng, mix) {
  let SEARCH_RATIO    = 0.6;
  let RECOMMEND_RATIO = 0.39;
  let USER_RATIO      = 0.005;
  // reserve gets the remainder

  if (mix != null) {
    [SEARCH_RATIO, RECOMMEND_RATIO, USER_RATIO] = mix;
  }

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

// ── reporting ────────────────────────────────────────────────────────────────

// Millisecond source padded to nanosecond width, to match the detector's time_utc column
// (walltime.TimeOnlyNanos = "15:04:05.000000000", which carries no date).
export function utcNanos(ms) {
  const d = new Date(ms);
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  const frac = String(d.getUTCMilliseconds()).padStart(3, '0') + '000000';
  return `${hh}:${mm}:${ss}.${frac}`;
}

export function val(data, key, field) {
  const m = data.metrics[key];
  return m && m.values && m.values[field] !== undefined ? m.values[field] : 0;
}

// The scenario-agnostic top of every handleSummary: overall throughput/latency/connection-reuse
// numbers. Scenarios append their own per-phase delivery table after this.
export function commonSummaryLines(data) {
  const out = [];
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
  return out;
}
