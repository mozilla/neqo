// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
"use strict";
async function decompress(b64) {
  const bin = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const ds = new DecompressionStream("gzip");
  const w = ds.writable.getWriter();
  w.write(bin);
  w.close();
  return JSON.parse(await new Response(ds.readable).text());
}
decompress("__DATA_B64GZ__").then((D) => {
  const isMac = /Mac/.test(navigator.platform);
  const modKey = isMac ? "⌘" : "Ctrl";
  document.querySelector(".hint").textContent =
    `Drag to zoom \xb7 ${modKey}-drag to pan \xb7 Scroll to zoom \xb7 Shift for single panel \xb7 Double-click to reset \xb7 Click to freeze`;

  // ── Palette ──────────────────────────────────────────────────────────
  const dkMq = matchMedia("(prefers-color-scheme:dark)");
  const dk = dkMq.matches;
  dkMq.addEventListener("change", () => location.reload());
  const OI = {
    orange: dk ? "#F0B030" : "#B87800",
    green: dk ? "#2BC08A" : "#007A5A",
    blue: dk ? "#3A9FD6" : "#0072B2",
    vermillion: dk ? "#F07030" : "#D55E00",
    cyan: dk ? "#66CCCC" : "#008080",
    fg: dk ? "#ccc" : "#222",
    ax: dk ? "#999" : "#555",
    gray: dk ? "#bbb" : "#666",
  };

  const CC = {
    slow_start: [dk ? "#1a2e1a" : "#e8f5e8", "Slow Start"],
    congestion_avoidance: [dk ? "#181818" : "#fff", "Congestion Avoidance"],
    recovery_start: [dk ? "#3a1a1a" : "#fce8e4", "Recovery (Loss)"],
    recovery: [dk ? "#3a1a1a" : "#fce8e4", "Recovery (Loss)"],
    "recovery:ecn": [dk ? "#3a2a0a" : "#faf0d8", "Recovery (ECN)"],
    "recovery:persistent_congestion": [
      dk ? "#2e2a1a" : "#f5ede0",
      "Recovery (Persistent Congestion)",
    ],
  };
  const streamDashes = [
    null,
    [10, 4],
    [2, 4],
    [10, 2, 2, 2],
    [2, 2],
    [10, 2, 2, 2, 2, 2],
    [6, 2, 2, 2],
    [14, 4],
  ];
  const LS = {
    pto_expired: [OI.vermillion, "PTO Loss"],
    time_threshold: [dk ? "#ff77ff" : "#cc00cc", "Time Threshold Loss"],
    reordering_threshold: [
      dk ? "#ff6666" : "#cc0000",
      "Reordering Threshold Loss",
    ],
  };

  // ── Formatters ────────────────────────────────────────────────────────
  function sn(v, d) {
    if (v === 0) return "0";
    return +Math.abs(v).toPrecision(d) * (v < 0 ? -1 : 1) + "";
  }
  function _fmtMs1(v, d) {
    if (v == null) return "";
    const a = Math.abs(v);
    if (a >= 1e3) return sn(v / 1e3, d) + " s";
    if (a >= 1) return sn(v, d) + " ms";
    if (a >= 0.001) return sn(v * 1e3, d) + " µs";
    return sn(v, d) + " ms";
  }
  function _fmtB1(v, d) {
    if (v == null) return "";
    const a = Math.abs(v);
    if (a >= 1e9) return sn(v / 1e9, d) + " GB";
    if (a >= 1e6) return sn(v / 1e6, d) + " MB";
    if (a >= 1e3) return sn(v / 1e3, d) + " KB";
    return sn(v, d) + " B";
  }
  const fmtB = (v) => _fmtB1(v, 4);
  const fmtBps = (v) => (v == null ? "" : fmtB(v) + "/s");
  const fmtPn = (v) => (v == null ? "" : Math.round(v).toLocaleString());
  const fmtMs = (v) => _fmtMs1(v, 4);
  const scaleFmt = {
    sb: { f: fmtB, u: " bytes" },
    bytes: { f: fmtB, u: " bytes" },
    rate: { f: fmtBps, u: " bytes/s" },
    pn: { f: fmtPn, u: "" },
    rtt: { f: fmtMs, u: " ms" },
    gap: { f: fmtMs, u: " ms" },
    fcb: { f: fmtB, u: " bytes" },
    sfcb: { f: fmtB, u: " bytes" },
  };
  const N = (n) => (typeof n === "number" ? n.toLocaleString() : n);
  const R = (a, b) => (a === b ? N(a) : `${N(a)}..${N(b)}`);
  const H = (s) =>
    (s + "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  const DD = (s) => `<div class="ip-frame-detail">${s}</div>`;
  const bullet = (color, text) =>
    `<div class="ip-bullet">${dotHtml(color, false)}<span>${text}</span></div>`;
  function lighten(hex, amt = 0.4) {
    const n = parseInt(hex.replace("#", ""), 16);
    const r = Math.min(
      255,
      ((n >> 16) & 255) + Math.round(amt * (255 - ((n >> 16) & 255))),
    );
    const g = Math.min(
      255,
      ((n >> 8) & 255) + Math.round(amt * (255 - ((n >> 8) & 255))),
    );
    const b = Math.min(255, (n & 255) + Math.round(amt * (255 - (n & 255))));
    return `#${((r << 16) | (g << 8) | b).toString(16).padStart(6, "0")}`;
  }
  const sColor = (s, u, si) =>
    typeof s.stroke === "function" ? (u ? s.stroke(u, si) : "#888") : s.stroke;
  function dotHtml(c, hollow) {
    const cls = hollow ? "ip-dot ip-dot-hollow" : "ip-dot";
    return `<span class="${cls}" style="--c:${c}"></span>`;
  }
  function swatch(s) {
    const c = sColor(s);
    if (s.width > 0) {
      const r = devicePixelRatio;
      const da = s.dash
        ? ` stroke-dasharray="${s.dash.map((v) => v / r).join(",")}"`
        : "";
      return `<svg class="ip-line"><line x1="0" y1="5" x2="20" y2="5" stroke="${c}" stroke-width="${s.width || 1}"${da}/></svg>`;
    }
    return dotHtml(c, s._hollow);
  }

  // ── Plugins ──────────────────────────────────────────────────────────
  function fillIntervals(ctx, u, intervals, color) {
    if (!intervals.length) return;
    const { left, top, width, height } = u.bbox;
    ctx.save();
    ctx.fillStyle = color;
    for (const [t0, t1] of intervals) {
      const x0 = Math.max(u.valToPos(t0, "x", true), left);
      const x1 = Math.min(u.valToPos(t1, "x", true), left + width);
      if (x1 > x0) ctx.fillRect(x0, top, x1 - x0, height);
    }
    ctx.restore();
  }
  function shadingPlugin() {
    // Group CC intervals by color to minimize fillStyle changes
    const ccByColor = new Map();
    for (const [t0, t1, st] of D.ccIntervals) {
      const s = CC[st];
      if (!s) continue;
      if (!ccByColor.has(s[0])) ccByColor.set(s[0], []);
      ccByColor.get(s[0]).push([t0, t1]);
    }
    return {
      hooks: {
        drawClear: [
          (u) => {
            const ctx = u.ctx;
            for (const [color, intervals] of ccByColor)
              fillIntervals(ctx, u, intervals, color);
            fillIntervals(ctx, u, fcStreamIntervals, fcStreamColor);
            fillIntervals(ctx, u, fcConnIntervals, fcConnColor);
          },
        ],
      },
    };
  }

  function zeroLinePlugin() {
    return {
      hooks: {
        draw: [
          (u) => {
            const ctx = u.ctx,
              { left, top, width, height } = u.bbox;
            ctx.save();
            ctx.strokeStyle = dk ? "#333" : "#ccc";
            ctx.lineWidth = devicePixelRatio;
            ctx.setLineDash([4 * devicePixelRatio, 4 * devicePixelRatio]);
            forYScales(u, (k, s) => {
              if (s.min > 0 || s.max < 0) return;
              const y = u.valToPos(0, k, true);
              if (y >= top && y <= top + height) {
                ctx.beginPath();
                ctx.moveTo(left, y);
                ctx.lineTo(left + width, y);
                ctx.stroke();
              }
            });
            ctx.restore();
          },
        ],
      },
    };
  }

  // Derive FC-limited intervals from budget==0 regions
  function budgetZeroIntervals(t, v, endT) {
    const intervals = [];
    let start = null;
    for (let i = 0; i < t.length; i++) {
      if (v[i] === 0 && start == null) start = t[i];
      else if (v[i] > 0 && start != null) {
        intervals.push([start, t[i]]);
        start = null;
      }
    }
    if (start != null) intervals.push([start, endT ?? t[t.length - 1]]);
    return intervals;
  }
  const fcConnIntervals = D.fcConnBudget[0].length
    ? budgetZeroIntervals(D.fcConnBudget[0], D.fcConnBudget[1], D.maxT)
    : [];
  const fcStreamIntervals = [];
  for (const [sid, tv] of Object.entries(D.fcStreamBudget || {})) {
    for (const iv of budgetZeroIntervals(tv[0], tv[1], D.maxT))
      fcStreamIntervals.push([iv[0], iv[1], +sid]);
  }
  fcStreamIntervals.sort((a, b) => a[1] - b[1]);

  function budgetAt(tv, t) {
    if (!tv || !tv[0].length) return null;
    const i = bisect(tv[0], t + 1e-9) - 1;
    return i >= 0 ? tv[1][i] : null;
  }

  function tvPush(tv, t, v) {
    tv[0].push(t);
    tv[1].push(v);
  }
  function tvGetOrCreate(map, key) {
    return map[key] || (map[key] = [[], []]);
  }
  const fcConnBlockedData = [[], []];
  const fcConnIncreasedData = [[], []];
  const fcStreamBlockedBySid = {};
  const fcStreamIncreasedBySid = {};
  const fcEvByTime = new Map();
  for (const [t, type, value, sid] of D.fcEvents || []) {
    if (!fcEvByTime.has(t)) fcEvByTime.set(t, []);
    fcEvByTime.get(t).push({ type, value, sid });
    const budgetTv = sid === -1 ? D.fcConnBudget : D.fcStreamBudget[sid];
    const bv = budgetAt(budgetTv, t) ?? 0;
    if (sid === -1) {
      tvPush(type === "blocked" ? fcConnBlockedData : fcConnIncreasedData, t, bv);
    } else {
      const store =
        type === "blocked" ? fcStreamBlockedBySid : fcStreamIncreasedBySid;
      tvPush(tvGetOrCreate(store, sid), t, bv);
    }
  }
  const hasFcConnBlocked = fcConnBlockedData[0].length > 0;
  const hasFcConnIncreased = fcConnIncreasedData[0].length > 0;
  const fcEventStreamIds = [
    ...new Set([
      ...Object.keys(fcStreamBlockedBySid),
      ...Object.keys(fcStreamIncreasedBySid),
    ]),
  ].sort((a, b) => a - b);

  const _shadingP = shadingPlugin(),
    _zeroLineP = zeroLinePlugin();

  // ── Legend ───────────────────────────────────────────────────────────
  const fcStreamColor = dk ? "#1a1a2e" : "#e4e8f5";
  const fcConnColor = dk ? "#2e2a1a" : "#f5ede0";
  const ccLegEls = {};
  {
    const el = document.getElementById("ccleg");
    const activeCC = new Set(D.ccIntervals.map(([, , st]) => st));
    const items = [
      ...Object.entries(CC)
        .filter(([st]) => st !== "recovery_start")
        .map(([st, [c, l]]) => [
          st,
          c,
          l,
          activeCC.has(st) ||
            (st === "recovery" && activeCC.has("recovery_start")),
        ]),
      [
        "fc_stream",
        fcStreamColor,
        "Stream FC Limited",
        fcStreamIntervals.length > 0,
      ],
      [
        "fc_conn",
        fcConnColor,
        "Connection FC Limited",
        fcConnIntervals.length > 0,
      ],
    ];
    for (const [key, color, label, active] of items) {
      el.innerHTML += `<span data-rg="${H(key)}" class="${active ? "" : "cc-inactive"}"><b style="--c:${color}"></b><span class="cc-label">${H(label)}</span></span>`;
    }
    el.querySelectorAll("[data-rg]").forEach(
      (s) => (ccLegEls[s.dataset.rg] = s),
    );
  }

  // Highlight the legend item for the region at time t
  let _activeRg = null;
  function findInterval(intervals, t) {
    const lo = bisect(intervals, t, 0, intervals.length, (iv) => iv[1]);
    return lo < intervals.length && t >= intervals[lo][0]
      ? intervals[lo]
      : null;
  }
  function highlightRegion(t) {
    if (_activeRg) {
      _activeRg.classList.remove("cc-active");
      _activeRg = null;
    }
    if (t == null) return;
    if (findInterval(fcConnIntervals, t)) _activeRg = ccLegEls.fc_conn;
    else if (findInterval(fcStreamIntervals, t)) _activeRg = ccLegEls.fc_stream;
    else {
      const cc = findInterval(D.ccIntervals, t);
      if (cc)
        _activeRg = ccLegEls[cc[2] === "recovery_start" ? "recovery" : cc[2]];
    }
    _activeRg?.classList.add("cc-active");
  }

  // ── Chart helpers ────────────────────────────────────────────────────
  const charts = [];
  function mkEl(tag, cls) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    return e;
  }
  let _frozen = false;
  function setFrozen(v) {
    _frozen = v;
    for (const ch of charts) {
      ch.over.style.cursor = v ? "default" : "crosshair";
      ch.root.closest(".chart").classList.toggle("frozen", v);
    }
  }
  const cursorSnapPct = 0.02;
  const zoomResetThreshold = 0.999;

  const stepped = uPlot.paths.stepped({ align: 1 });
  const axProps = {
    stroke: OI.ax,
    border: { stroke: OI.ax, width: 1 },
    grid: { show: false },
    size: 55,
    labelSize: 20,
  };
  function adaptiveSigFigs(ticks, fmt) {
    for (let d = 4; d <= 12; d++) {
      const labels = ticks.map((v) => fmt(v, d));
      let dup = false;
      for (let i = 1; i < labels.length; i++)
        if (labels[i] === labels[i - 1]) {
          dup = true;
          break;
        }
      if (!dup) return d;
    }
    return 12;
  }
  function fmtMsAdaptive(_, ticks) {
    const d = adaptiveSigFigs(ticks, _fmtMs1);
    return ticks.map((v) => _fmtMs1(v, d));
  }
  const xAx = { ...axProps, size: 38, values: fmtMsAdaptive };

  // Y-axes: bare numbers, unit stored on axis for label
  const msUnits = [
    [1e3, 1e-3, "s"],
    [1, 1, "ms"],
    [1e-3, 1e3, "µs"],
  ];
  const bUnits = [
    [1e9, 1e-9, "GB"],
    [1e6, 1e-6, "MB"],
    [1e3, 1e-3, "KB"],
    [0, 1, "B"],
  ];
  function unitAxis(units, suffix) {
    return function (u, ticks, axisIdx) {
      if (!ticks.length) return [];
      const mx = Math.max(...ticks.map((v) => Math.abs(v || 0)));
      const [, div, unit] =
        units.find(([t]) => mx >= t) || units[units.length - 1];
      const fmt = (v, d) => (v == null ? "" : sn(v * div, d));
      const d = adaptiveSigFigs(ticks, fmt);
      u.axes[axisIdx]._unit = unit + (suffix || "");
      return ticks.map((v) => fmt(v, d));
    };
  }
  const fmtBAxis = unitAxis(bUnits);
  const fmtBpsAxis = unitAxis(bUnits, "/s");
  const fmtMsAxis = unitAxis(msUnits);
  function fmtPnAxis(_, ticks) {
    return ticks.map(fmtPn);
  }
  function axLabel(base) {
    return (u, ai) => {
      const unit = u.axes[ai]?._unit;
      return unit ? `${base} [${unit}]` : base;
    };
  }

  // Apply fn(scaleKey, scale) to every non-x scale on a chart.
  function forYScales(u, fn) {
    for (const k of Object.keys(u.scales)) if (k !== "x") fn(k, u.scales[k]);
  }

  // Sync all scales (x + y) across charts, avoiding recursion.
  let syncing = false;
  function syncAll(src, xMin, xMax, yZoom) {
    if (syncing) return;
    syncing = true;
    for (const ch of charts) {
      if (ch === src) continue;
      ch.batch(() => {
        ch.setScale("x", { min: xMin, max: xMax });
        if (yZoom) yZoom(ch);
      });
    }
    syncing = false;
  }

  function wheelZoomPlugin() {
    return {
      hooks: {
        ready: [
          (u) => {
            const sensitivity = 0.004;
            function clamp(nr, mn, mx) {
              const xMin0 = u._fullXMin,
                xMax0 = u._fullXMax,
                xRange0 = xMax0 - xMin0;
              if (nr > xRange0) {
                mn = xMin0;
                mx = xMax0;
              } else if (mn < xMin0) {
                mn = xMin0;
                mx = xMin0 + nr;
              } else if (mx > xMax0) {
                mx = xMax0;
                mn = xMax0 - nr;
              }
              return [mn, mx];
            }
            u.over.addEventListener("dblclick", () => {
              if (_frozen) setFrozen(false);
              const fMin = u._fullXMin,
                fMax = u._fullXMax;
              for (const ch of charts) {
                ch._rangeLock.v = true;
                ch.batch(() => {
                  ch.setScale("x", { min: fMin, max: fMax });
                  forYScales(ch, (k) =>
                    ch.setScale(k, { min: null, max: null }),
                  );
                });
                ch._rangeLock.v = false;
              }
            });
            u.over.addEventListener(
              "mousedown",
              (e) => {
                if (_frozen || e.button !== 0) return;
                if (!(e.metaKey || e.ctrlKey)) return;
                e.stopImmediatePropagation();
                e.preventDefault();
                const solo = e.shiftKey;
                const x0 = e.clientX,
                  y0 = e.clientY;
                const scXMin0 = u.scales.x.min,
                  scXMax0 = u.scales.x.max;
                const xUnitsPerPx = u.posToVal(1, "x") - u.posToVal(0, "x");
                const targetCharts = solo ? [u] : charts;
                const allSnap = targetCharts.map((ch) => {
                  const ySnap = [];
                  forYScales(ch, (k, s) => {
                    if (s.min == null || s.max == null) return;
                    ySnap.push({
                      key: k,
                      min0: s.min,
                      max0: s.max,
                      upp: ch.posToVal(1, k) - ch.posToVal(0, k),
                    });
                  });
                  return { ch, ySnap };
                });
                function panY(ch, snap, dyPx) {
                  let dy = dyPx;
                  for (const ys of snap) {
                    const init = ch._initY[ys.key];
                    if (!init) continue;
                    const d = ys.upp * dy;
                    const mn = ys.min0 - d,
                      mx = ys.max0 - d,
                      yr = ys.max0 - ys.min0;
                    if (mn < init.min) dy = (ys.min0 - init.min) / ys.upp;
                    if (mx > init.max)
                      dy = (ys.min0 - (init.max - yr)) / ys.upp;
                  }
                  for (const ys of snap) {
                    const d = ys.upp * dy;
                    ch.setScale(ys.key, { min: ys.min0 - d, max: ys.max0 - d });
                  }
                }
                function onmove(e) {
                  e.preventDefault();
                  const dyPx = e.clientY - y0;
                  const dx = xUnitsPerPx * (e.clientX - x0);
                  let nMin = scXMin0 - dx,
                    nMax = scXMax0 - dx;
                  const xr = scXMax0 - scXMin0;
                  if (nMin < u._fullXMin) {
                    nMin = u._fullXMin;
                    nMax = u._fullXMin + xr;
                  }
                  if (nMax > u._fullXMax) {
                    nMax = u._fullXMax;
                    nMin = u._fullXMax - xr;
                  }
                  const srcSnap = allSnap.find((s) => s.ch === u);
                  u.batch(() => {
                    u.setScale("x", { min: nMin, max: nMax });
                    panY(u, srcSnap.ySnap, dyPx);
                  });
                  if (!solo)
                    syncAll(u, nMin, nMax, (ch) => {
                      const s = allSnap.find((a) => a.ch === ch);
                      if (s) panY(ch, s.ySnap, dyPx);
                    });
                }
                function onup() {
                  document.removeEventListener("mousemove", onmove);
                  document.removeEventListener("mouseup", onup);
                }
                document.addEventListener("mousemove", onmove);
                document.addEventListener("mouseup", onup);
              },
              true,
            );
            let pending = null;
            u.over.addEventListener(
              "wheel",
              (e) => {
                if (_frozen) return;
                e.preventDefault();
                const rect = u.over.getBoundingClientRect();
                if (!pending)
                  pending = {
                    dy: 0,
                    left: e.clientX - rect.left,
                    top: e.clientY - rect.top,
                    solo: e.shiftKey,
                  };
                pending.dy += e.deltaY;
                pending.left = e.clientX - rect.left;
                pending.top = e.clientY - rect.top;
                pending.solo = pending.solo || e.shiftKey;
                if (!pending.raf) {
                  pending.raf = requestAnimationFrame(() => {
                    const { dy, left, top, solo } = pending;
                    pending = null;
                    const factor = Math.max(
                      0.5,
                      Math.min(Math.exp(-dy * sensitivity), 2),
                    );
                    const leftPct = left / rect.width;
                    const topPct = top / rect.height;
                    const xVal = u.posToVal(left, "x");
                    const nxr = (u.scales.x.max - u.scales.x.min) * factor;
                    const [nMin, nMax] = clamp(
                      nxr,
                      xVal - leftPct * nxr,
                      xVal - leftPct * nxr + nxr,
                    );
                    function zoomY(ch) {
                      let f = factor;
                      forYScales(ch, (k, s) => {
                        if (s.min == null) return;
                        const init = ch._initY[k];
                        if (!init) return;
                        f = Math.min(
                          f,
                          (init.max - init.min) / (s.max - s.min),
                        );
                      });
                      forYScales(ch, (k, s) => {
                        if (s.min == null) return;
                        const init = ch._initY[k];
                        if (!init) return;
                        const yVal = ch.posToVal(top, k);
                        const nyr = (s.max - s.min) * f;
                        let mn = yVal - (1 - topPct) * nyr,
                          mx = mn + nyr;
                        if (mn < init.min) {
                          mn = init.min;
                          mx = init.min + nyr;
                        }
                        if (mx > init.max) {
                          mx = init.max;
                          mn = init.max - nyr;
                        }
                        const ir = init.max - init.min;
                        if (mx - mn >= ir * zoomResetThreshold) {
                          mn = init.min;
                          mx = init.max;
                        }
                        ch.setScale(k, { min: mn, max: mx });
                      });
                    }
                    u.batch(() => {
                      u.setScale("x", { min: nMin, max: nMax });
                      zoomY(u);
                    });
                    if (!solo) syncAll(u, nMin, nMax, zoomY);
                  });
                }
              },
              { passive: false },
            );
          },
        ],
      },
    };
  }

  function bisect(arr, v, lo = 0, hi = arr.length, key = (x) => x) {
    while (lo < hi) {
      const m = (lo + hi) >> 1;
      key(arr[m]) < v ? (lo = m + 1) : (hi = m);
    }
    return lo;
  }

  function getNonNullIndices(u, si) {
    if (!u._nnCache) u._nnCache = new Map();
    if (!u._nnCache.has(si)) {
      const d = u.data[si],
        idx = [];
      if (d) for (let i = 0; i < d.length; i++) if (d[i] != null) idx.push(i);
      u._nnCache.set(si, idx);
    }
    return u._nnCache.get(si);
  }
  function nearestNonNull(u, si, ci) {
    const d = u.data[si];
    if (!d || ci == null) return null;
    const idx = getNonNullIndices(u, si);
    if (!idx.length) return null;
    const lo = bisect(idx, ci);
    const best =
      lo > 0 && lo < idx.length
        ? Math.abs(ci - idx[lo - 1]) <= Math.abs(ci - idx[lo])
          ? idx[lo - 1]
          : idx[lo]
        : lo < idx.length
          ? idx[lo]
          : idx[lo - 1];
    const cy = u.cursor.top;
    if (cy == null || cy < 0) return best;
    const sc = u.series[si].scale;
    if (!sc) return best;
    const cx = u.cursor.left;
    const bestX = u.data[0][best];
    let closestY = best,
      closestDy = Math.abs(u.valToPos(d[best], sc) - cy);
    const p = lo > 0 && idx[lo - 1] === best ? lo - 1 : lo;
    for (let dir = -1; dir <= 1; dir += 2) {
      for (let j = p + dir; j >= 0 && j < idx.length; j += dir) {
        if (
          Math.abs(u.data[0][idx[j]] - bestX) >
          (u.scales.x.max - u.scales.x.min) * 1e-4
        )
          break;
        const dy = Math.abs(u.valToPos(d[idx[j]], sc) - cy);
        if (dy < closestDy) {
          closestDy = dy;
          closestY = idx[j];
        }
      }
    }
    if (
      Math.abs(u.valToPos(u.data[0][closestY], "x") - cx) >
      u.over.clientWidth * cursorSnapPct
    )
      return null;
    return closestY;
  }
  // Overdraw series points in different colors based on a classifier function.
  // colorFn(u, si, dataIdx) → color string or null
  function recolorPlugin(seriesFilter, colorFn) {
    return {
      hooks: {
        drawSeries: [
          (u, si) => {
            if (!seriesFilter(si)) return;
            const ctx = u.ctx,
              d = u.data[si],
              sc = u.series[si].scale;
            const { left, top, width, height } = u.bbox;
            const r = ((u.series[si].points?.size || 5) / 2) * devicePixelRatio;
            const byColor = new Map();
            for (let i = 0; i < d.length; i++) {
              if (d[i] == null) continue;
              const color = colorFn(u, si, i);
              if (!color) continue;
              const cx = Math.round(u.valToPos(u.data[0][i], "x", true));
              const cy = Math.round(u.valToPos(d[i], sc, true));
              if (
                cx < left ||
                cx > left + width ||
                cy < top ||
                cy > top + height
              )
                continue;
              if (!byColor.has(color)) byColor.set(color, new Path2D());
              const p = byColor.get(color);
              p.moveTo(cx + r, cy);
              p.arc(cx, cy, r, 0, Math.PI * 2);
            }
            ctx.save();
            for (const [color, path] of byColor) {
              ctx.fillStyle = color;
              ctx.fill(path);
            }
            ctx.restore();
          },
        ],
      },
    };
  }

  function origPn(u, si, hi) {
    if (!u._origData) {
      const v = u.data[si]?.[hi];
      return v != null ? Math.round(v) : null;
    }
    const rawT = u.data[0][hi];
    const origT = u._origData[0];
    if (!origT) return null;
    const k = bisect(origT, rawT + 1e-10) - 1;
    if (k < 0 || origT[k] !== rawT) return null;
    const v = u._origData[si]?.[k];
    return v != null ? Math.round(v) : null;
  }
  const cursor = {
    drag: { x: true, y: false, setScale: true },
    points: { size: 10, width: 1 },
    sync: { key: "qvis", setSeries: false },
    dataIdx: (u, si, ci) =>
      _frozen ? u.cursor.idxs[si] : si === 0 ? ci : nearestNonNull(u, si, ci),
  };

  // Expand compact pktMeta: [sid,off,len,fin] → [{frame_type:"stream",...}], [null,frames] → frames
  function getPktFrames(pn) {
    const m = D.pktMeta[pn];
    if (!m) return null;
    if (m[0] == null) return m[1];
    return [
      {
        frame_type: "stream",
        stream_id: m[0],
        offset: m[1],
        length: m[2],
        fin: m[3] === 1,
      },
    ];
  }

  const frameFields = {
    stream: [
      ["range", "offset", "length"],
      ["length", "length", null, "bytes"],
      ["FIN", "fin", "flag"],
    ],
    crypto: [
      ["offset", "offset"],
      ["length", "length"],
    ],
    padding: [["length", "length"]],
    stream_data_blocked: [
      ["stream", "stream_id"],
      ["limit", "limit"],
    ],
    data_blocked: [["limit", "limit"]],
    max_stream_data: [
      ["stream", "stream_id"],
      ["limit", "maximum", "limit"],
    ],
    max_data: [["limit", "maximum", "limit"]],
  };

  function collectCandidates(u, idx) {
    const cx = u.cursor.left,
      cy = u.cursor.top;
    const candidates = [];
    for (let si = 1; si < u.series.length; si++) {
      if (!u.series[si].show) continue;
      const sc = u.series[si].scale;
      if ((sc === "fcb" || sc === "sfcb") && !u.series[si]._fcEvent) continue;
      const hi = nearestNonNull(u, si, idx);
      if (hi == null || u.data[si][hi] == null) continue;
      const v = u.data[si][hi];
      const sc2 = u.series[si].scale;
      const px = u.valToPos(u.data[0][hi], "x");
      const py = sc2 ? u.valToPos(v, sc2) : cy;
      if (
        px < 0 ||
        px > u.over.clientWidth ||
        py < 0 ||
        py > u.over.clientHeight
      )
        continue;
      candidates.push({ si, hi, v, dist: (px - cx) ** 2 + (py - cy) ** 2 });
    }
    return candidates;
  }

  function dedupAckLoss(candidates, u, cy) {
    const ackLoss = candidates.filter((c) => {
      const l = u.series[c.si].label;
      return l === "ACK" || l.includes("Loss");
    });
    if (ackLoss.length <= 1) return candidates;
    const cx = u.cursor.left;
    const byX = new Map();
    for (const c of ackLoss) {
      const xp = Math.round(u.valToPos(u.data[0][c.hi], "x") / 3) * 3;
      const dy = Math.abs(
        (u.series[c.si].scale ? u.valToPos(c.v, u.series[c.si].scale) : 0) - cy,
      );
      if (!byX.has(xp)) byX.set(xp, []);
      byX.get(xp).push({ c, dy });
    }
    let bestXp = null,
      bestDx = Infinity;
    for (const xp of byX.keys()) {
      const dx = Math.abs(xp - cx);
      if (dx < bestDx) {
        bestDx = dx;
        bestXp = xp;
      }
    }
    const dropSet = new Set();
    for (const [xp, group] of byX) {
      if (xp !== bestXp) {
        for (const g of group) dropSet.add(g.c);
      } else if (group.length > 1) {
        group.sort((a, b) => a.dy - b.dy);
        for (let i = 1; i < group.length; i++) dropSet.add(group[i].c);
      }
    }
    return candidates.filter((c) => !dropSet.has(c));
  }

  function mkChart(
    { id: el, scales, axes, series, data, linkedY, extraPlugins, _origData },
    w,
    h,
  ) {
    const yRanges = {};
    const sMap = series.map((s) => s.scale || null);
    for (let si = 1; si < data.length; si++) {
      const sk = sMap[si];
      if (!sk || sk === "x") continue;
      if (series[si]?._fcEvent) continue;
      const a = data[si];
      if (!a) continue;
      if (!yRanges[sk]) yRanges[sk] = { min: 0, max: 0 };
      for (let i = 0; i < a.length; i++)
        if (a[i] != null && a[i] > yRanges[sk].max) yRanges[sk].max = a[i];
    }
    const linked = linkedY?.length ? linkedY : null;
    if (linked) {
      let mx = 0;
      for (const k of linked) if (yRanges[k]) mx = Math.max(mx, yRanges[k].max);
      for (const k of linked) if (yRanges[k]) yRanges[k].max = mx;
    }
    // Inject range functions: return pre-computed range when locked, pass-through otherwise.
    const rangeLock = { v: true };
    scales.x.range = (u, mn, mx) => {
      if (rangeLock.v) return [globalXMin, globalXMax];
      if (mx - mn < minXRange) {
        const mid = (mn + mx) / 2;
        return [mid - minXRange / 2, mid + minXRange / 2];
      }
      return [mn, mx];
    };
    for (const k of Object.keys(scales)) {
      if (k === "x" || !yRanges[k]) continue;
      const r = yRanges[k];
      scales[k].range = (u, mn, mx) =>
        rangeLock.v ? [r.min, r.max] : [mn, mx];
    }

    const panelEl = document.getElementById(el);

    const opts = {
      width: w,
      height: h,
      scales,
      axes,
      series,
      cursor,
      legend: { show: false },
      plugins: [
        _shadingP,
        _zeroLineP,
        _axisHlP,
        wheelZoomPlugin(),
        {
          hooks: {
            setCursor: [
              (u) => {
                if (_frozen) return;
                const idx = u.cursor.idx;
                highlightRegion(idx != null ? u.data[0][idx] : null);
                const ip = u._dataDiv;
                if (!ip || !u._infoPanel.classList.contains("open")) return;
                if (idx == null) {
                  ip.innerHTML = "";
                  u._shownSi = null;
                  const tg = u._infoPanel.querySelector(".ip-toggles");
                  if (tg) tg.style.display = "";
                  if (u._activeScale) {
                    u._activeScale = null;
                    u.redraw(false);
                  }
                  return;
                }
                const items = [];
                const cy = u.cursor.top;
                const deduped = dedupAckLoss(
                  collectCandidates(u, idx),
                  u,
                  cy,
                ).sort((a, b) => a.si - b.si);
                const nearest = deduped.reduce(
                  (a, b) => (b.dist < a.dist ? b : a),
                  deduped[0],
                );
                const activeScale = nearest
                  ? u.series[nearest.si].scale
                  : null;
                if (activeScale !== u._activeScale) {
                  u._activeScale = activeScale;
                  u.redraw(false);
                }
                const shownSi = new Set();
                const seenPn = new Set();
                for (const { si, hi, v } of deduped) {
                  const pn = origPn(u, si, hi) ?? Math.round(v);
                  const s = u.series[si];
                  if (s.scale === "pn") {
                    if (seenPn.has(pn)) continue;
                    seenPn.add(pn);
                  }
                  shownSi.add(si);
                  const col = sColor(s, u, si);
                  let label = s.label;
                  const isAckSeries = s.label === "ACK";
                  const isLossSeries = s.label.includes("Loss");
                  const pktFrames =
                    !isAckSeries && !isLossSeries && s.scale === "pn"
                      ? getPktFrames(pn)
                      : null;
                  const isPktSeries = !!pktFrames;
                  if (isPktSeries) label = `Packet ${N(pn)}`;
                  const itemT = Math.round(u.data[0][hi] * 1e4) / 1e4;
                  const itemFmtT = fmtMs(itemT);
                  const itemTExtra = itemFmtT.endsWith(" ms")
                    ? ""
                    : " (" + itemFmtT + ")";
                  const hollow = s._hollow;
                  const hdr = `${dotHtml(col, hollow)}<span class="ip-color" style="--c:${col}">${label}${s.width > 0 ? " " + swatch(s) : ""}</span>`;
                  let html =
                    `<div class="ip-item"><div class="ip-label ip-bullet">${hdr}</div><div class="ip-frame">` +
                    DD(`t = ${N(itemT)} ms${itemTExtra}`) +
                    `</div>`;
                  if (isLossSeries) {
                    html += `<div class="ip-frame">` + DD(N(pn));
                    const gi = lossGapInfo.get(pn);
                    if (gi) {
                      html += DD(`gap ${N(gi.lo)}..${N(gi.hi)}`);
                      if (gi.rpn != null) html += DD(`from ACK ${N(gi.rpn)}`);
                    }
                    html += `</div>`;
                  } else if (isPktSeries) {
                    for (const fr of pktFrames) {
                      const ft = fr.frame_type || "?";
                      const ftLabel =
                        ft === "stream" ? `stream ${fr.stream_id || 0}` : H(ft);
                      let fh = `<div class="ip-frame"><div class="ip-frame-type">${ftLabel}</div>`;
                      if (ft === "ack" && fr.acked_ranges) {
                        fh += DD(
                          "ranges: " +
                            fr.acked_ranges.map(([a, b]) => R(a, b)).join(", "),
                        );
                        if (fr.ack_delay)
                          fh += DD(`delay ${N(fr.ack_delay)} ms`);
                      } else if (frameFields[ft]) {
                        for (const [lbl, key, extra, suffix] of frameFields[
                          ft
                        ]) {
                          if (extra === "flag") {
                            if (fr[key]) fh += DD(lbl);
                          } else if (lbl === "range") {
                            const off = fr[key] || 0,
                              len = fr[extra] || 0;
                            fh += DD(`offset ${N(off)}..${N(off + len)}`);
                          } else
                            fh += DD(
                              `${lbl} ${N(fr[key] || (extra ? fr[extra] : 0) || 0)}${suffix ? " " + suffix : ""}`,
                            );
                        }
                      }
                      fh += "</div>";
                      html += fh;
                    }
                    const lossInfo = lostPnMap.get(pn);
                    if (lossInfo)
                      for (const lt of lossInfo.triggers)
                        html += bullet(lt.color, `Declared lost: ${lt.label}`);
                    const connBudget = budgetAt(D.fcConnBudget, itemT);
                    if (connBudget != null)
                      html +=
                        `<div class="ip-frame">` +
                        DD(`connection FC budget: ${fmtB(connBudget)}`) +
                        `</div>`;
                  } else if (isAckSeries && pnRanges[pn]) {
                    const asc = [...pnRanges[pn]].sort((a, b) => a[0] - b[0]);
                    const myRange = asc.find(([a, b]) => pn >= a && pn <= b);
                    html += `<div class="ip-frame">` + DD(N(pn));
                    if (myRange) html += DD(`in ${R(myRange[0], myRange[1])}`);
                    const rpn = ackRecvPn[pn];
                    if (rpn != null) html += DD(`from ACK ${N(rpn)}`);
                    if (ecnCePnSet.has(pn))
                      html += bullet(OI.cyan, "CE marked");
                    html += `</div>`;
                  } else if (s._fcEvent) {
                    const rawT = u.data[0][hi];
                    const evs = (fcEvByTime.get(rawT) || []).filter(
                      (e) =>
                        e.type === s._fcEvent &&
                        (s._fcSid != null
                          ? e.sid === s._fcSid
                          : s._fcConn
                            ? e.sid === -1
                            : e.sid !== -1),
                    );
                    for (const ev of evs) {
                      html += `<div class="ip-frame">`;
                      if (ev.type === "blocked") {
                        html += DD(`Blocked at limit ${fmtB(ev.value)}`);
                      } else {
                        html += DD(`Budget now ${fmtB(ev.value)}`);
                      }
                      html += `</div>`;
                    }
                  } else {
                    const su = scaleFmt[s.scale] || { f: fmtMs, u: " ms" };
                    const raw = `${s.scale === "pn" ? N(pn) : N(v)}${su.u}`;
                    const abbr = su.f(v);
                    const showAbbr =
                      abbr && abbr !== raw && Math.abs(v) >= 10000;
                    html +=
                      `<div class="ip-frame">` +
                      DD(raw + (showAbbr ? " (" + abbr + ")" : "")) +
                      `</div>`;
                    if (s.label === "Send Gap" && fcGapTimes.has(u.data[0][hi]))
                      html += bullet(OI.vermillion, "Flow control limited");
                    if (s.scale === "sb" && s.label.startsWith("Stream ")) {
                      const sid = s.label.replace("Stream ", "");
                      const sBudget = budgetAt(D.fcStreamBudget[sid], itemT);
                      if (sBudget != null)
                        html +=
                          `<div class="ip-frame">` +
                          DD(`FC budget: ${fmtB(sBudget)}`) +
                          `</div>`;
                    }
                  }
                  html += "</div>";
                  items.push(html);
                }
                u._shownSi = shownSi;
                const pts = u.root.querySelectorAll(".u-cursor-pt");
                for (let i = 0; i < pts.length; i++) {
                  pts[i].style.display = shownSi.has(i + 1) ? "block" : "none";
                  const cd = deduped.find((c) => c.si === i + 1);
                  if (cd) {
                    const rpn = origPn(u, i + 1, cd.hi);
                    const li = rpn != null ? lostPnMap.get(rpn) : null;
                    const ce = rpn != null && ecnCePnSet.has(rpn);
                    const isFcGap =
                      u.series[i + 1].label === "Send Gap" &&
                      fcGapTimes.has(u.data[0][cd.hi]);
                    const hc = li
                      ? li.color
                      : ce
                        ? OI.cyan
                        : isFcGap
                          ? OI.vermillion
                          : null;
                    const sc = sColor(u.series[i + 1], u, i + 1);
                    pts[i].style.borderColor = hc || sc;
                    pts[i].style.background = hc || sc;
                  }
                }
                // Add FC limit info at the bottom
                const curT = u.data[0][idx];
                const fcC = findInterval(fcConnIntervals, curT);
                const fcS = findInterval(fcStreamIntervals, curT);
                if (fcC)
                  items.push(bullet(fcConnColor, "Connection FC limited"));
                if (fcS)
                  items.push(
                    bullet(
                      fcStreamColor,
                      `Stream ${H(String(fcS[2]))} FC limited`,
                    ),
                  );
                ip.innerHTML =
                  items.join("") ||
                  "<div class='ip-detail'>Hover over data</div>";
                const tg = u._infoPanel.querySelector(".ip-toggles");
                if (tg) {
                  tg.style.display = "";
                  if (u._infoPanel.scrollHeight > u._infoPanel.clientHeight)
                    tg.style.display = "none";
                }
              },
            ],
            ready: [
              (u) => {
                u._rangeLock.v = false;
              },
            ],
          },
        },
        ...(extraPlugins || []),
      ],
    };
    // Create info panel first so chart can measure remaining width
    const rowEl = panelEl.parentElement;
    const infoPanel = mkEl("div", "info open");
    const togglesDiv = mkEl("div", "ip-toggles");
    const dataDiv = mkEl("div", "ip-data");
    dataDiv.textContent = "Hover over data";
    infoPanel.appendChild(togglesDiv);
    infoPanel.appendChild(dataDiv);
    rowEl.appendChild(infoPanel);
    opts.width = panelEl.clientWidth;
    const c = new uPlot(opts, data, panelEl);
    c.over.addEventListener("click", (e) => {
      if (e.detail !== 1) return;
      setFrozen(!_frozen);
    });
    for (let si = 1; si < series.length; si++) {
      const s = series[si];
      const lbl = mkEl("label");
      const cb = mkEl("input");
      cb.type = "checkbox";
      cb.checked = true;
      cb.addEventListener("change", () => {
        const saved = {};
        forYScales(c, (k, sc) => {
          if (sc.min != null) saved[k] = { min: sc.min, max: sc.max };
        });
        c.setSeries(si, { show: cb.checked });
        c.batch(() => {
          for (const [k, v] of Object.entries(saved)) c.setScale(k, v);
        });
      });
      lbl.appendChild(cb);
      lbl.insertAdjacentHTML(
        "beforeend",
        swatch(s) + `<span class="ip-color" style="--c:${sColor(s)}">${H(s.label)}</span>`,
      );
      togglesDiv.appendChild(lbl);
    }
    const toggle = mkEl("div", "info-toggle");
    toggle.textContent = "ℹ";
    toggle.onclick = () => {
      const open = !infoPanel.classList.contains("open");
      for (const ch of charts) {
        ch._infoPanel.classList.toggle("open", open);
        ch.root.closest(".row").classList.toggle("has-info", open);
      }
      const { W } = layoutDims();
      for (const ch of charts) ch.setSize({ width: W, height: ch.height });
    };
    panelEl.appendChild(toggle);
    c._infoPanel = infoPanel;
    c._dataDiv = dataDiv;
    if (_origData) c._origData = _origData;
    c._fullXMin = globalXMin;
    c._fullXMax = globalXMax;
    c._initY = {};
    for (const [k, r] of Object.entries(yRanges))
      c._initY[k] = { min: r.min, max: r.max };
    c._rangeLock = rangeLock;
    c._activeScale = null;
    charts.push(c);
    return c;
  }

  function axisHlPlugin() {
    return {
      hooks: {
        drawClear: [
          (u) => {
            const orig = u.ctx.fillText.bind(u.ctx);
            u._restoreFillText = () => {
              u.ctx.fillText = orig;
            };
            u._labelPos = {};
            u.ctx.fillText = function (text, x, y, maxW) {
              for (let ai = 1; ai < u.axes.length; ai++) {
                const ax = u.axes[ai];
                if (ax.scale === "x") continue;
                const lbl =
                  typeof ax.label === "function"
                    ? ax.label(u, ai)
                    : ax.label;
                if (lbl && text === lbl) {
                  u._labelPos[ax.scale] = {
                    transform: u.ctx.getTransform(),
                    x,
                    y,
                    ai,
                    textAlign: u.ctx.textAlign,
                    textBaseline: u.ctx.textBaseline,
                  };
                  break;
                }
              }
              return orig(text, x, y, maxW);
            };
          },
        ],
        draw: [
          (u) => {
            if (u._restoreFillText) {
              u._restoreFillText();
              u._restoreFillText = null;
            }
            const pos = u._labelPos?.[u._activeScale];
            if (!pos) return;
            const ax = u.axes[pos.ai];
            const lbl =
              typeof ax.label === "function"
                ? ax.label(u, pos.ai)
                : ax.label;
            if (!lbl) return;
            const ctx = u.ctx;
            const r = devicePixelRatio;
            ctx.save();
            ctx.setTransform(pos.transform);
            ctx.font =
              ax.labelFont?.[0] || "bold 12px system-ui, sans-serif";
            const m = ctx.measureText(lbl);
            const pad = 4 * r;
            const asc = m.actualBoundingBoxAscent || 10;
            const dsc = m.actualBoundingBoxDescent || 2;
            let cx = pos.x,
              cy = pos.y;
            if (
              pos.textAlign === "start" ||
              pos.textAlign === "left"
            )
              cx += m.width / 2;
            else if (
              pos.textAlign === "end" ||
              pos.textAlign === "right"
            )
              cx -= m.width / 2;
            if (pos.textBaseline === "alphabetic")
              cy -= (asc - dsc) / 2;
            else if (pos.textBaseline === "top")
              cy += (asc + dsc) / 2;
            else if (pos.textBaseline === "bottom")
              cy -= (asc + dsc) / 2;
            const hw = m.width / 2 + pad;
            const hh = (asc + dsc) / 2 + pad;
            ctx.strokeStyle = dk ? "#ccc" : "#222";
            ctx.lineWidth = 2 * r;
            ctx.beginPath();
            ctx.roundRect(cx - hw, cy - hh, hw * 2, hh * 2, 4 * r);
            ctx.stroke();
            ctx.restore();
          },
        ],
      },
    };
  }
  const _axisHlP = axisHlPlugin();

  // Per-point deviation from linear interpolation (Ramer-Douglas-Peucker criterion).
  // Stored as fraction of y-range; cached per chart+series.
  function getPointDev(u, si) {
    if (!u._devCache) u._devCache = new Map();
    if (u._devCache.has(si)) return u._devCache.get(si);
    const gIdx = getNonNullIndices(u, si);
    const d = u.data[si],
      x = u.data[0];
    let yMin = Infinity,
      yMax = -Infinity;
    for (let k = 0; k < gIdx.length; k++) {
      const v = d[gIdx[k]];
      if (v < yMin) yMin = v;
      if (v > yMax) yMax = v;
    }
    const yRange = yMax - yMin || 1;
    const dev = new Float32Array(gIdx.length);
    for (let k = 1; k < gIdx.length - 1; k++) {
      const p = gIdx[k - 1],
        i = gIdx[k],
        n = gIdx[k + 1];
      const dx1 = x[i] - x[p],
        dx2 = x[n] - x[i];
      if (dx1 + dx2 <= 0) continue;
      const predicted = d[p] + ((d[n] - d[p]) * dx1) / (dx1 + dx2);
      dev[k] = Math.abs(d[i] - predicted) / yRange;
    }
    dev[0] = dev[gIdx.length - 1] = 1;
    u._devCache.set(si, dev);
    return dev;
  }

  const ptsFilter = (u, si) => {
    const d = u.data[si],
      s = u.series[si],
      idxs = s.idxs;
    if (!d || !idxs) return null;
    const [i0, i1] = idxs;
    const gIdx = getNonNullIndices(u, si);
    if (!gIdx.length) return null;
    const lo = bisect(gIdx, i0);
    const lo2 = bisect(gIdx, i1 + 1, lo);
    const nn = lo2 - lo;
    if (!nn) return null;
    // Hierarchical 2D spatial thinning: process coarsest power-of-2 grid first,
    // then finer levels. A point is included if its pixel cell isn't occupied by
    // a higher-priority point. Points shown zoomed out stay when zooming in.
    // For line series, high-deviation corners are always included first.
    const minD =
      s.width > 0 ? (s.points?.size || 4) * 0.6 : (s.points?.size || 4) * 0.1;
    const occ = new Set();
    function cellKey(px, py) {
      return ((px / minD) | 0) * spatialGridScale + ((py / minD) | 0);
    }
    function tryAdd(idx) {
      const px = u.valToPos(u.data[0][idx], "x");
      const py = u.valToPos(d[idx], s.scale);
      const cx = (px / minD) | 0,
        cy = (py / minD) | 0;
      for (let dx = -1; dx <= 1; dx++)
        for (let dy = -1; dy <= 1; dy++)
          if (occ.has((cx + dx) * spatialGridScale + (cy + dy))) return false;
      occ.add(cellKey(px, py));
      return true;
    }
    let step = 1;
    while (nn / step > thinTargetPts) step *= 2;
    const dev = s.width > 0 ? getPointDev(u, si) : null;
    const out = [];
    // Pass 0: high-deviation corners (line series only) — highest priority
    if (dev) {
      for (let i = lo; i < lo2; i++)
        if (dev[i] >= step / nn && tryAdd(gIdx[i])) out.push(gIdx[i]);
    }
    // Passes 1..N: power-of-2 grid levels, coarsest first
    for (let s2 = step; s2 >= 1; s2 >>= 1) {
      for (let i = lo; i < lo2; i++) {
        if (s2 > 1 && (i - lo) % s2 !== 0) continue;
        if (s2 < step && (i - lo) % (s2 << 1) === 0) continue;
        if (tryAdd(gIdx[i])) out.push(gIdx[i]);
      }
    }
    return out;
  };
  const S = (label, stroke, scale, extra) => ({
    label,
    stroke,
    scale,
    width: 1,
    points: { size: 5, width: 0, show: true, fill: stroke, filter: ptsFilter },
    spanGaps: true,
    ...extra,
  });
  const P = (label, stroke, scale, extra) =>
    S(label, stroke, scale, {
      width: 0,
      points: {
        size: 4,
        width: 0,
        show: true,
        fill: stroke,
        filter: ptsFilter,
      },
      ...extra,
    });

  // ── Build panel data using uPlot.join() ─────────────────────────────
  const lossTriggers = [
    "pto_expired",
    "time_threshold",
    "reordering_threshold",
  ];
  const activeLoss = lossTriggers.filter((t) => D.lost[t]);
  const p1LossSeries = activeLoss.map((t) => P(LS[t][1], LS[t][0], "pn"));

  // Panel 1: packet timeline with modulo wrapping for vertical resolution

  const p1Raw = uPlot.join([
    D.sent,
    D.acked,
    ...activeLoss.map((t) => D.lost[t]),
  ]);
  const p1Unwrapped = [
    p1Raw[0],
    p1Raw[1],
    p1Raw[2],
    ...activeLoss.map((_, i) => p1Raw[3 + i]),
  ];

  // Build pn → loss/ECN info maps for recoloring points and info panel
  const ecnCePnSet = new Set(D.ecnCe[1]);
  const lostPnMap = new Map();
  for (const trig of activeLoss) {
    const pns = D.lost[trig][1];
    for (const pn of pns) {
      const entry = lostPnMap.get(pn) || { triggers: [] };
      entry.triggers.push({ color: LS[trig][0], label: LS[trig][1] });
      entry.color = LS[trig][0];
      entry.label = LS[trig][1];
      lostPnMap.set(pn, entry);
    }
  }

  // Auto-compute modulo: target ~8 wraps, but at least max-in-flight packets
  // to prevent overlapping wraps within one RTT.
  let maxPn = 0;
  for (let si = 1; si < p1Unwrapped.length; si++) {
    const a = p1Unwrapped[si];
    if (!a) continue;
    for (let i = 0; i < a.length; i++)
      if (a[i] != null && a[i] > maxPn) maxPn = a[i];
  }
  const maxCwnd = D.metrics[D.mi.congestion_window]
    ? D.metrics[D.mi.congestion_window].reduce(
        (mx, v) => (v != null && v > mx ? v : mx),
        0,
      )
    : 0;
  let maxPktSize = 1;
  for (const pn of Object.keys(D.pktMeta)) {
    const m = D.pktMeta[pn];
    if (m[0] != null) maxPktSize = Math.max(maxPktSize, m[2]);
    else
      for (const fr of m[1])
        if (fr.length) maxPktSize = Math.max(maxPktSize, fr.length);
  }
  const maxInflight = Math.ceil(maxCwnd / maxPktSize);
  const raw = Math.max(50, maxInflight * 2, Math.ceil(maxPn / 8));
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const pnMod = [1, 2, 5, 10].find((m) => m * mag >= raw) * mag;

  // Store originals for info panel, then wrap
  const p1Orig = p1Unwrapped.map((a) => a);
  function wrapPn(arr) {
    if (!arr) return arr;
    const out = new Array(arr.length);
    for (let i = 0; i < arr.length; i++) {
      if (arr[i] == null) {
        out[i] = null;
        continue;
      }
      const w = arr[i] % pnMod;
      if (i > 0 && arr[i - 1] != null && w < arr[i - 1] % pnMod) out[i] = null;
      else out[i] = w;
    }
    return out;
  }
  const p1Base = [p1Unwrapped[0], ...p1Unwrapped.slice(1).map(wrapPn)];
  // Join connection FC budget and FC event markers into panel 1
  const p1ConnFcData = D.fcConnBudget[0].length > 0 ? D.fcConnBudget : null;
  const p1FcTables = [];
  if (p1ConnFcData) p1FcTables.push(p1ConnFcData);
  if (hasFcConnBlocked) p1FcTables.push(fcConnBlockedData);
  if (hasFcConnIncreased) p1FcTables.push(fcConnIncreasedData);
  const p1Data = p1FcTables.length
    ? uPlot.join([p1Base, ...p1FcTables])
    : p1Base;

  // Panel 2: per-stream bytes (own panel with per-stream colors)
  const streamIds = Object.keys(D.streamBytes).sort((a, b) => a - b);
  const streamColors = [
    OI.blue,
    OI.vermillion,
    OI.green,
    OI.orange,
    OI.cyan,
    OI.gray,
  ];
  const p2StreamFcIds = streamIds.filter((sid) => D.fcStreamBudget[sid]);
  const p2Tables = [
    ...streamIds.map((sid) => D.streamBytes[sid]).filter(Boolean),
    ...p2StreamFcIds.map((sid) => D.fcStreamBudget[sid]),
    ...fcEventStreamIds.flatMap((sid) => [
      ...(fcStreamBlockedBySid[sid] ? [fcStreamBlockedBySid[sid]] : []),
      ...(fcStreamIncreasedBySid[sid] ? [fcStreamIncreasedBySid[sid]] : []),
    ]),
  ];
  const p2Data = p2Tables.length ? uPlot.join(p2Tables) : null;

  // Panel 3: congestion metrics
  const M = D.metrics,
    mi = D.mi;
  const p3Data = [
    M[0],
    M[mi.pacing_rate],
    M[mi.bytes_in_flight],
    M[mi.ssthresh],
    M[mi.congestion_window],
  ];

  // Panel 4: send gaps (FC gaps recolored) + RTT metrics
  const fcGapTimes = new Set();
  {
    const fcAll = [...fcStreamIntervals, ...fcConnIntervals].sort(
      (a, b) => a[0] - b[0],
    );
    for (let i = 0, fi = 0; i < D.sendGap[0].length; i++) {
      const mid = D.sendGap[0][i];
      while (fi < fcAll.length && fcAll[fi][1] < mid) fi++;
      if (fi < fcAll.length && fcAll[fi][0] <= mid) fcGapTimes.add(mid);
    }
  }
  const p4Raw = uPlot.join([
    [M[0], M[mi.min_rtt], M[mi.latest_rtt], M[mi.smoothed_rtt]],
    D.sendGap,
  ]);
  // p4Raw = [t, min_rtt(1), latest_rtt(2), smoothed_rtt(3), sendGap(4)]
  const p4Data = [p4Raw[0], p4Raw[4], p4Raw[1], p4Raw[2], p4Raw[3]];

  function buildMap(arr) {
    const m = new Map();
    for (let i = 0; i < arr[0].length; i++) m.set(arr[1][i], arr[0][i]);
    return m;
  }
  const pnAckTime = buildMap(D.acked),
    pnSentTime = buildMap(D.sent);
  const pnLostTime = new Map();
  for (const trig of activeLoss) {
    const [t, pns] = D.lost[trig];
    for (let i = 0; i < pns.length; i++) pnLostTime.set(pns[i], t[i]);
  }
  // Reconstruct pn→ranges and pn→recvPn from deduped ackRanges+ackIdx
  const pnRanges = {},
    ackRecvPn = {};
  for (const [pn, idx] of Object.entries(D.ackIdx || {})) {
    const [rngs, rpn] = D.ackRanges[idx];
    pnRanges[pn] = rngs;
    if (rpn != null) ackRecvPn[pn] = rpn;
  }
  // Precompute loss pn → {gap, recvPn} for reordering losses.
  // Build flat sorted gap list from unique ackRanges, then scan-match losses.
  const lossGapInfo = new Map();
  if (D.lost.reordering_threshold) {
    const gaps = [];
    for (const [rngs, rpn] of D.ackRanges) {
      const asc = [...rngs].sort((a, b) => a[0] - b[0]);
      for (let g = 0; g < asc.length - 1; g++)
        gaps.push({ lo: asc[g][1] + 1, hi: asc[g + 1][0] - 1, rpn });
    }
    gaps.sort((a, b) => a.lo - b.lo);
    for (const pn of D.lost.reordering_threshold[1]) {
      const lo = bisect(gaps, pn, 0, gaps.length, (g) => g.hi);
      if (lo < gaps.length && pn >= gaps[lo].lo) lossGapInfo.set(pn, gaps[lo]);
    }
  }

  // Plugin: draw RTT line between sent packet and its ACK (or vice versa)
  function rttLinePlugin(sentSi, ackSiList) {
    const allSi = [[sentSi, true], ...ackSiList.map((si) => [si, false])];
    const els = [];
    function mkPair(parent) {
      const line = mkEl("div", "rtt-line"),
        arrow = mkEl("div", "rtt-arrow"),
        label = mkEl("div", "rtt-label");
      line.style.display = arrow.style.display = label.style.display = "none";
      label.style.transform = "translateX(-50%)";
      parent.append(line, arrow, label);
      return { line, arrow, label };
    }
    function hide(j) {
      els[j].line.style.display =
        els[j].arrow.style.display =
        els[j].label.style.display =
          "none";
    }
    return {
      hooks: {
        init: [
          (u) => {
            for (let i = 0; i < allSi.length; i++) els.push(mkPair(u.over));
          },
        ],
        setCursor: [
          (u) => {
            if (_frozen) return;
            const plotH = u.over.clientHeight;
            const ci = u.cursor.idx;
            const active = [];
            for (let j = 0; j < allSi.length; j++) {
              const [si, isSent] = allSi[j];
              if (!u.series[si].show) {
                hide(j);
                continue;
              }
              if (!isSent && !u.series[sentSi].show) {
                hide(j);
                continue;
              }
              if (isSent && ackSiList.every((asi) => !u.series[asi].show)) {
                hide(j);
                continue;
              }
              if (u._shownSi && !u._shownSi.has(si)) {
                hide(j);
                continue;
              }
              const hi = ci != null ? nearestNonNull(u, si, ci) : null;
              if (hi == null) {
                hide(j);
                continue;
              }
              const v = u.data[si][hi];
              if (v == null) {
                hide(j);
                continue;
              }
              const pn = origPn(u, si, hi);
              if (pn == null) {
                hide(j);
                continue;
              }
              const lossInfo = isSent ? lostPnMap.get(pn) : null;
              const sentT = isSent ? u.data[0][hi] : pnSentTime.get(pn);
              const otherT = isSent
                ? lossInfo
                  ? pnLostTime.get(pn)
                  : pnAckTime.get(pn)
                : u.data[0][hi];
              if (sentT == null || otherT == null) {
                hide(j);
                continue;
              }
              const x1 = u.valToPos(sentT, "x"),
                x2 = u.valToPos(otherT, "x");
              const y = u.valToPos(v, "pn");
              const left = Math.min(x1, x2),
                w = Math.abs(x2 - x1);
              if (x1 < 0 || x2 < 0 || y < 0 || w < rttMinWidth) {
                hide(j);
                continue;
              }
              const c = lossInfo ? lossInfo.color : sColor(u.series[si], u, si);
              const { line, arrow } = els[j];
              const otherX = isSent ? x2 : x1;
              const pointsRight = otherX > left + w / 2;
              const aw = 8;
              const lx = pointsRight ? left : left + aw;
              const lw = w - aw;
              line.style.display = "";
              line.style.borderColor = c;
              line.style.left = lx + "px";
              line.style.top = y + "px";
              line.style.width = lw + "px";
              arrow.style.display = "";
              arrow.className =
                "rtt-arrow " + (pointsRight ? "rtt-arrow-r" : "rtt-arrow-l");
              arrow.style.borderLeftColor = arrow.style.borderRightColor = c;
              arrow.style.left = (pointsRight ? left + w - aw : left) + "px";
              arrow.style.top = y - 5 + "px";
              active.push({ j, left, w, y, c, dt: Math.abs(otherT - sentT) });
            }
            // Pass 2: place labels avoiding lines and other labels
            const obstacles = active.map((a) => ({
              x: a.left + a.w / 2,
              y: a.y,
              w: a.w,
            }));
            const placed = [];
            const hitTest = (lx, ly) => {
              for (const o of obstacles)
                if (
                  Math.abs(ly - o.y) < 6 &&
                  lx >= o.x - o.w / 2 - 10 &&
                  lx <= o.x + o.w / 2 + 10
                )
                  return true;
              for (const p of placed)
                if (Math.abs(lx - p.x) < 30 && Math.abs(ly - p.y) < 11)
                  return true;
              return false;
            };
            for (const a of active) {
              const { j, left, w, y, c, dt } = a;
              const { label } = els[j];
              const above = y > plotH / 2;
              const candidates = [];
              for (const xf of [0.5, 0.25, 0.75])
                for (const yoff of [
                  above ? -14 : 4,
                  above ? -25 : 15,
                  above ? 4 : -14,
                ])
                  candidates.push({ lx: left + w * xf, ly: y + yoff });
              let best = candidates[0];
              for (const c of candidates) {
                if (!hitTest(c.lx, c.ly)) {
                  best = c;
                  break;
                }
              }
              placed.push({ x: best.lx, y: best.ly });
              label.style.display = "";
              label.style.color = c;
              label.style.left = best.lx + "px";
              label.style.top = best.ly + "px";
              label.textContent = fmtMs(dt);
            }
          },
        ],
      },
    };
  }

  // FC event point helpers: filled (blocked) and hollow (increased)
  const fcPtFilled = (col) => ({
    size: 4,
    width: 0,
    show: true,
    fill: col,
  });
  const fcPtHollow = (col) => ({
    size: 4,
    width: 1,
    show: true,
    stroke: col,
    fill: "transparent",
  });
  const fcLighten = 0.55;
  const fcConnStroke = lighten(OI.vermillion, fcLighten);

  // ── Panel definitions ───────────────────────────────────────────────
  const panels = [
    {
      id: "p1",
      scales: { x: { time: false }, pn: {}, fcb: {} },
      axes: [
        xAx,
        {
          ...axProps,
          scale: "pn",
          label: `Packet (mod ${N(pnMod)})`,
          values: fmtPnAxis,
        },
        {
          ...axProps,
          scale: "fcb",
          side: 1,
          label: axLabel("Connection FC Budget"),
          values: fmtBAxis,
        },
      ],
      series: [
        {},
        S("Sent", OI.blue, "pn"),
        P("ACK", OI.orange, "pn"),
        ...p1LossSeries,
        ...(p1ConnFcData
          ? [
              S("Connection FC Budget", fcConnStroke, "fcb", {
                width: 1,
                paths: stepped,
                points: { show: false },
              }),
            ]
          : []),
        ...(hasFcConnBlocked
          ? [
              P("FC Blocked", OI.vermillion, "fcb", {
                _fcEvent: "blocked",
                _fcConn: true,
                _hollow: true,
                points: fcPtHollow(OI.vermillion),
              }),
            ]
          : []),
        ...(hasFcConnIncreased
          ? [
              P("FC Increased", fcConnStroke, "fcb", {
                _fcEvent: "increased",
                _fcConn: true,
                points: fcPtFilled(fcConnStroke),
              }),
            ]
          : []),
      ],
      data: p1Data,
      extraPlugins: [
        recolorPlugin(
          (si) => si === 1 || si === 2,
          (u, si, i) => {
            const pn = origPn(u, si, i);
            if (pn == null) return null;
            if (si === 1) {
              const li = lostPnMap.get(pn);
              if (li) return li.color;
            }
            if (si === 2 && ecnCePnSet.has(pn)) return OI.cyan;
            return null;
          },
        ),
        rttLinePlugin(1, [2, ...activeLoss.map((_, i) => 3 + i)]),
      ],
      _origData: p1Orig,
    },
    {
      id: "p2",
      scales: { x: { time: false }, sb: {}, sfcb: {} },
      axes: [
        xAx,
        {
          ...axProps,
          scale: "sb",
          label: axLabel("Stream Bytes"),
          values: fmtBAxis,
        },
        {
          ...axProps,
          scale: "sfcb",
          side: 1,
          label: axLabel("Stream FC Budget"),
          values: fmtBAxis,
        },
      ],
      series: [
        {},
        ...streamIds.map((sid, i) => {
          const col = streamColors[i % streamColors.length];
          const d = streamDashes[i % streamDashes.length];
          return S(`Stream ${sid}`, col, "sb", {
            width: 1.5,
            ...(d ? { dash: d } : {}),
          });
        }),
        ...p2StreamFcIds
          .map((sid, i) => {
            const col =
              streamColors[streamIds.indexOf(sid) % streamColors.length];
            return S(`Stream ${sid} FC`, lighten(col, fcLighten), "sfcb", {
              width: 1,
              paths: stepped,
              points: { show: false },
            });
          }),
        ...fcEventStreamIds.flatMap((sid) => {
          const sidIdx = streamIds.indexOf(sid);
          const baseCol =
            streamColors[(sidIdx >= 0 ? sidIdx : 0) % streamColors.length];
          const lightCol = lighten(baseCol, fcLighten);
          return [
            ...(fcStreamBlockedBySid[sid]
              ? [
                  P(`Stream ${sid} FC Blocked`, baseCol, "sfcb", {
                    _fcEvent: "blocked",
                    _fcSid: +sid,
                    _hollow: true,
                    points: fcPtHollow(baseCol),
                  }),
                ]
              : []),
            ...(fcStreamIncreasedBySid[sid]
              ? [
                  P(`Stream ${sid} FC Increased`, lightCol, "sfcb", {
                    _fcEvent: "increased",
                    _fcSid: +sid,
                    points: fcPtFilled(lightCol),
                  }),
                ]
              : []),
          ];
        }),
      ],
      data: p2Data,
    },
    {
      id: "p3",
      scales: { x: { time: false }, bytes: {}, rate: {} },
      axes: [
        xAx,
        {
          ...axProps,
          scale: "bytes",
          label: axLabel("Bytes"),
          values: fmtBAxis,
        },
        {
          ...axProps,
          scale: "rate",
          label: axLabel("Pacing Rate"),
          side: 1,
          values: fmtBpsAxis,
        },
      ],
      series: [
        {},
        S("Pacing Rate", OI.orange, "rate", { width: 1.5, paths: stepped }),
        S("BIF", OI.blue, "bytes", { paths: stepped }),
        S("ssthresh", OI.vermillion, "bytes", { dash: [6, 3], paths: stepped }),
        S("cwnd", OI.green, "bytes", { width: 2, paths: stepped }),
      ],
      data: p3Data,
    },
    {
      id: "p4",
      scales: { x: { time: false }, rtt: {}, gap: {} },
      axes: [
        xAx,
        { ...axProps, scale: "rtt", label: axLabel("RTT"), values: fmtMsAxis },
        {
          ...axProps,
          scale: "gap",
          label: axLabel("Send Gap"),
          side: 1,
          values: fmtMsAxis,
        },
      ],
      series: [
        {},
        P("Send Gap", OI.gray, "gap"),
        S("minRTT", OI.orange, "rtt"),
        S("lRTT", dk ? "#999" : "#555", "rtt"),
        S("sRTT", OI.blue, "rtt", { width: 2 }),
      ],
      data: p4Data,
      linkedY: ["rtt", "gap"],
      extraPlugins: [
        recolorPlugin(
          (si) => si === 1,
          (u, si, i) => (fcGapTimes.has(u.data[0][i]) ? OI.vermillion : null),
        ),
      ],
    },
  ];

  // Global x-range across all panels so axes always align
  let globalXMin = Infinity,
    globalXMax = -Infinity;
  for (const p of panels) {
    const t = p.data?.[0];
    if (t?.length) {
      if (t[0] < globalXMin) globalXMin = t[0];
      if (t[t.length - 1] > globalXMax) globalXMax = t[t.length - 1];
    }
  }
  if (!isFinite(globalXMin)) {
    globalXMin = 0;
    globalXMax = 1;
  }
  // Fill in empty panels with a minimal time array so uPlot renders axes
  for (const p of panels) {
    if (!p.data || !p.data[0] || !p.data[0].length) {
      const t = [globalXMin, globalXMax];
      p.data = [t, ...p.series.slice(1).map(() => [null, null])];
    }
  }

  // ── Create charts ───────────────────────────────────────────────────
  function layoutDims() {
    const hdr =
      document.querySelector(".hdr").offsetHeight +
      document.getElementById("ccleg").offsetHeight +
      16;
    return {
      W: document.getElementById("p1").clientWidth,
      H: Math.max(
        Math.floor((window.innerHeight - hdr) / panels.length) - 8,
        120,
      ),
    };
  }

  const { W: initW, H: initH } = layoutDims();
  const minXRange = (globalXMax - globalXMin) / initW;
  const rttMinWidth = initW * 0.02;
  const thinTargetPts = Math.max(10, Math.round(initW / 40));
  const spatialGridScale = Math.max(initH, initW) * 10;

  function init() {
    for (const p of panels) mkChart(p, initW, initH);
    for (const c of charts) c.redraw(false);
  }
  init();

  window.addEventListener("resize", () => {
    const { W, H } = layoutDims();
    for (const c of charts) c.setSize({ width: W, height: H });
  });
}).catch((e) => {
  document.body.classList.add("error");
  document.body.textContent = "Failed to load trace data: " + e;
}); // end decompress().then()
