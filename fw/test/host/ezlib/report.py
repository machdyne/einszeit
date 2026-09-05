"""Builds the validation report.

Design intent: this is a measurement record, not a dashboard. It opens with the
one number the device's whole security claim rests on -- min-entropy per
captured bit -- expressed in the terms that matter operationally for a
one-time-pad device, which is how many raw bits you must capture per bit of
usable key. Everything below that is evidence, separated by rules rather than
boxed into cards, so it reads top to bottom like a lab notebook.
"""

from __future__ import annotations

import datetime
import html
import json
import math

CSS = """
:root {
  --paper:#F7F8F7; --ink:#14181A; --muted:#5F6B6F; --rule:#C9D0D3;
  --accent:#2D5BA8; --pass:#1F7A5C; --warn:#B37400; --fail:#B3261E;
}
*{box-sizing:border-box}
body{
  margin:0; background:var(--paper); color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  font-size:15px; line-height:1.55; -webkit-font-smoothing:antialiased;
}
.wrap{max-width:940px;margin:0 auto;padding:56px 28px 96px}
p,li{max-width:68ch}
h1{font-size:27px;line-height:1.2;font-weight:600;margin:0 0 6px}
h2{font-size:19px;font-weight:600;margin:0 0 14px;letter-spacing:-0.01em}
h3{font-size:15px;font-weight:600;margin:26px 0 8px}
a{color:var(--accent)}
.sub{color:var(--muted);font-size:13.5px;margin:0}
section{border-top:1px solid var(--rule);padding-top:26px;margin-top:38px}
code,.mono,td.num,th.num{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  font-variant-numeric:tabular-nums}

/* hero */
.headline{display:flex;align-items:baseline;gap:16px;flex-wrap:wrap;margin:30px 0 4px}
.figure-big{font-size:76px;line-height:0.92;font-weight:600;letter-spacing:-0.035em;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.figure-unit{font-size:16px;color:var(--muted);max-width:20ch}
.budget{margin:18px 0 4px;font-size:15px}
.budget b{font-weight:600}
.gauge{height:9px;background:#E4E9EA;border-radius:0;margin:20px 0 8px;max-width:640px;position:relative}
.gauge > i{display:block;height:100%;background:var(--accent)}
.gauge-labels{display:flex;justify-content:space-between;max-width:640px;
  font-size:12px;color:var(--muted)}

/* verdict strip */
.strip{display:flex;gap:0;margin:26px 0 6px;border:1px solid var(--rule);max-width:760px;flex-wrap:wrap}
.strip div{flex:1 1 0;min-width:150px;padding:12px 14px;border-right:1px solid var(--rule)}
.strip div:last-child{border-right:0}
.strip .k{font-size:12.5px;color:var(--muted);margin-bottom:3px}
.strip .v{font-size:15px;font-weight:600}
.pass{color:var(--pass)} .warn{color:var(--warn)} .fail{color:var(--fail)}

table{border-collapse:collapse;width:100%;margin:12px 0 6px;font-size:13.5px}
th{text-align:left;font-weight:600;color:var(--muted);padding:7px 10px 7px 0;
  border-bottom:1px solid var(--rule);font-size:12.5px}
td{padding:7px 10px 7px 0;border-bottom:1px solid #E4E9EA;vertical-align:top}
td.num,th.num{text-align:right;padding-right:18px}
tr.bad td{background:#FCF2F1}
figure{margin:22px 0}
figure img{width:100%;border:1px solid var(--rule);background:white}
figcaption{font-size:12.5px;color:var(--muted);margin-top:7px;max-width:68ch}
.note{border-left:3px solid var(--warn);padding:9px 0 9px 14px;margin:16px 0;
  font-size:13.5px;color:#4A4136;background:#FDF9F1}
.caution{border-left-color:var(--fail);background:#FCF2F1;color:#4A2320}
details{margin:10px 0;font-size:13.5px}
summary{cursor:pointer;color:var(--accent)}
pre{background:white;border:1px solid var(--rule);padding:12px;overflow-x:auto;
  font-size:12px;line-height:1.45}
footer{margin-top:54px;padding-top:18px;border-top:1px solid var(--rule);
  font-size:12.5px;color:var(--muted)}
@media print{body{background:white} section{break-inside:avoid}}
"""


def _uuid_line(meta: dict, dev: dict) -> str:
    """Tie the report to a specific die, visibly rather than in a JSON dump."""
    uuid = meta.get("device_uuid") or meta.get("board_id")
    if not uuid and dev:
        info = dev.get("info") or {}
        uuid = info.get("device_uuid") or info.get("board_id")
    if not uuid:
        return ('<p class="sub">Device UUID not recorded: this capture predates '
                'firmware 1.4.0 and cannot be tied to a specific die.</p>')
    return (f'<p class="sub">Device <span class="mono">{_esc(uuid)}</span> '
            f'\u00b7 RP2350 OTP CHIPID, unique per die</p>')


def _esc(x) -> str:
    return html.escape(str(x))


def _fmt(v, digits=4):
    if v is None:
        return "&mdash;"
    if isinstance(v, float):
        if v != v:
            return "&mdash;"
        if v == 0:
            return "0"
        if abs(v) < 1e-4 or abs(v) >= 1e6:
            return f"{v:.3e}"
        return f"{v:.{digits}f}"
    if isinstance(v, int):
        return f"{v:,}"
    return _esc(v)


def _verdict(ok, good="pass", bad="fail"):
    cls = "pass" if ok else "fail"
    return f'<span class="{cls}">{good if ok else bad}</span>'


def _sts_headline(ctx: dict) -> str:
    """The multi-sequence run is the governing result when it was made."""
    multi = ctx.get("sts_multi")
    if multi and not multi.get("error"):
        n = len(multi["tests"])
        bad = len(multi.get("failed", []))
        marg = len(multi.get("marginal", []))
        if bad:
            return f'<span class="fail">{bad} of {n} failed</span>'
        suffix = f", {marg} marginal" if marg else ""
        return f'<span class="pass">{n}/{n} pass{suffix}</span>'
    summ = ctx["sts_summary"]
    ok = summ["pass"]
    text = (f"{summ['ran'] - len(summ['failed'])}/{summ['ran']} pass" if ok
            else f"{len(summ['failed'])} of {summ['ran']} failed")
    return f'<span class="{"pass" if ok else "fail"}">{text}</span>'


def _fig(b64, caption):
    if not b64:
        return ""
    return (f'<figure><img alt="{_esc(caption)}" src="data:image/png;base64,{b64}">'
            f"<figcaption>{caption}</figcaption></figure>")


def build(ctx: dict) -> str:
    """ctx keys: meta, basic, assessment, assessment_bytes, sts, ais, fips,
    restart, figures, device, sweep, conditioned."""
    a = ctx["assessment"]
    basic = ctx["basic"]
    meta = ctx.get("meta", {})
    figs = ctx.get("figures", {})
    dev = ctx.get("device", {})

    h = a.h_min
    mode = meta.get("mode", "unknown")
    raw_mode = mode == "raw"

    # Operational translation: how much raw capture buys one bit of key.
    if h > 0:
        expansion = 1.0 / h
        budget = (f"At this rate, one byte of one-time-pad key needs "
                  f"<b>{expansion * 8:,.1f} bits</b> "
                  f"({expansion:.2f} raw bits per key bit) fed through a "
                  f"conditioning function that preserves min-entropy.")
    else:
        expansion = float("inf")
        budget = ("A min-entropy of zero means no amount of this data yields "
                  "key material. Treat the source as failed.")

    sts_summary = ctx["sts_summary"]
    ais = ctx["ais"]
    fips = ctx["fips"]

    parts = [f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Einszeit V1 hardware validation</title><style>{CSS}</style></head><body><div class="wrap">
<h1>Einszeit V1 hardware validation</h1>
<p class="sub">{_esc(ctx.get('title_line', ''))}</p>
{_uuid_line(meta, dev)}
"""]

    # ---- hero ----------------------------------------------------------
    pct = max(0.0, min(1.0, h))
    parts.append(f"""
<div class="headline">
  <div class="figure-big">{h:.4f}</div>
  <div class="figure-unit">bits of min-entropy per captured bit<br>
    <span class="mono">{_esc(a.limiting)}</span> is the limiting estimator</div>
</div>
<div class="gauge"><i style="width:{pct * 100:.1f}%"></i></div>
<div class="gauge-labels"><span>0</span><span>1.0, a perfect binary source</span></div>
<p class="budget">{budget}</p>
""")

    ais_ok = ais["pass"]
    parts.append(f"""
<div class="strip">
  <div><div class="k">Capture mode</div><div class="v">{_esc(mode)}</div></div>
  <div><div class="k">SP 800-90B</div><div class="v mono">{h:.4f} bit/bit</div></div>
  <div><div class="k">SP 800-22</div><div class="v">{_sts_headline(ctx)}</div></div>
  <div><div class="k">AIS-31 (2011)</div><div class="v">{_verdict(ais_ok,
     'all pass', f"{len(ais['failed'])} failed")}</div></div>
  <div><div class="k">FIPS 140-2 4.9.1</div><div class="v">{_verdict(fips.get('pass', False),
     f"{fips.get('blocks', 0)} blocks", 'failed')}</div></div>
</div>
""")

    if raw_mode:
        parts.append("""
<div class="note">This capture is the <b>raw noise source</b>, taken with the
Von Neumann balancer, the continuous RNG test and the autocorrelation test all
bypassed. Bias and correlation are expected here and are not defects. This is
the number SP 800-90B wants for an entropy source assessment. The conditioned
output the firmware would actually use is assessed separately below.</div>""")
    else:
        parts.append("""
<div class="note caution">This capture is the <b>conditioned</b> TRNG output.
Passing statistical tests on conditioned data says very little: a correctly
seeded DRBG passes all of them too. The min-entropy figure above is an upper
bound on what the post-processing preserved, not a measurement of the physical
source. Use a raw capture for the entropy claim.</div>""")

    # ---- entropy assessment --------------------------------------------
    parts.append('<section><h2>Entropy assessment</h2>')
    parts.append(f"<p>Assessed over {a.n_bits:,} bits using the non-IID track "
                 f"of SP 800-90B. The reported min-entropy is the smallest of "
                 f"the ten estimators, which is what the specification "
                 f"requires.</p>")
    parts.append(_fig(figs.get("estimators", ""),
                      "Each estimator bounds min-entropy from above in its own way; "
                      "the assessment takes the most pessimistic."))

    rows = []
    for e in a.estimates:
        bad = ' class="bad"' if (e.h_min == e.h_min and e.name == a.limiting) else ""
        note = e.detail.get("note", "")
        rows.append(f"<tr{bad}><td>{_esc(e.name)}</td>"
                    f'<td class="num mono">{_fmt(e.h_min)}</td>'
                    f"<td>{_esc(note)}</td></tr>")
    parts.append('<table><tr><th>Estimator</th><th class="num">H<sub>min</sub></th>'
                 f"<th>Note</th></tr>{''.join(rows)}</table>")

    for n in a.notes:
        parts.append(f'<div class="note">{_esc(n)}</div>')

    ceil = getattr(a, "detail_ceiling", None) or {}
    if ceil:
        if ceil["at_ceiling"]:
            parts.append(f"""<div class="note">The <b>{_esc(ceil['estimator'])}</b>
estimator is limiting, but it is reporting at its ceiling for this sample size.
Running the same estimator over an ideal uniform sample of {a.n_bits:,} bits
scores <b>{ceil['ideal_score']:.4f} &plusmn; {ceil.get('ideal_sd', 0):.4f}</b>
(mean of {ceil.get('trials', 5)} runs), against {ceil['measured']:.4f} measured.
The gap of {ceil['gap']:.4f} is within normal run-to-run spread, so at this
length the estimator cannot report higher and this figure reflects the
estimator rather than the source. Capture more to raise the ceiling.</div>""")
        else:
            parts.append(f"""<div class="note caution">The
<b>{_esc(ceil['estimator'])}</b> estimator scores {ceil['measured']:.4f} here
against {ceil['ideal_score']:.4f} &plusmn; {ceil.get('ideal_sd', 0):.4f} for
ideal samples of the same length. The gap of {ceil['gap']:.4f} exceeds the
{ceil.get('threshold', 0):.4f} threshold (three standard deviations), so it is
unlikely to be sample-size bias and is probably a real property of the
source.</div>""")

    if a.limiting == "Compression" and a.n_bits < 4_000_000 and not ceil:
        parts.append("""<div class="note">The compression estimator is limiting
here. Its expected-value curve is almost flat near maximum entropy, so the 99%
confidence subtraction costs a great deal at this sample size and the estimate
runs low. It converges slowly: expect it to rise toward the other estimators as
the capture grows past a few million bits. If the other nine estimators cluster
well above it, the true figure is probably nearer that cluster.</div>""")

    iid = a.iid_indicators
    parts.append(f"""<h3>Independence indicators</h3>
<table>
<tr><th>Check</th><th class="num">Statistic</th><th class="num">p</th></tr>
<tr><td>Chi-square goodness of fit</td><td class="num mono">{_fmt(iid.get('chi2_goodness_of_fit'), 2)}</td>
    <td class="num mono">{_fmt(iid.get('chi2_goodness_of_fit_p'))}</td></tr>
<tr><td>Chi-square independence</td><td class="num mono">{_fmt(iid.get('chi2_independence'), 2)}</td>
    <td class="num mono">{_fmt(iid.get('chi2_independence_p'))}</td></tr>
<tr><td>Longest repeated substring</td><td class="num mono">{_fmt(iid.get('lrs_length'))}</td>
    <td class="num mono">expected {_fmt(iid.get('lrs_expected_iid'), 1)}</td></tr>
</table>
<p><b>{_esc(iid.get('verdict', ''))}.</b> {_esc(iid.get('note', ''))}</p>""")
    parts.append("</section>")

    # ---- descriptive ----------------------------------------------------
    parts.append('<section><h2>Distribution and structure</h2>')
    comp = basic.compression
    parts.append(f"""<table>
<tr><th>Measure</th><th class="num">Value</th><th>Reference</th></tr>
<tr><td>Capture size</td><td class="num mono">{basic.nbytes:,} B</td><td>{basic.nbits:,} bits</td></tr>
<tr><td>Proportion of ones</td><td class="num mono">{basic.ones_fraction:.6f}</td><td>0.5</td></tr>
<tr><td>Bit bias</td><td class="num mono">{basic.bit_bias:+.6f}</td><td>0</td></tr>
<tr><td>Shannon entropy per bit</td><td class="num mono">{basic.shannon_bit:.6f}</td><td>1.0</td></tr>
<tr><td>Shannon entropy per byte</td><td class="num mono">{basic.shannon_byte:.6f}</td><td>8.0</td></tr>
<tr><td>Min-entropy per byte, most common value</td><td class="num mono">{basic.min_entropy_byte_mcv:.4f}</td><td>8.0</td></tr>
<tr><td>Byte chi-square</td><td class="num mono">{basic.byte_chi2:.1f}</td><td>255 &plusmn; 23, p = {basic.byte_chi2_p:.4f}</td></tr>
<tr><td>Arithmetic mean of bytes</td><td class="num mono">{basic.arithmetic_mean:.4f}</td><td>127.5</td></tr>
<tr><td>Monte Carlo &pi;</td><td class="num mono">{_fmt(basic.monte_carlo_pi, 5)}</td><td>error {_fmt(basic.monte_carlo_error * 100 if basic.monte_carlo_error == basic.monte_carlo_error else None, 3)}%</td></tr>
<tr><td>Serial correlation</td><td class="num mono">{_fmt(basic.serial_correlation, 6)}</td><td>0</td></tr>
<tr><td>Longest run of ones / zeros</td><td class="num mono">{basic.longest_run_ones} / {basic.longest_run_zeros}</td><td>~{math.log2(max(basic.nbits, 2)):.0f}</td></tr>
<tr><td>Compressed size (zlib / bz2 / lzma)</td><td class="num mono">{_fmt(comp.get('zlib'), 4)} / {_fmt(comp.get('bz2'), 4)} / {_fmt(comp.get('lzma'), 4)}</td><td>&ge; 1.0</td></tr>
</table>""")

    for key, cap in (
        ("bitmap", "Visual inspection. Any visible texture, banding or repetition "
                   "is a defect that the numeric tests may not isolate."),
        ("byte_hist", "Byte value distribution against the uniform expectation."),
        ("bitpos", "Bias by position inside one 192-bit entropy-holding-register "
                   "read. A repeating shape here points at the collection "
                   "mechanism rather than the ring oscillator."),
        ("autocorr", "Autocorrelation at short lags. A spike at a fixed lag "
                     "usually means the sampling interval is short enough that "
                     "consecutive samples share oscillator phase."),
        ("spectrum", "Power spectrum. Peaks indicate periodic structure, often "
                     "from a clock beating against the ring oscillator."),
        ("runs", "Run lengths against the 2^-k ideal."),
        ("drift", "Entropy across the capture, in order."),
    ):
        parts.append(_fig(figs.get(key, ""), cap))
    parts.append("</section>")

    # ---- standards -------------------------------------------------------
    parts.append('<section><h2>Standards conformance</h2>')

    multi = ctx.get("sts_multi")
    if multi and not multi.get("error"):
        rows = []
        for r in sorted(multi["tests"], key=lambda x: x["test"]):
            if r.get("ran", 0) == 0:
                rows.append(f"<tr><td>{_esc(r['test'])}</td><td></td>"
                            f'<td colspan="3" class="warn">'
                            f"{_esc(r.get('verdict', 'not run'))}</td></tr>")
                continue
            v = r["verdict"]
            cls = {"pass": "pass", "marginal": "warn"}.get(v, "fail")
            bad = ' class="bad"' if v == "fail" else ""
            subs = r.get("subtests", 1)
            skipped = (f" ({r['skipped']} seq n/a)" if r.get("skipped") else "")
            rows.append(
                f"<tr{bad}><td>{_esc(r['test'])}</td>"
                f'<td class="num">{subs if subs > 1 else ""}</td>'
                f'<td class="num mono">{r["passed"]}/{r["ran"]}{skipped}</td>'
                f'<td class="num mono">{r["proportion"]:.3f} vs {r["bounds"][0]:.3f}</td>'
                f'<td class="{cls}">{v}</td></tr>')
        lo, _ = multi["proportion_bounds"]
        parts.append(f"""<h3>NIST SP 800-22 Rev 1a, {multi['sequences']} sequences</h3>
<p>This is the governing SP 800-22 result: the suite partitioned into
{multi['sequences']} sequences of {multi['bits_per_sequence']:,} bits, scored by
the proportion of sequences passing. Tests that emit several p-values per
sequence are scored per sub-test, as the specification intends; the count
column shows how many, and the proportion shown is the worst of them.</p>
<table><tr><th>Test</th><th class="num">sub</th><th class="num">worst</th>
<th class="num">proportion vs bound</th><th>Result</th></tr>
{''.join(rows)}</table>""")
        if multi.get("marginal"):
            parts.append(f"""<div class="note">Marginal:
{_esc(', '.join(multi['marginal']))}. The shortfall is smaller than one
sequence, which is the integer coarseness of the acceptance bound rather than
evidence of a defect.</div>""")
        if multi.get("weak_criterion"):
            parts.append(f"""<div class="note">With only {multi['sequences']}
sequences the proportion criterion is coarse and the p-value uniformity
criterion does not apply, which needs at least 10. Treat this as a weak
pass.</div>""")

    whole_bits = sts_summary.get("bits")
    scope = (f"the first {whole_bits:,} bits" if whole_bits
             and whole_bits < basic.nbits else "the whole capture")
    parts.append(f"<h3>Single-sequence pass over {scope}</h3>")
    parts.append(f"""<p>A second, independent run of the same suite treating
{scope} as one sequence. It is not the conformance result; it is kept because
a single long sequence has more statistical power than any individual sequence
above, so it can surface a small consistent deviation that the per-sequence
view absorbs. Disagreement between the two is expected and is not a
contradiction.</p>""")
    rows = []
    for r in ctx["sts"]:
        if r.skipped:
            v, cls = "not run", "warn"
            detail = r.skipped
        else:
            v = "pass" if r.passed else "fail"
            cls = "pass" if r.passed else "fail"
            detail = (f"{len(r.p_values)} p-values, min "
                      f"{min(r.p_values):.4f}" if len(r.p_values) > 1
                      else "")
        bad = ' class="bad"' if (not r.skipped and not r.passed) else ""
        pv = f"{r.p_value:.4f}" if r.p_values else "&mdash;"
        rows.append(f"<tr{bad}><td>{_esc(r.name)}</td>"
                    f'<td class="num mono">{pv}</td>'
                    f'<td class="{cls}">{v}</td><td>{_esc(detail)}</td></tr>')
    parts.append('<table><tr><th>Test</th><th class="num">p</th><th>Result</th>'
                 f"<th></th></tr>{''.join(rows)}</table>")
    parts.append(_fig(figs.get("sts", ""), "p-values from the single-sequence "
                                           "pass; they should scatter roughly "
                                           "uniformly over (0,1)."))
    if multi and not multi.get("error"):
        whole_failed = set(sts_summary.get("failed", []))
        seq_ok = {r["test"] for r in multi["tests"]
                  if r.get("verdict") in ("pass", "marginal")}
        both = sorted(whole_failed & seq_ok)
        if both:
            parts.append(f"""<div class="note"><b>{_esc(', '.join(both))}</b>
failed the single-sequence pass above but not the {multi['sequences']}-sequence
assessment. Test power grows with sequence length, so a small consistent
deviation can sit inside the threshold on each shorter sequence and clear it
over a longer one. The conformance verdict follows the multi-sequence result;
the disagreement is recorded here because it is the more sensitive of the
two and is worth investigating even when conformance is met.</div>""")

    parts.append("<h3>BSI AIS-31</h3>")
    rows = []
    for grp, label in (("procedure_a", "A"), ("procedure_b", "B")):
        for c in ais[grp]:
            if c["skipped"]:
                v, cls = "not run", "warn"
            else:
                v = "pass" if c["pass"] else "fail"
                cls = "pass" if c["pass"] else "fail"
            bounds = (f"{c['bounds'][0]:g} &ndash; {c['bounds'][1]:g}"
                      if len(c["bounds"]) == 2 else "")
            bad = ' class="bad"' if (not c["skipped"] and not c["pass"]) else ""
            rows.append(f"<tr{bad}><td>{label}</td><td>{_esc(c['name'])}</td>"
                        f'<td class="num mono">{_fmt(c["value"], 3)}</td>'
                        f'<td class="num">{bounds}</td>'
                        f'<td class="{cls}">{v}</td>'
                        f"<td>{_esc(c['skipped'])}</td></tr>")
    parts.append('<table><tr><th>Proc</th><th>Test</th><th class="num">Value</th>'
                 f'<th class="num">Accept</th><th>Result</th><th></th></tr>'
                 f"{''.join(rows)}</table>")
    parts.append(f'<div class="note">{_esc(ais["note"])}</div>')

    parts.append("<h3>FIPS 140-2 section 4.9.1</h3>")
    if fips.get("blocks"):
        per = fips.get("per_test")
        if per:
            rows = "".join(
                f"<tr><td>{_esc(k)}</td>"
                f'<td class="num mono">{d["blocks_failed"]}</td>'
                f'<td class="num mono">{d["expected_failures"]:.1f}</td>'
                f'<td class="num mono">{d["p_value"]:.3f}</td>'
                f'<td class="{"pass" if d["pass"] else "fail"}">'
                f'{"pass" if d["pass"] else "fail"}</td></tr>'
                for k, d in per.items())
            parts.append(f"""<p>Across {fips['blocks']:,} blocks of 20,000 bits.
A few blocks fall outside the intervals by chance on any source, so each
subtest is judged on whether its failure count matches the expected
false-positive rate.</p>
<table><tr><th>Test</th><th class="num">blocks failed</th>
<th class="num">expected</th><th class="num">p</th><th>Result</th></tr>
{rows}</table>""")
        else:
            rows = "".join(
                f"<tr><td>{_esc(k)}</td>"
                f'<td class="num mono">{v} / {fips["blocks"]}</td></tr>'
                for k, v in fips["passed_per_test"].items())
            parts.append(f'<table><tr><th>Test</th>'
                         f'<th class="num">Blocks passed</th></tr>{rows}</table>')
    else:
        parts.append(f"<p>{_esc(fips.get('note', 'not run'))}</p>")
    parts.append(f'<div class="note">{_esc(fips.get("note", ""))}</div>')
    parts.append("</section>")

    ent = ctx.get("ent001")
    if ent:
        rows = "".join(
            f"<tr><td>{_esc(c['requirement'])}</td>"
            f"<td class=\"{'pass' if c['met'] else 'fail'}\">"
            f"{'met' if c['met'] else 'not met'}</td>"
            f"<td class=\"mono\">{_esc(c['actual'])}</td></tr>"
            for c in ent["checks"])
        verdict = ("satisfied by this analysis" if ent["met"]
                   else "NOT satisfied by this analysis")
        cls = "pass" if ent["met"] else "fail"
        parts.append(f"""<section><h2>SEC-TEST-ENT-001 conformance</h2>
<p>EZ-SEC-001 requires the SP 800-22 suite, all fifteen tests, to be run
against at least 100,000,000 bits of TRNG output for each hardware revision.
This analysis is <span class="{cls}"><b>{verdict}</b></span>.</p>
<table><tr><th>Requirement</th><th>Result</th><th>Measured</th></tr>
{rows}</table>
<div class="note">{_esc(ent['note'])}</div></section>""")

    # ---- restart --------------------------------------------------------
    if ctx.get("restart"):
        r = ctx["restart"]
        parts.append('<section><h2>Restart test</h2>')
        parts.append(f"""<p>{r['rows']} restarts of the noise source,
{r['cols']} bits collected after each. The sanity check compares the most
lopsided row or column against what the sequential min-entropy estimate
predicts.</p>
<table>
<tr><th>Quantity</th><th class="num">Value</th></tr>
<tr><td>Largest single-value count in any row or column</td><td class="num mono">{r['max_row_col_count']}</td></tr>
<tr><td>Sanity check upper bound</td><td class="num mono">{r['sanity_bound']}</td></tr>
<tr><td>Sanity check</td><td class="num">{_verdict(r['sanity_pass'])}</td></tr>
<tr><td>H<sub>min</sub> across rows</td><td class="num mono">{r['h_rows']:.4f}</td></tr>
<tr><td>H<sub>min</sub> across columns</td><td class="num mono">{r['h_cols']:.4f}</td></tr>
<tr><td>H<sub>min</sub> sequential</td><td class="num mono">{r['h_original']:.4f}</td></tr>
<tr><td><b>Final H<sub>min</sub></b></td><td class="num mono"><b>{r['h_final']:.4f}</b></td></tr>
</table>""")
        parts.append(_fig(figs.get("restart", ""), "Each row is one restart."))
        parts.append(f'<div class="note caution">{_esc(r["note"])}</div>')
        parts.append("</section>")

    # ---- sampling sweep --------------------------------------------------
    if figs.get("sweep"):
        parts.append('<section><h2>Sampling interval sweep</h2>')
        parts.append("""<p>SAMPLE_CNT1 sets how many system clocks pass between
ring-oscillator samples, and TRNG_CONFIG selects one of four inverter chain
lengths. Shortening the interval raises throughput and lowers the independence
of consecutive samples. The reset value of 65535 gives roughly 2.3 kbit/s at
150 MHz, well below the ~7.5 kbit/s figure in the project documentation, so
production firmware will have to pick a point on this curve deliberately.</p>""")
        parts.append(_fig(figs["sweep"], "Throughput and bias against sampling "
                                         "interval, for each inverter chain length."))
        parts.append("</section>")

    # ---- subsystems ------------------------------------------------------
    parts.append('<section><h2>Board subsystems</h2>')
    if dev:
        parts.append(_subsystem_tables(dev))
    else:
        # An omitted section reads as "nothing to report". For a conformance
        # artifact it has to say "not tested" explicitly, or a reader may
        # assume the board passed checks that were never run.
        parts.append("""<div class="note caution">Subsystem tests were
<b>not run</b> for this capture: no <code>device.json</code> accompanies it.
Pin integrity, clocks, the always-on timer, FRAM and microSD are therefore
<b>unverified here</b> and no conclusion about them should be drawn from this
report.<br><br>
This is the expected result when a capture was collected with
<code>--no-device-tests</code>, which is normal for a long conformance run.
The subsystem evidence belongs in a separate report from a run collected
without that flag.</div>""")
    parts.append("</section>")

    # ---- provenance ------------------------------------------------------
    parts.append('<section><h2>Provenance</h2>')
    if meta.get("key_material") is False:
        parts.append('<div class="note caution">This capture is characterisation '
                     'data and <b>must not be used as key material</b>. It was '
                     'produced by bench firmware that bypasses the TRNG health '
                     'tests, and it has crossed a USB link to this host. '
                     'EZ-SEC-001 SEC-ENTROPY-001 requires key bytes to come '
                     'exclusively from the TRNG on the device, and SEC-DIST-001 '
                     'prohibits electronic transmission of key material.</div>')
    uuid = meta.get("device_uuid") or meta.get("board_id")
    if uuid:
        parts.append(f"""<table>
<tr><th>Identifier</th><th>Value</th><th>Notes</th></tr>
<tr><td>Device UUID</td><td class="mono">{_esc(uuid)}</td>
    <td>RP2350 OTP CHIPID0..3, a 64-bit identifier programmed at manufacture.
    Read through the ROM get_sys_info call, so it identifies the die and not
    the flash part. The datasheet treats it as a public device ID.</td></tr>
</table>""")
    parts.append("""<p>The block below is telemetry the device recorded
alongside the capture itself: die temperature, system clock, TRNG
configuration and health-test counters. It travels inside every capture and is
present whether or not the subsystem tests were run.</p>""")
    parts.append("<p>Everything above derives from the capture described here. "
                 "Re-running the analysis on the archived <code>.bin</code> "
                 "reproduces this report exactly.</p>")
    parts.append(f"<pre>{_esc(json.dumps(meta, indent=2))}</pre>")
    parts.append("""<h3>What this report does not establish</h3>
<ul>
<li>The estimators here are an independent reimplementation of SP 800-90B, not
a validated one. A certification claim needs NIST's own EntropyAssessment tool
against the same archived capture.</li>
<li>Restarts are triggered by TRNG_SW_RESET rather than by power-cycling the
noise source, which is weaker than the specification intends.</li>
<li>Entropy was measured at one supply voltage and one die temperature. A
source that is healthy at room temperature can degrade at the edges of its
range; characterise across the intended operating envelope before trusting it
with key material.</li>
<li>The TRNG is closed Arm IP. No amount of output testing can rule out a
construction that is deterministic in a way the tests cannot see. This is the
same limitation the project documentation notes for V0.</li>
</ul>""")
    parts.append("</section>")

    parts.append(f"""<footer>Generated {_esc(ctx.get('generated', ''))} by
einszeit-hwtest. Capture CRC-32 verified end to end from device to this
report.</footer></div></body></html>""")

    return "".join(parts)


def _subsystem_tables(dev: dict) -> str:
    out = []

    pins = dev.get("pins")
    if pins:
        row_html = []
        for pin in pins.get("pins", []):
            good = pin["pass"]
            cls = "pass" if good else "fail"
            tr = ' class="bad"' if not good else ""
            row_html.append(
                f"<tr{tr}>"
                f'<td class="mono">GPIO{pin["gpio"]}</td><td>{_esc(pin["name"])}</td>'
                f'<td class="num mono">{pin["pullup"]}</td>'
                f'<td class="num mono">{pin["pulldown"]}</td>'
                f'<td class="{cls}">{"pass" if good else "fail"}</td></tr>')
        rows = "".join(row_html)
        out.append("<h3>Pin integrity</h3>")
        out.append("<p>Each pin read with the internal pull-up then the "
                   "internal pull-down engaged. A pin with an external pull-up "
                   "reads high in both states, because 10K or 20K overwhelms "
                   "the RP2350's ~55K internal pull-down. That is how the "
                   "external resistors are confirmed present.</p>")
        out.append('<table><tr><th>Pin</th><th>Net</th><th class="num">pull-up</th>'
                   f'<th class="num">pull-down</th><th>Result</th></tr>{rows}</table>')

    clk = dev.get("clock")
    if clk:
        m = clk.get("meas", {})
        out.append("<h3>Clocks</h3>")
        out.append(f"""<table>
<tr><th>Clock</th><th class="num">Configured</th><th class="num">Measured</th></tr>
<tr><td>clk_sys</td><td class="num mono">{clk.get('clk_sys_hz', 0) / 1e6:.3f} MHz</td>
    <td class="num mono">{m.get('clk_sys_khz', 0) / 1e3:.3f} MHz</td></tr>
<tr><td>clk_peri</td><td class="num mono">{clk.get('clk_peri_hz', 0) / 1e6:.3f} MHz</td>
    <td class="num mono">{m.get('clk_peri_khz', 0) / 1e3:.3f} MHz</td></tr>
<tr><td>clk_usb</td><td class="num mono">{clk.get('clk_usb_hz', 0) / 1e6:.3f} MHz</td>
    <td class="num mono">{m.get('clk_usb_khz', 0) / 1e3:.3f} MHz</td></tr>
<tr><td>XOSC</td><td class="num mono">&mdash;</td>
    <td class="num mono">{m.get('xosc_khz', 0) / 1e3:.3f} MHz</td></tr>
<tr><td>ROSC</td><td class="num mono">&mdash;</td>
    <td class="num mono">{m.get('rosc_khz', 0) / 1e3:.3f} MHz</td></tr>
<tr><td>LPOSC</td><td class="num mono">&mdash;</td>
    <td class="num mono">{m.get('lposc_khz', 0)} kHz</td></tr>
<tr><td>XOSC stable</td><td class="num">&mdash;</td>
    <td class="num">{_verdict(clk.get('xosc_stable', False), 'yes', 'NO')}</td></tr>
</table>""")

    aon = dev.get("aon")
    if aon:
        out.append("<h3>Always-on timer</h3>")
        out.append(f"""<table>
<tr><td>Tick source</td><td>{_esc(aon.get('source', ''))}</td></tr>
<tr><td>Running</td><td>{_verdict(aon.get('running', False), 'yes', 'no')}</td></tr>
<tr><td>Measured error</td><td class="num mono">{_fmt(aon.get('ppm'), 1)} ppm
    over {aon.get('window_ms', 0)} ms</td></tr>
</table>
<p>The RP2350 has no RTC block; this is the POWMAN always-on timer. When its
tick comes from the same 12&nbsp;MHz crystal as the system timer, the error
above measures the divider and not the crystal, so it will read near zero
regardless of crystal accuracy. Only a comparison against an external
reference characterises the crystal itself.</p>""")

    fram = dev.get("fram")
    if fram:
        out.append("<h3>FRAM</h3>")
        rows = "".join(f"<tr><td>{_esc(k)}</td><td class=\"mono\">{_esc(v)}</td></tr>"
                       for k, v in fram.items() if not isinstance(v, (dict, list)))
        out.append(f"<table>{rows}</table>")

    sd = dev.get("sd")
    if sd:
        out.append("<h3>microSD</h3>")
        # CMD0 returning 0xFF means nothing answered on the bus at all, which
        # is what an empty socket looks like. Reporting that as a subsystem
        # failure would be a false negative in a conformance record.
        if (not sd.get("ok", True) and sd.get("last_r1") == 255
                and sd.get("step", 99) <= 3):
            out.append("""<div class="note">No card responded to CMD0. With no
card fitted this is the expected result and says nothing about the microSD
interface; the socket, level shifting and SPI wiring remain untested. Fit a
card and re-run to exercise them.</div>""")
        rows = "".join(f"<tr><td>{_esc(k)}</td><td class=\"mono\">{_esc(v)}</td></tr>"
                       for k, v in sd.items() if not isinstance(v, (dict, list)))
        out.append(f"<table>{rows}</table>")

    return "".join(out)


def write(path, ctx: dict) -> None:
    import pathlib

    p = pathlib.Path(path)
    p.write_text(build(ctx), encoding="utf-8")


def timestamp() -> str:
    return datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
