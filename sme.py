"""Assisted risk assessment for small and medium enterprises (PLAN.md section 10, releases P2a/P2b).

    python sme.py init <workspace> --company "Tên công ty"     # create an isolated company workspace
    python sme.py run <workspace> [--as-of YYYY-MM-DD] [--baseline <workspace>/runs/<date>/state.json]
    python sme.py --check                                     # self-check

The IT person fills answers.csv (Excel, saved as CSV UTF-8) by interviewing the director and checking
configurations. Everything scenario-specific lives in the versioned library (library/sme, SPEC 8):
scenarios, answer mappings (ANS), decision tables (DT), control-status rules and default effects.
This file is the generic engine that applies them, runs risk.py and writes the owner report.
Ratings from self-reported answers stay judgments; the tool never accepts a risk.
"""
import csv
import datetime
import html
import io
import json
import math
import shutil
import sys
import tempfile
from pathlib import Path

import risk

ROOT = Path(__file__).parent
LIB = ROOT / 'library' / 'sme'
ANS_VERSION = 'ANS-0.2'
VL, L, M, H, VH = risk.LEVELS
UNK = risk.UNK
VI_LEVEL = {VL: 'Rất thấp', L: 'Thấp', M: 'Trung bình', H: 'Cao', VH: 'Rất cao', UNK: 'Chưa xác định', '': '—'}
VI_EFFORT = {'Low': 'Thấp', 'Medium': 'Vừa', 'High': 'Cao'}
VI_STATUS = {'implemented_assessed_effective': 'đã làm và đã kiểm chứng', 'implemented': 'đã làm (chưa kiểm chứng)',
             'partial': 'làm một phần', 'planned_compensated': 'mới có kế hoạch', 'absent_unplanned': 'chưa có', UNK: 'chưa rõ'}
DUE_DAYS = {'Low': 14, 'Medium': 30, 'High': 60}           # suggested deadline by effort tier [DA]
SOURCES = {'observed', 'attested', 'forecast', 'unknown'}
ANSWER_FIELDS = ['question_id', 'path', 'text_vi', 'options', 'answer', 'source', 'evidence_ref', 'answered_by',
                 'answered_on', 'note']
FINDING_FIELDS = ['finding_id', 'cve_id', 'component_id', 'applicability', 'remediation_state', 'first_confirmed_on',
                  'evidence_ref', 'exception_approved_by', 'exception_expires_on']
LIB_FILES = ('questions', 'scenarios', 'mappings', 'decision_tables', 'controls_map', 'effects_lib', 'packages')
SYSTEM = 'SYS-SME'
CONSEQUENCES = ['negligible', 'limited', 'serious', 'severe']
DEFAULT_IMPACT = (('info_class', 'public'), ('records_disclosed', '0'), ('integrity_consequence', 'negligible'),
                  ('corrected_before_use', 'no'), ('outage_hours', '0'), ('in_critical_window', 'no'),
                  ('multiple_severe_documented', 'no'))


# ---------------------------------------------------------------- library and answers
def library_dir(ws):
    """The workspace's pinned copy of the library (created by init); the repo copy only if none exists."""
    return ws / 'library' if (ws / 'library' / 'scenarios.csv').exists() else LIB


def read_csv(path):
    """Read a CSV saved by Excel: UTF-8 with or without BOM, comma or semicolon delimited."""
    with open(path, encoding='utf-8-sig', newline='') as f:     # newline='' keeps line breaks inside quoted cells
        text = f.read()
    first = text.splitlines()[0] if text else ''
    delim = ';' if first.count(';') > first.count(',') else ','
    return list(csv.DictReader(io.StringIO(text, newline=''), delimiter=delim))


def write_csv(path, rows, fields, bom=False):
    with open(path, 'w', encoding='utf-8-sig' if bom else 'utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator='\n')
        w.writeheader()
        w.writerows(rows)


def load_library(ws):
    d = library_dir(ws)
    return {n: read_csv(d / f'{n}.csv') for n in LIB_FILES}


def options(q):
    return {} if q['options'] in ('text', 'number') else dict(o.split('=', 1) for o in q['options'].split('|'))


def match(when, A, unknown_matches=False):
    """'*' or 'Q=a,b&Q2=c'. With unknown_matches=True an unknown answer satisfies its clause (applicability)."""
    if when.strip() in ('', '*'):
        return True
    for part in when.split('&'):
        q, vals = part.split('=', 1)
        v = A(q.strip())
        if not (unknown_matches and v == UNK) and v not in [x.strip() for x in vals.split(',')]:
            return False
    return True


def first_match(rows, A, key):
    for r in sorted(rows, key=lambda r: int(r['order'])):
        if match(r['when'], A):
            return r[key]
    return UNK


def load_answers(ws, lib):
    """-> ({question_id: answer dict}, errors). Blank answers become 'unknown'."""
    questions = {q['question_id']: q for q in lib['questions']}
    answers, errors = {}, []
    for a in read_csv(ws / 'answers.csv'):
        qid = a.get('question_id', '').strip()
        if qid not in questions:
            errors.append(f'answers.csv: unknown question_id {qid!r}')
            continue
        q, ans = questions[qid], (a.get('answer') or '').strip()
        src = (a.get('source') or '').strip() or ('unknown' if not ans else 'attested')
        if not ans:
            ans, src = UNK, 'unknown'
        opts = options(q)
        if opts and ans not in opts:
            errors.append(f"{qid}: answer {ans!r} is not one of {', '.join(opts)}")
        if q['options'] == 'number' and ans != UNK:
            try:
                number = float(ans.replace(' ', ''))
                if not math.isfinite(number) or number < 0:
                    raise ValueError
                ans = ans.replace(' ', '')
            except ValueError:
                errors.append(f'{qid}: answer {ans!r} must be a number >= 0 (no thousands separators)')
        if src not in SOURCES:
            errors.append(f"{qid}: source {src!r} is not one of {', '.join(sorted(SOURCES))}")
        if src == 'observed' and not (a.get('evidence_ref') or '').strip():
            errors.append(f'{qid}: source observed needs evidence_ref (what was looked at)')
        day = (a.get('answered_on') or '').strip()
        if day:
            try:
                datetime.date.fromisoformat(day)
            except ValueError:
                errors.append(f'{qid}: answered_on {day!r} is not YYYY-MM-DD')
        answers[qid] = {'value': ans, 'source': src, 'evidence_ref': (a.get('evidence_ref') or '').strip(),
                        'by': (a.get('answered_by') or '').strip(), 'on': day, 'text': q['text_vi']}
    for qid, q in questions.items():
        answers.setdefault(qid, {'value': UNK, 'source': 'unknown', 'evidence_ref': '', 'by': '', 'on': '', 'text': q['text_vi']})
    return answers, errors


def tolerance_error(answers, qids):
    """Error text when the owner's thresholds (qids[1:4]) are known but do not increase, else None."""
    vals = [answers[q]['value'] for q in qids[1:4]]
    if UNK in vals:
        return None
    try:
        t1, t2, t3 = (float(v) for v in vals)
    except ValueError:
        return None                                  # not a number: already reported by load_answers
    if t1 < t2 < t3:
        return None
    return f'tolerances must increase: {qids[1]} < {qids[2]} < {qids[3]} (got {t1:g}, {t2:g}, {t3:g})'


def tol_consequence(answers, qids):
    """BUS-TOL: estimated loss against the owner's thresholds TOL-01 < TOL-02 < TOL-03 -> consequence class."""
    vals = [answers[q]['value'] for q in qids]
    if UNK in vals:
        return UNK
    problem = tolerance_error(answers, qids)
    if problem:
        raise SystemExit(problem)
    loss, t1, t2, t3 = (float(v) for v in vals)
    return CONSEQUENCES[0] if loss < t1 else CONSEQUENCES[1] if loss < t2 else CONSEQUENCES[2] if loss < t3 else CONSEQUENCES[3]


# ---------------------------------------------------------------- answers -> model (SPEC 8)
def compile_model(ws, as_of, lib):
    """Answers -> complete model data set (SPEC 6) in ws/model; returns (answers, profile, applicable, excluded)."""
    answers, errors = load_answers(ws, lib)
    # reported together with the other answer errors, once, instead of stopping at the first scenario that uses them
    tol = {tolerance_error(answers, [q for q in m['questions'].split(';') if q])
           for m in lib['mappings'] if m['map'] == 'TOL'}
    errors += sorted(t for t in tol if t)
    if errors:
        raise SystemExit('answers.csv has errors:\n  ' + '\n  '.join(errors))
    A = lambda q: answers[q]['value'] if q in answers else UNK
    applicable = [s for s in lib['scenarios'] if match(s['applies_if'], A, unknown_matches=True)]
    excluded = [s for s in lib['scenarios'] if s not in applicable]
    ids = {s['risk_id'] for s in applicable}
    inputs = []

    def add(rid, attr, value, qids, rule, default=False):
        used = [answers[q] for q in qids]
        observed = bool(used) and all(u['source'] == 'observed' and u['evidence_ref'] for u in used)
        conf = 'High' if observed else min(({'attested': 'Medium', 'observed': 'Medium'}.get(u['source'], 'Low')
                                            for u in used), key=['Low', 'Medium', 'High'].index, default='Medium')
        why = '; '.join(f"{q}={answers[q]['value']} ({answers[q]['source']}{', ' + answers[q]['by'] if answers[q]['by'] else ''})"
                        for q in qids)
        mode = 'evidence' if observed and not rule.startswith('DT') and not default else 'judgment'
        inputs.append({'subject_id': rid, 'attribute': attr, 'value': value, 'mode': mode,
                       'evidence_ref': '; '.join(u['evidence_ref'] for u in used) if mode == 'evidence' else '',
                       'rationale': '' if mode == 'evidence' else f'{rule} {ANS_VERSION}: {why or "library default"}',
                       'confidence': conf if not default else 'Medium', 'assessor': 'sme.py',
                       'observed_on': max([u['on'] for u in used if u['on']] or [as_of.isoformat()])})

    dts = {}
    for r in lib['decision_tables']:
        dts.setdefault(r['dt_id'], []).append(r)
    for m in lib['mappings']:
        if m['risk_id'] not in ids:
            continue
        qids = [q for q in m['questions'].split(';') if q]
        if m['map'].startswith('DT:'):
            value = first_match(dts[m['map'][3:]], A, 'result')
        elif m['map'] == 'TOL':
            value = tol_consequence(answers, qids)
        elif m['map']:
            value = dict(p.split('=', 1) for p in m['map'].split('|')).get(A(qids[0]), UNK)
        else:
            value = m['default_value']
        add(m['risk_id'], m['attribute'], value, qids, m['rule_id'], default=not qids)
    # optional CVE findings reported by the IT person for self-managed software (KEV onboarding, SPEC 8.6)
    if (ws / 'findings.csv').exists():
        for f in read_csv(ws / 'findings.csv'):
            if not (f.get('finding_id') or '').strip():
                continue
            ref = (f.get('evidence_ref') or '').strip()
            for attr in ('cve_id', 'component_id', 'applicability', 'remediation_state', 'first_confirmed_on',
                         'exception_approved_by', 'exception_expires_on'):
                if (f.get(attr) or '').strip():
                    inputs.append({'subject_id': f['finding_id'].strip(), 'attribute': attr, 'value': f[attr].strip(),
                                   'mode': 'evidence' if ref else 'judgment', 'evidence_ref': ref,
                                   'rationale': '' if ref else 'reported in findings.csv without evidence',
                                   'confidence': 'High' if ref else 'Low', 'assessor': 'sme.py', 'observed_on': as_of.isoformat()})
    present = {(i['subject_id'], i['attribute']) for i in inputs}
    for s in applicable:
        for attr, value in DEFAULT_IMPACT:
            if (s['risk_id'], attr) not in present:
                add(s['risk_id'], attr, value, [], 'SME-LIB default', default=True)

    rules = {}
    for r in lib['controls_map']:
        rules.setdefault(r['package_id'], []).append(r)
    controls = []
    for p in lib['packages']:
        rows = rules.get(p['package_id'], [])
        status = first_match(rows, A, 'status') if rows else UNK
        qids = [q for q in (rows[0]['questions'] if rows else '').split(';') if q]
        used = [answers[q] for q in qids]
        day = max([u['on'] for u in used if u['on']] or [''])
        if status == 'implemented_assessed_effective' and not (used and all(u['source'] == 'observed' and u['evidence_ref']
                                                                            for u in used) and day):
            status = 'implemented'          # "effective" needs an observed, dated check
        controls.append({'scope_id': SYSTEM, 'package_id': p['package_id'], 'status': status,
                         'evidence_ref': '; '.join(u['evidence_ref'] for u in used if u['evidence_ref']) or 'answers.csv',
                         'verified_on': day if status == 'implemented_assessed_effective' else ''})
    profile = {'it': A('PRO-01'), 'finance': A('PRO-02'), 'director': A('PRO-03')}
    effort = {p['package_id']: p['effort_tier'] for p in lib['packages']}
    packages = [{'package_id': p['package_id'], 'name': p['name_vi'], 'control_ids': p['cis_ref'], 'effort_tier': p['effort_tier'],
                 'requires': '', 'owner': p['owner_role'], 'due_date': '', 'status': 'proposed',
                 'verification_ref': p['verification_vi']} for p in lib['packages']]
    seen, assets = set(), []
    for s in applicable:
        if s['asset_id'] not in seen:
            seen.add(s['asset_id'])
            assets.append({'asset_id': s['asset_id'], 'name': s['asset_name_vi'], 'kind': 'service', 'component_ids': '',
                           'owner': profile['director'], 'confidentiality': UNK, 'integrity': UNK, 'availability': UNK,
                           'rationale': 'SME scope', 'asset_class': s['asset_class'], 'system_id': SYSTEM, 'vendor': '',
                           'product': '', 'version': '', 'exposure': s['exposure']})
    templates = [{'template_id': s['template_id'], 'asset_classes': s['asset_class'], 'scope': 'asset', 'threat_profile_id': '',
                  'source_type': s['source_type'], 'event': s['name_vi'], 'init_rule': s['init_rule'], 'adverse_rule': 'DT',
                  'impact_rule': 'IMP-01'} for s in applicable]
    register = []
    for s in applicable:
        pk = s['packages'].split(';')
        register.append({'risk_id': s['risk_id'], 'template_id': s['template_id'], 'family_id': s['family_id'],
                         'asset_id': s['asset_id'], 'vulnerability_condition': '', 'existing_controls': 'see controls.csv',
                         'applicable_packages': s['packages'], 'treatment_option': 'mitigate', 'treatment_packages': s['packages'],
                         'risk_owner': profile['director'],
                         'due_date': (as_of + datetime.timedelta(days=max(DUE_DAYS[effort[p]] for p in pk))).isoformat(),
                         'decision_ref': 'chưa quyết định (giám đốc)', 'evidence_ref': 'answers.csv', 'status': 'proposed',
                         'last_reviewed': as_of.isoformat(), 'next_review': (as_of + datetime.timedelta(days=90)).isoformat()})
    d = {'assets': assets, 'templates': templates, 'inputs': inputs, 'controls': controls, 'packages': packages,
         'effects': [], 'risk_register': register}
    d['effects'] = default_effects(d, lib)
    model = ws / 'model'
    model.mkdir(exist_ok=True)
    for name, rows in d.items():
        fields = list(rows[0]) if rows else ['risk_id', 'package_ids', 'initiation', 'adverse', 'impact', 'basis_ref', 'basis_hash']
        write_csv(model / f'{name}.csv', rows, fields)
    if (ws / 'snapshots' / 'manifest.csv').exists():          # optional KEV/EPSS snapshots of this workspace
        shutil.copytree(ws / 'snapshots', model / 'snapshots', dirs_exist_ok=True)
    return answers, profile, applicable, excluded


def apply_effect(kind, ini, adv, imp):
    """Apply one or more comma-separated effect kinds (e.g. 'adv-1,impact-1')."""
    if ',' in kind:
        for k in kind.split(','):
            ini, adv, imp = apply_effect(k.strip(), ini, adv, imp)
        return ini, adv, imp
    shift = lambda lv, n: risk.LEVELS[max(0, min(4, risk.LEVELS.index(lv) + n))]
    if kind == 'adv=L':
        adv = L
    elif kind == 'adv<=M':
        adv = min(adv, M, key=risk.LEVELS.index)
    elif kind == 'adv-1':
        adv = max(shift(adv, -1), L, key=risk.LEVELS.index)        # EFF-01: projected G-4 never Very Low
    elif kind == 'init-1':
        ini = shift(ini, -1)
    elif kind == 'impact-1':
        imp = shift(imp, -1)
    elif kind != 'none':
        raise SystemExit(f'effects_lib: unknown effect kind {kind!r}')
    return ini, adv, imp


IN_PLACE = {'implemented', 'implemented_assessed_effective'}


def default_effects(d, lib):
    """Library default effects for the current ratings, stamped with the current basis (SPEC 8.4).
    A package that is already in place (implemented, verified or not) projects no further change: the answers
    behind the current rating already describe it, so applying its library effect again would count it twice.
    Its remaining work is verification, which never changes a projected rating."""
    rows, _ = risk.evaluate(d)
    kinds = {(e['risk_id'], frozenset(e['packages'].split(';'))): e['kind'] for e in lib['effects_lib']}
    in_place = {c['package_id'] for c in d['controls'] if c['status'] in IN_PLACE}
    out = []
    for r in rows:
        if UNK in (r['initiation'], r['adverse'], r['impact']):
            continue
        pkgs = [p for p in r['applicable_packages'].split(';') if p]
        singles = []
        for p in pkgs:
            kind = 'none' if p in in_place else kinds.get((r['risk_id'], frozenset([p])), 'none')
            s = apply_effect(kind, r['initiation'], r['adverse'], r['impact'])
            singles.append(s)
            note = ' (already implemented: no further projected effect)' if p in in_place else ''
            out.append({'risk_id': r['risk_id'], 'package_ids': p, 'initiation': s[0], 'adverse': s[1], 'impact': s[2],
                        'basis_ref': f'SME-LIB default: {kind}{note}', 'basis_hash': r['basis']})
        if len(pkgs) > 1:
            # a bundle-level library effect cannot be split per package, so it is used only while no package of the
            # bundle is in place; otherwise the bundle projects the best of its singles (conservative)
            full = kinds.get((r['risk_id'], frozenset(pkgs)))
            if full and in_place & set(pkgs):
                full, label = None, 'best of singles (some packages already implemented)'
            else:
                label = full or 'best of singles'
            best = (apply_effect(full, r['initiation'], r['adverse'], r['impact']) if full else
                    [min((s[k] for s in singles), key=risk.LEVELS.index) for k in range(3)])
            out.append({'risk_id': r['risk_id'], 'package_ids': ';'.join(sorted(pkgs)), 'initiation': best[0], 'adverse': best[1],
                        'impact': best[2], 'basis_ref': f'SME-LIB default: bundle {label}', 'basis_hash': r['basis']})
    return out


# ---------------------------------------------------------------- owner report
def top_actions(res, answers, profile, as_of, lib, n=3):
    """Obligations first, then packages with a supported threshold crossing, then foundational gaps
    (unverified packages that would improve a Moderate+ or unknown risk), then evidence to collect."""
    pk = {p['package_id']: p for p in res['data']['packages']}
    rows = {r['risk_id']: r for r in res['rows']}
    name = {s['risk_id']: s['name_vi'] for s in lib['scenarios']}
    status = {c['package_id']: c['status'] for c in res['data']['controls']}
    roles = {'it': 'Người phụ trách IT', 'finance': 'Phụ trách tài chính'}
    owner = lambda role: profile.get(role) if profile.get(role) not in (None, '', UNK) else roles.get(role, 'Giám đốc')
    acts, used = [], set()

    def add(pkgs, reason):
        key = tuple(sorted(pkgs))
        if key in used or len(acts) >= n:
            return
        used.add(key)
        tier = max((pk[p]['effort_tier'] for p in pkgs), key=risk.EFFORT.index)
        acts.append({'title': ' + '.join(pk[p]['name'] for p in pkgs), 'reason': reason,
                     'owner': ', '.join(sorted({owner(pk[p]['owner']) for p in pkgs})),
                     'due': (as_of + datetime.timedelta(days=DUE_DAYS[tier])).isoformat(),
                     'effort': VI_EFFORT[tier] if len(pkgs) == 1 else 'chưa ước tính (nhiều gói)',
                     'cost': 'chưa ước tính', 'proof': ' '.join(pk[p]['verification_ref'] for p in pkgs)})
    for o in res['obligations']:
        if (o['state'] == 'open' or o['state'].startswith('overdue')) and len(acts) < n:
            acts.append({'title': f"Khắc phục {o['cve_id']} trên {o['component_id']}",
                         'reason': f"Lỗ hổng đã bị khai thác thực tế (CISA KEV); trạng thái: {o['state']}",
                         'owner': owner('it'), 'due': str(o['due']), 'effort': '—', 'cost': 'chưa ước tính',
                         'proof': 'Quét lại cho thấy đã vá'})
            used.add(('KEV', o['finding_id']))
    fam_risk = {}
    for r in res['rows']:
        if r['family_id'] not in fam_risk or (r['risk'] != UNK and risk.LEVELS.index(r['risk']) >
                                              risk.LEVELS.index(fam_risk[r['family_id']]['risk'] if fam_risk[r['family_id']]['risk'] != UNK else VL)):
            fam_risk[r['family_id']] = r
    front, dominated, bundles, _, _ = res['ranking']
    covered = set()
    for c in front + dominated + bundles:
        fams = c['below_high'] + [f for f in c['below_moderate'] if f not in c['below_high']]
        if set(fams) <= covered and any(set(u) < set(c['packages']) for u in used):
            continue        # a superset of an already chosen action that crosses nothing new adds no benefit
        covered |= set(fams)
        why = '; '.join(f"giảm rủi ro “{name[fam_risk[f]['risk_id']]}” từ {VI_LEVEL[fam_risk[f]['risk']]} "
                        f"xuống dưới mức {'Cao' if f in c['below_high'] else 'Trung bình'} (dự kiến)" for f in fams)
        add(c['packages'], why)
    eff = {(e['risk_id'], e['package_ids']): e for e in res['data']['effects']}
    gaps = []
    for p in pk:
        if status.get(p) == 'implemented_assessed_effective':
            continue
        hits = []
        for r in rows.values():
            e = eff.get((r['risk_id'], p))
            if p in r['applicable_packages'].split(';') and (r['risk'] == UNK or risk.LEVELS.index(r['risk']) >= 2):
                improves = e is not None and r['risk'] != UNK and any(
                    risk.LEVELS.index(e[k]) < risk.LEVELS.index(r[k]) for k in ('initiation', 'adverse', 'impact'))
                hits.append((improves, 5 if r['risk'] == UNK else risk.LEVELS.index(r['risk']), r['risk_id']))
        if hits:
            best = max(hits)
            gaps.append((not best[0], -best[1], risk.EFFORT.index(pk[p]['effort_tier']), p, best[2]))
    for _, _, _, p, rid in sorted(gaps):
        add([p], f"Biện pháp nền tảng chưa được kiểm chứng; liên quan “{name[rid]}” (hiện: {VI_LEVEL[rows[rid]['risk']]})")
    for qid, a in answers.items():
        if len(acts) >= n:
            break
        if a['value'] == UNK and not qid.startswith('PRO'):
            acts.append({'title': f'Trả lời/kiểm chứng câu hỏi {qid}', 'reason': a['text'], 'owner': owner('it'),
                         'due': (as_of + datetime.timedelta(days=7)).isoformat(), 'effort': 'Thấp', 'cost': '—',
                         'proof': 'Câu trả lời có nguồn (observed kèm evidence_ref)'})
    return acts[:n]


def vi_changes(prev, cur, lib):
    out = []
    name = {s['risk_id']: s['name_vi'] for s in lib['scenarios']}
    names = {p['package_id']: p['name_vi'] for p in lib['packages']}
    for rid, b in cur['risks'].items():
        a = prev['risks'].get(rid)
        if a is None:
            out.append(f"Tình huống mới được đánh giá: “{name.get(rid, rid)}” ({VI_LEVEL[b['risk']]})")
        elif a['risk'] != b['risk']:
            out.append(f"Rủi ro “{name.get(rid, rid)}”: {VI_LEVEL[a['risk']]} → {VI_LEVEL[b['risk']]}")
    for k, s in cur['controls'].items():
        if prev['controls'].get(k) != s:
            p = k.split('@')[0]
            out.append(f"Biện pháp “{names.get(p, p)}”: {VI_STATUS.get(prev['controls'].get(k), '—')} → {VI_STATUS.get(s, s)}")
    return out


def read_version(ws=None):
    d = library_dir(ws) if ws else LIB
    return (d / 'VERSION').read_text(encoding='utf-8').strip() if (d / 'VERSION').exists() else 'SME-LIB'


def render_html(res, answers, company, as_of, acts, lib, excluded, version):
    e = html.escape
    name = {s['risk_id']: s['name_vi'] for s in lib['scenarios']}
    order = [s['risk_id'] for s in lib['scenarios']]
    attr_q = {(m['risk_id'], m['attribute']): [q for q in m['questions'].split(';') if q] for m in lib['mappings']}
    rows = sorted(res['rows'], key=lambda r: order.index(r['risk_id']))
    unknown_q = [(q, a['text']) for q, a in answers.items() if a['value'] == UNK and not q.startswith('PRO')]
    check_q = []
    for subj, inp, _, _ in res['queue']:
        for q in attr_q.get((subj, inp.split(' = ')[0]), []):
            if (q, answers[q]['text']) not in check_q + unknown_q:
                check_q.append((q, answers[q]['text']))
    css = ('body{font-family:Segoe UI,Arial,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#222}'
           'h1{font-size:1.5em}h2{border-bottom:2px solid #ddd;padding-bottom:4px;margin-top:28px}'
           'table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:6px;vertical-align:top;text-align:left}'
           '.act{border:1px solid #bbb;border-radius:6px;padding:10px 14px;margin:10px 0}.lv{font-weight:bold}'
           '.note{color:#555;font-size:.9em}')
    h = [f'<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>Báo cáo rủi ro - {e(company)}</title>'
         f'<style>{css}</style></head><body>', f'<h1>Báo cáo rủi ro an toàn thông tin: {e(company)}</h1>',
         f'<p class="note">Ngày đánh giá {as_of} · Phạm vi: {len(rows)} tình huống áp dụng cho công ty · Thư viện {e(version)} · '
         f"{ANS_VERSION} · {risk.SPEC_VERSION} · mã kiểm tra {risk.state_sha(res['state'])[:12]}</p>", '<h2>3 việc nên làm tiếp</h2>']
    for i, a in enumerate(acts, 1):
        h.append(f'<div class="act"><b>{i}. {e(a["title"])}</b><br>Lý do: {e(a["reason"])}<br>'
                 f'Người phụ trách: {e(a["owner"])} · Hạn đề xuất: {e(a["due"])} · Công sức: {e(a["effort"])} · '
                 f'Chi phí: {e(a["cost"])}<br>Cách chứng minh đã làm xong: {e(a["proof"])}</div>')
    if not acts:
        h.append('<p>Không có việc nào được đề xuất.</p>')
    h += ['<h2>Mức rủi ro hiện tại</h2><table><tr><th>Tình huống</th><th>Mức hiện tại</th>'
          '<th>Nếu làm các biện pháp đề xuất (dự kiến)</th><th>Cần quyết định của</th></tr>']
    who = {'owner': 'Người phụ trách', 'delegated': 'Giám đốc (ủy quyền)', 'senior': 'Giám đốc', UNK: 'Chưa xác định'}
    for r in rows:
        cls = risk.decision_class(r['risk'], r['impact']).split('+')[0] if r['risk'] != UNK else UNK
        res_txt = VI_LEVEL[r['res_risk']] if r['res_risk'] else ('cần rà soát lại' if r.get('res_status') == 'needs_review'
                                                                 else 'chưa xác định')
        if r.get('res_status') == 'verified':
            res_txt += ' (đã kiểm chứng)'
        h.append(f"<tr><td>{e(name[r['risk_id']])}</td><td class='lv'>{VI_LEVEL[r['risk']]}</td><td>{e(res_txt)}</td>"
                 f"<td>{who.get(cls, cls)}</td></tr>")
    h.append('</table><p class="note">Mức rủi ro được tính theo NIST SP 800-30 Rev.1 (bảng G-5, I-2) từ câu trả lời phỏng vấn. '
             'Câu trả lời tự khai là phán đoán, không phải bằng chứng; mức “dự kiến” chỉ đạt được khi biện pháp được kiểm chứng.</p>')
    if excluded:
        h.append('<p class="note">Không áp dụng theo câu trả lời: ' + '; '.join(e(s['name_vi']) for s in excluded) + '.</p>')
    if res.get('baseline'):
        ch = vi_changes(res['baseline'], res['state'], lib)
        h.append(f"<h2>Thay đổi so với lần đánh giá {e(res['baseline']['as_of'])}</h2><ul>" +
                 ''.join(f'<li>{e(c)}</li>' for c in ch) + ('' if ch else '<li>Không có thay đổi</li>') + '</ul>')
    h.append('<h2>Những điều chưa biết hoặc cần kiểm chứng</h2>')
    if unknown_q or check_q:
        h.append('<ul>' + ''.join(f'<li><b>{q}</b> (chưa có câu trả lời): {e(t)}</li>' for q, t in unknown_q) +
                 ''.join(f'<li><b>{q}</b> (nếu câu trả lời khác đi thì người cần quyết định sẽ khác): {e(t)}</li>'
                         for q, t in check_q) + '</ul>')
    else:
        h.append('<p>Không có.</p>')
    h += ['<h2>Giới hạn</h2><ul><li>Đây là đánh giá có hỗ trợ, không phải chứng nhận tuân thủ.</li>'
          '<li>Mã safeguard CIS của các biện pháp chưa được đối chiếu với tài liệu CIS v8.1.</li>'
          '<li>Chi phí chỉ ghi khi có báo giá; nếu không: “chưa ước tính”.</li>'
          '<li>Chi tiết kỹ thuật và chuỗi giải thích: trace.md, action_report.md trong cùng thư mục.</li></ul></body></html>']
    return '\n'.join(h) + '\n'


# ---------------------------------------------------------------- commands
def init(ws, company):
    ws = Path(ws)
    if (ws / 'answers.csv').exists():
        raise SystemExit(f'{ws} already contains answers.csv; not overwriting')
    ws.mkdir(parents=True, exist_ok=True)
    shutil.copytree(LIB, ws / 'library', dirs_exist_ok=True)       # pin the library version used
    (ws / 'evidence').mkdir(exist_ok=True)
    (ws / 'company.json').write_text(json.dumps({'company': company, 'library': read_version()}, ensure_ascii=False, indent=1),
                                     encoding='utf-8')
    rows = [{**{k: q[k] for k in ('question_id', 'path', 'text_vi', 'options')}, 'answer': '', 'source': '', 'evidence_ref': '',
             'answered_by': '', 'answered_on': '', 'note': ''} for q in read_csv(LIB / 'questions.csv')]
    write_csv(ws / 'answers.csv', rows, ANSWER_FIELDS, bom=True)
    write_csv(ws / 'findings.csv', [], FINDING_FIELDS, bom=True)
    print(f'created workspace {ws} ({len(rows)} questions in answers.csv). Next: fill answers.csv, then: '
          f'python sme.py run "{ws}"')


def run(ws, as_of, baseline=None):
    ws = Path(ws)
    if not (ws / 'answers.csv').exists():
        raise SystemExit(f'{ws} is not a workspace (no answers.csv); create one with: python sme.py init "{ws}" --company "..."')
    company = json.loads((ws / 'company.json').read_text(encoding='utf-8'))['company'] if (ws / 'company.json').exists() else ws.name
    lib = load_library(ws)
    answers, profile, applicable, excluded = compile_model(ws, as_of, lib)
    res = risk.run(as_of, ws / 'model', baseline)
    out = ws / 'runs' / as_of.isoformat()
    out.mkdir(parents=True, exist_ok=True)
    reg, mat, tr = risk.render(res['rows'], res['warnings'], res['feeds'], res['findings'], as_of)
    acts = top_actions(res, answers, profile, as_of, lib)
    page = render_html(res, answers, company, as_of, acts, lib, excluded, read_version(ws))
    for name, text in (('bao_cao.html', page), ('action_report.md', risk.render_action(res, as_of)), ('register.md', reg),
                       ('matrix.md', mat), ('trace.md', tr), ('state.json', json.dumps(res['state'], indent=1, sort_keys=True) + '\n')):
        (out / name).write_text(text, encoding='utf-8')
    print(f'report: {out / "bao_cao.html"}')
    return res, acts, out


# ---------------------------------------------------------------- self-check
DEMO = {'PRO-01': 'IT thuê ngoài', 'PRO-02': 'Kế toán trưởng', 'PRO-03': 'Giám đốc',
        'TOL-01': '10000000', 'TOL-02': '100000000', 'TOL-03': '500000000',
        'EML-01': 'm365', 'EML-02': 'some', 'EML-03': 'unknown', 'EML-04': 'often', 'EML-05': 'nonpublic',
        'EML-06': 'to1000', 'EML-07': 'serious', 'PAY-01': 'yes', 'PAY-02': 'none', 'PAY-03': 'recent',
        'PAY-04': '800000000', 'PAY-05': 'no', 'REC-01': 'auto', 'REC-02': 'same', 'REC-03': 'never',
        'REC-04': 'once', 'REC-05': 'd3', 'REC-06': 'yes', 'REC-07': 'serious',
        'RAN-01': 'some', 'RAN-02': 'manual', 'RAN-03': 'basic', 'RAN-04': 'w1',
        'DEV-01': 'once', 'DEV-02': 'some', 'DEV-03': 'nonpublic', 'DEV-04': 'to1000',
        'SHR-01': 'allowed', 'SHR-02': 'once', 'SHR-03': 'nonpublic', 'SHR-04': 'to1000', 'ERP-01': 'once', 'ERP-02': 'one',
        'WEB-01': 'yes', 'WEB-02': 'monthly', 'WEB-03': 'nonpublic', 'WEB-04': 'to1000', 'WEB-05': 'limited',
        'OFF-01': 'week', 'OFF-02': 'never', 'OFF-03': 'few', 'VEN-01': 'yes', 'VEN-02': 'shared_password', 'VEN-03': 'no',
        'SAS-01': 'once', 'SAS-02': 'none', 'SAS-03': 'h4',
        'EXP-01': 'many', 'EXP-02': 'no', 'EXP-03': 'nonpublic', 'EXP-04': 'to1000'}


def fill(ws, values, day='2026-11-23'):
    """Test/demo helper: write answers (value or (value, source, evidence_ref[, date]))."""
    rows = read_csv(ws / 'answers.csv')
    for r in rows:
        v = values.get(r['question_id'], '')
        v = v if isinstance(v, tuple) else (v, 'attested' if v else '', '')
        r.update(answer=v[0], source=v[1], evidence_ref=v[2], answered_by='demo' if v[0] else '',
                 answered_on=(v[3] if len(v) > 3 else day) if v[0] else '')
    write_csv(ws / 'answers.csv', rows, ANSWER_FIELDS, bom=True)


def check():
    if not __debug__:
        raise SystemExit('the self-check is written with assert; run it without python -O')
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp) / 'ws'
        init(ws, 'Công ty Thử nghiệm')
        try:
            init(ws, 'x')
            raise AssertionError('init overwrote a workspace')
        except SystemExit:
            pass
        day = datetime.date(2026, 11, 23)
        fill(ws, DEMO)
        res, acts, out = run(ws, day)
        lv = {r['risk_id']: r['risk'] for r in res['rows'] if r['risk_id'] in ('R-EMAIL', 'R-PAY', 'R-RECOVERY')}
        assert lv == {'R-EMAIL': M, 'R-PAY': H, 'R-RECOVERY': M}, lv
        assert len(acts) == 3 and all(a['owner'] and a['due'] and a['proof'] for a in acts)
        page = (out / 'bao_cao.html').read_text(encoding='utf-8')
        assert '3 việc nên làm tiếp' in page and 'EML-03' in page          # unknown answer is shown to the owner
        # BUS-TOL: the owner's tolerances drive the business consequence
        fill(ws, {**DEMO, 'TOL-03': '900000000'})
        r_pay = next(r for r in run(ws, day)[0]['rows'] if r['risk_id'] == 'R-PAY')
        assert r_pay['impact'] == M, r_pay['impact']                       # 800M is now "serious", not "severe"
        fill(ws, {**DEMO, 'TOL-02': '600000000'})
        try:
            run(ws, day)
            raise AssertionError('non-increasing tolerances accepted')
        except SystemExit as e:
            assert 'tolerances must increase' in str(e)
        # Excel variant: semicolon delimiter is read the same
        fill(ws, DEMO)
        rows = list(csv.reader((ws / 'answers.csv').read_text(encoding='utf-8-sig').splitlines()))
        with open(ws / 'answers.csv', 'w', encoding='utf-8-sig', newline='') as f:
            csv.writer(f, delimiter=';', lineterminator='\n').writerows(rows)
        assert {r['risk_id']: r['risk'] for r in run(ws, day)[0]['rows'] if r['risk_id'] in lv} == lv
        # invalid answers are reported together
        fill(ws, {**DEMO, 'EML-02': 'maybe', 'REC-03': ('recent', 'observed', ''), 'PAY-04': '8.000.000'})
        try:
            run(ws, day)
            raise AssertionError('invalid answers accepted')
        except SystemExit as e:
            for frag in ("EML-02: answer 'maybe'", 'REC-03: source observed needs evidence_ref', 'PAY-04: answer'):
                assert frag in str(e), e
        # an unknown answer keeps the rating unknown
        fill(ws, {**DEMO, 'PAY-02': ''})
        assert next(r for r in run(ws, day)[0]['rows'] if r['risk_id'] == 'R-PAY')['risk'] == UNK
        # second cycle: payment verification done and observed -> lower risk, change shown
        fill(ws, DEMO)
        base = run(ws, day)[0]['state']
        fill(ws, {**DEMO, 'PAY-02': ('both', 'observed', 'evidence/pay-test.pdf', '2026-12-01')}, '2026-12-05')
        res2, _, out2 = run(ws, datetime.date(2026, 12, 5), base)
        assert next(r for r in res2['rows'] if r['risk_id'] == 'R-PAY')['risk'] == M
        assert res2['state']['controls']['P-PAYVERIFY@SYS-SME'] == 'implemented_assessed_effective'
        page2 = (out2 / 'bao_cao.html').read_text(encoding='utf-8')
        assert 'Thay đổi so với lần đánh giá 2026-11-23' in page2 and 'Cao → Trung bình' in page2
        try:
            run(Path(tmp) / 'nothing', day)
            raise AssertionError('non-workspace accepted')
        except SystemExit:
            pass
        assert not match('A=x', lambda q: UNK) and match('A=x', lambda q: UNK, unknown_matches=True)
        # P2b: all 12 scenarios rated with full answers; applies_if excludes what does not apply
        fill(ws, DEMO)
        res3 = run(ws, day)[0]
        assert len(res3['rows']) == 12 and all(r['risk'] != UNK for r in res3['rows']), [(r['risk_id'], r['risk']) for r in res3['rows']]
        fill(ws, {**DEMO, 'WEB-01': 'no', 'VEN-01': 'no'})
        res4, _, out4 = run(ws, day)
        assert {r['risk_id'] for r in res4['rows']} == {r['risk_id'] for r in res3['rows']} - {'R-WEB', 'R-VENDOR'}
        assert 'Không áp dụng theo câu trả lời' in (out4 / 'bao_cao.html').read_text(encoding='utf-8')
        # KEV onboarding: an applicable KEV finding on the website becomes the first time-sensitive action
        kev_files = sorted((risk.DATA / 'snapshots' / 'kev').glob('*/*.json'))
        if kev_files:
            fill(ws, DEMO)
            risk.import_snapshot('kev', kev_files[-1], today='2026-11-23', root=ws)
            write_csv(ws / 'findings.csv', [{'finding_id': 'F-101', 'cve_id': 'CVE-2025-24813', 'component_id': 'AS-WEB',
                                             'applicability': 'confirmed', 'remediation_state': 'open',
                                             'first_confirmed_on': '2026-11-20', 'evidence_ref': 'scan: test'}], FINDING_FIELDS, bom=True)
            res5, acts5, _ = run(ws, day)
            assert acts5[0]['title'].startswith('Khắc phục CVE-2025-24813') and acts5[0]['due'] == '2026-12-04', acts5[0]
            write_csv(ws / 'findings.csv', [], FINDING_FIELDS, bom=True)
        # review fixes: a package already in place projects no further change (it was counted twice)
        fill(ws, {**DEMO, 'RAN-01': 'no', 'RAN-02': 'auto', 'WEB-02': 'auto'})
        res6 = run(ws, day)[0]
        r = next(x for x in res6['rows'] if x['risk_id'] == 'R-RANSOM')
        eff6 = {e['package_ids']: e for e in res6['data']['effects'] if e['risk_id'] == 'R-RANSOM'}
        for p in ('P-ADMINSEP', 'P-PATCH'):
            assert (eff6[p]['initiation'], eff6[p]['adverse'], eff6[p]['impact']) == (r['initiation'], r['adverse'], r['impact']), eff6[p]
            assert 'already implemented' in eff6[p]['basis_ref']
        assert eff6['P-MFA']['adverse'] == L                                  # partial MFA still projects its effect
        bundle = next(e for k, e in eff6.items() if ';' in k)
        assert 'some packages already implemented' in bundle['basis_ref'] and bundle['adverse'] == L, bundle
        # invalid tolerances are reported together with the other answer errors; non-finite numbers are rejected
        fill(ws, {**DEMO, 'TOL-02': '600000000', 'EML-02': 'maybe', 'PAY-04': 'nan'})
        try:
            run(ws, day)
            raise AssertionError('invalid answers accepted')
        except SystemExit as e:
            for frag in ('tolerances must increase', "EML-02: answer 'maybe'", "PAY-04: answer 'nan'"):
                assert frag in str(e), e
        # a line break inside a quoted Excel cell stays in that cell
        fill(ws, DEMO)
        rows = read_csv(ws / 'answers.csv')
        rows[0]['note'] = 'dòng 1\ndòng 2'
        write_csv(ws / 'answers.csv', rows, ANSWER_FIELDS, bom=True)
        again = read_csv(ws / 'answers.csv')
        assert len(again) == len(rows) and again[0]['note'] == 'dòng 1\ndòng 2'
    print('sme self-check passed')


def main(argv):
    if '--check' in argv:
        return check()
    opt = lambda name, default: risk.option(argv, name, default)
    if argv[:1] == ['init'] and len(argv) >= 2:
        return init(Path(argv[1]), opt('--company', Path(argv[1]).name))
    if argv[:1] == ['import-kev'] and len(argv) >= 3:      # store a downloaded CISA KEV JSON in the workspace
        risk.import_snapshot('kev', Path(argv[2]), opt('--url', ''), root=Path(argv[1]))
        return
    if argv[:1] == ['run'] and len(argv) >= 2:
        base = opt('--baseline', None)
        baseline = json.loads(Path(base).read_text(encoding='utf-8')) if base else None
        run(Path(argv[1]), datetime.date.fromisoformat(opt('--as-of', datetime.date.today().isoformat())), baseline)
        return
    raise SystemExit(__doc__)


if __name__ == '__main__':
    main(sys.argv[1:])
