"""Assisted risk assessment for small and medium enterprises (PLAN.md section 10, release P2a).

    python sme.py init <workspace> --company "Tên công ty"     # create an isolated company workspace
    python sme.py run <workspace> [--as-of YYYY-MM-DD] [--baseline <workspace>/runs/<date>/state.json]
    python sme.py --check                                     # self-check

The IT person fills answers.csv (Excel, saved as CSV UTF-8) by interviewing the director and checking
configurations. Answer rules (ANS-xx) and decision tables (DT-xx) turn answers into model inputs; the
engine in risk.py rates them; the owner reads runs/<date>/bao_cao.html. P2a scope: three business
services (email accounts, supplier payments, data recovery). Ratings from self-reported answers stay
judgments; the tool never accepts a risk.
"""
import csv
import datetime
import html
import json
import shutil
import sys
import tempfile
from pathlib import Path

import risk

ROOT = Path(__file__).parent
LIB = ROOT / 'library' / 'sme'
ANS_VERSION = 'ANS-0.1'
VL, L, M, H, VH = risk.LEVELS
UNK = risk.UNK
VI_LEVEL = {VL: 'Rất thấp', L: 'Thấp', M: 'Trung bình', H: 'Cao', VH: 'Rất cao', UNK: 'Chưa xác định', '': '—'}
VI_EFFORT = {'Low': 'Thấp', 'Medium': 'Vừa', 'High': 'Cao'}
DUE_DAYS = {'Low': 14, 'Medium': 30, 'High': 60}           # suggested deadline by effort tier [DA]
SOURCES = {'observed', 'attested', 'forecast', 'unknown'}
ANSWER_FIELDS = ['question_id', 'path', 'text_vi', 'options', 'answer', 'source', 'evidence_ref', 'answered_by',
                 'answered_on', 'note']
SYSTEM = 'SYS-SME'
ASSETS = [('AS-EMAIL', 'Email và tài khoản SaaS', 'identity_service', 'internet'),
          ('AS-PAY', 'Thanh toán cho nhà cung cấp', 'finance', 'internal'),
          ('AS-DATA', 'Dữ liệu kế toán/bán hàng và bản sao lưu', 'pii_database', 'internal')]
# risk id, template, Vietnamese name, asset, source type, initiation rule, applicable packages
SCENARIOS = [
    ('R-EMAIL', 'TPL-SME-EMAIL', 'Kẻ gian chiếm tài khoản email/SaaS', 'AS-EMAIL', 'adversarial', 'G2-JUDG', ['P-AWARE', 'P-MFA']),
    ('R-PAY', 'TPL-SME-PAY', 'Lừa đổi tài khoản ngân hàng của nhà cung cấp để chiếm tiền thanh toán', 'AS-PAY',
     'adversarial', 'G2-JUDG', ['P-AWARE', 'P-PAYVERIFY']),
    ('R-RECOVERY', 'TPL-SME-RECOVERY', 'Mất dữ liệu kinh doanh và không khôi phục được từ sao lưu', 'AS-DATA',
     'non_adversarial', 'G3-01', ['P-BACKUP', 'P-RESTORE-TEST']),
]
# library default effect of each single package (a conditional judgment, SPEC 8.4); bundle rule below
EFFECT = {('R-EMAIL', 'P-MFA'): 'adv=L', ('R-EMAIL', 'P-AWARE'): 'none',
          ('R-PAY', 'P-PAYVERIFY'): 'adv=L', ('R-PAY', 'P-AWARE'): 'none',
          ('R-RECOVERY', 'P-BACKUP'): 'adv<=M', ('R-RECOVERY', 'P-RESTORE-TEST'): 'none'}
BUNDLE = {'R-RECOVERY': 'adv=L'}     # backup + restore test together: a tested, isolated copy
# which questions feed which model input (used to point the owner at the question to re-check)
ATTR_QUESTIONS = {('R-EMAIL', 'initiation_likelihood'): ['EML-04'], ('R-EMAIL', 'adverse_impact_likelihood'): ['EML-02', 'EML-03'],
                  ('R-EMAIL', 'info_class'): ['EML-05'], ('R-EMAIL', 'records_disclosed'): ['EML-06'],
                  ('R-EMAIL', 'integrity_consequence'): ['EML-07'],
                  ('R-PAY', 'initiation_likelihood'): ['PAY-03', 'PAY-01'], ('R-PAY', 'adverse_impact_likelihood'): ['PAY-02'],
                  ('R-PAY', 'integrity_consequence'): ['PAY-04'],
                  ('R-RECOVERY', 'annual_frequency'): ['REC-04'],
                  ('R-RECOVERY', 'adverse_impact_likelihood'): ['REC-01', 'REC-02', 'REC-03'],
                  ('R-RECOVERY', 'outage_hours'): ['REC-05'], ('R-RECOVERY', 'in_critical_window'): ['REC-06'],
                  ('R-RECOVERY', 'integrity_consequence'): ['REC-07']}


# ---------------------------------------------------------------- library and answers
def library_dir(ws):
    """The workspace's pinned copy of the library (created by init); the repo copy only if none exists."""
    return ws / 'library' if (ws / 'library' / 'questions.csv').exists() else LIB


def read_csv(path):
    """Read a CSV saved by Excel: UTF-8 with or without BOM, comma or semicolon delimited."""
    text = Path(path).read_text(encoding='utf-8-sig')
    first = text.splitlines()[0] if text else ''
    delim = ';' if first.count(';') > first.count(',') else ','
    return list(csv.DictReader(text.splitlines(), delimiter=delim))


def write_csv(path, rows, fields, bom=False):
    with open(path, 'w', encoding='utf-8-sig' if bom else 'utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator='\n')
        w.writeheader()
        w.writerows(rows)


def options(q):
    return {} if q['options'] == 'text' else dict(o.split('=', 1) for o in q['options'].split('|'))


def load_answers(ws):
    """-> ({question_id: answer dict}, questions, errors). Blank answers become 'unknown'."""
    questions = {q['question_id']: q for q in read_csv(library_dir(ws) / 'questions.csv')}
    answers, errors = {}, []
    for a in read_csv(ws / 'answers.csv'):
        qid = a.get('question_id', '').strip()
        if qid not in questions:
            errors.append(f'answers.csv: unknown question_id {qid!r}')
            continue
        q, ans = questions[qid], (a.get('answer') or '').strip()
        src = (a.get('source') or '').strip() or ('unknown' if not ans else 'attested')
        if not ans:
            ans, src = 'unknown', 'unknown'
        opts = options(q)
        if opts and ans not in opts:
            errors.append(f"{qid}: answer {ans!r} is not one of {', '.join(opts)}")
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
    for qid in questions:
        answers.setdefault(qid, {'value': 'unknown', 'source': 'unknown', 'evidence_ref': '', 'by': '', 'on': '',
                                 'text': questions[qid]['text_vi']})
    return answers, questions, errors


# ---------------------------------------------------------------- answer rules (ANS) and decision tables (DT)
def compile_model(ws, as_of):
    """Answers -> complete model data set (SPEC 6) in ws/model; returns (answers, profile)."""
    answers, questions, errors = load_answers(ws)
    if errors:
        raise SystemExit('answers.csv has errors:\n  ' + '\n  '.join(errors))
    A = lambda q: answers[q]['value']
    inputs = []

    def add(rid, attr, value, qids, rule, default=False):
        used = [answers[q] for q in qids]
        observed = bool(used) and all(u['source'] == 'observed' and u['evidence_ref'] for u in used)
        conf = 'High' if observed else min(({'attested': 'Medium', 'observed': 'Medium'}.get(u['source'], 'Low')
                                            for u in used), key=['Low', 'Medium', 'High'].index, default='Medium')
        why = '; '.join(f"{q}={answers[q]['value']} ({answers[q]['source']}{', ' + answers[q]['by'] if answers[q]['by'] else ''})"
                        for q in qids)
        is_table = rule.startswith('DT')          # decision tables are a declared model judgment (PLAN 10.3)
        mode = 'evidence' if observed and not is_table and not default else 'judgment'
        inputs.append({'subject_id': rid, 'attribute': attr, 'value': value, 'mode': mode,
                       'evidence_ref': '; '.join(u['evidence_ref'] for u in used) if mode == 'evidence' else '',
                       'rationale': '' if mode == 'evidence' else f'{rule} {ANS_VERSION}: {why or "library default"}',
                       'confidence': conf if not default else 'Medium', 'assessor': 'sme.py',
                       'observed_on': max([u['on'] for u in used if u['on']] or [as_of.isoformat()])})

    pick = lambda q, table: table.get(A(q), UNK)
    # email account takeover
    add('R-EMAIL', 'initiation_likelihood', pick('EML-04', {'often': H, 'sometimes': M, 'rarely': M}), ['EML-04'], 'ANS-01')
    mfa, legacy = A('EML-02'), A('EML-03')
    dt_email = UNK if mfa == UNK else (L if mfa == 'all' and legacy == 'blocked' else M if mfa == 'all'
                                       else VH if mfa == 'none' else H)
    add('R-EMAIL', 'adverse_impact_likelihood', dt_email, ['EML-02', 'EML-03'], 'DT-EMAIL')
    add('R-EMAIL', 'info_class', pick('EML-05', {'sensitive': 'sensitive', 'nonpublic': 'nonpublic', 'none': 'public'}),
        ['EML-05'], 'ANS-02')
    add('R-EMAIL', 'records_disclosed', pick('EML-06', {'lt10': '5', 'to1000': '500', 'gt1000': '5000'}), ['EML-06'], 'ANS-02')
    add('R-EMAIL', 'integrity_consequence', pick('EML-07', {k: k for k in ('negligible', 'limited', 'serious', 'severe')}),
        ['EML-07'], 'ANS-02')
    # supplier payment fraud
    seen, by_email = A('PAY-03'), A('PAY-01')
    add('R-PAY', 'initiation_likelihood', UNK if seen == UNK else H if seen == 'recent' or by_email == 'yes' else M,
        ['PAY-03', 'PAY-01'], 'ANS-03')
    add('R-PAY', 'adverse_impact_likelihood', pick('PAY-02', {'both': L, 'callback': M, 'approver': M, 'none': H}),
        ['PAY-02'], 'DT-PAY')
    add('R-PAY', 'integrity_consequence', pick('PAY-04', {k: k for k in ('negligible', 'limited', 'serious', 'severe')}),
        ['PAY-04'], 'ANS-04')
    # data recovery
    add('R-RECOVERY', 'annual_frequency', pick('REC-04', {'rare': '0.5', 'once': '1', 'few': '4', 'monthly': '12'}),
        ['REC-04'], 'ANS-05')
    bk, iso, test = A('REC-01'), A('REC-02'), A('REC-03')
    dt_rec = UNK if bk == UNK else VH if bk == 'none' else H if bk == 'manual' else \
        (L if iso == 'isolated' and test == 'recent' else M)
    add('R-RECOVERY', 'adverse_impact_likelihood', dt_rec, ['REC-01', 'REC-02', 'REC-03'], 'DT-RECOVERY')
    add('R-RECOVERY', 'outage_hours', pick('REC-05', {'h4': '4', 'd1': '24', 'd3': '72', 'w1': '168', 'w2': '336'}),
        ['REC-05'], 'ANS-06')
    add('R-RECOVERY', 'in_critical_window', pick('REC-06', {'yes': 'yes', 'no': 'no'}), ['REC-06'], 'ANS-06')
    add('R-RECOVERY', 'integrity_consequence', pick('REC-07', {k: k for k in ('negligible', 'limited', 'serious', 'severe')}),
        ['REC-07'], 'ANS-06')
    # library defaults for the remaining impact attributes [DA], recorded as judgments
    present = {(i['subject_id'], i['attribute']) for i in inputs}
    for rid, *_ in SCENARIOS:
        for attr, value in (('info_class', 'public'), ('records_disclosed', '0'), ('integrity_consequence', 'negligible'),
                            ('corrected_before_use', 'no'), ('outage_hours', '0'), ('in_critical_window', 'no'),
                            ('multiple_severe_documented', 'no')):
            if (rid, attr) not in present:
                add(rid, attr, value, [], 'SME-LIB default', default=True)

    # control status from answers (ANS-C)
    def ctl(pkg, status, qids):
        used = [answers[q] for q in qids]
        observed = all(u['source'] == 'observed' and u['evidence_ref'] for u in used)
        day = max([u['on'] for u in used if u['on']] or [''])
        if status == 'implemented_assessed_effective' and not (observed and day):
            status = 'implemented'          # "effective" needs an observed, dated check
        return {'scope_id': SYSTEM, 'package_id': pkg, 'status': status,
                'evidence_ref': '; '.join(u['evidence_ref'] for u in used if u['evidence_ref']) or 'answers.csv',
                'verified_on': day if status == 'implemented_assessed_effective' else ''}
    controls = [
        ctl('P-MFA', UNK if mfa == UNK else 'implemented_assessed_effective' if mfa == 'all' and legacy == 'blocked'
            else 'partial' if mfa in ('all', 'most', 'some') else 'absent_unplanned', ['EML-02', 'EML-03']),
        ctl('P-PAYVERIFY', {'both': 'implemented_assessed_effective', 'callback': 'partial', 'approver': 'partial',
                            'none': 'absent_unplanned'}.get(A('PAY-02'), UNK), ['PAY-02']),
        ctl('P-AWARE', {'yes': 'implemented', 'no': 'absent_unplanned'}.get(A('PAY-05'), UNK), ['PAY-05']),
        ctl('P-BACKUP', UNK if bk == UNK else 'absent_unplanned' if bk == 'none' else
            ('implemented' if bk == 'auto' and iso == 'isolated' else 'partial'), ['REC-01', 'REC-02']),
        ctl('P-RESTORE-TEST', {'recent': 'implemented_assessed_effective', 'older': 'partial', 'never': 'absent_unplanned'}
            .get(test, UNK), ['REC-03']),
    ]
    lib_pk = read_csv(library_dir(ws) / 'packages.csv')
    profile = {'it': A('PRO-01'), 'finance': A('PRO-02'), 'director': A('PRO-03')}
    packages = [{'package_id': p['package_id'], 'name': p['name_vi'], 'control_ids': p['cis_ref'], 'effort_tier': p['effort_tier'],
                 'requires': '', 'owner': p['owner_role'], 'due_date': '', 'status': 'proposed',
                 'verification_ref': p['verification_vi']} for p in lib_pk]
    assets = [{'asset_id': a, 'name': n, 'kind': 'service', 'component_ids': '', 'owner': profile['director'],
               'confidentiality': UNK, 'integrity': UNK, 'availability': UNK, 'rationale': 'P2a scope',
               'asset_class': c, 'system_id': SYSTEM, 'vendor': '', 'product': '', 'version': '', 'exposure': e}
              for a, n, c, e in ASSETS]
    templates = [{'template_id': t, 'asset_classes': ASSETS[[a[0] for a in ASSETS].index(asset)][2], 'scope': 'asset',
                  'threat_profile_id': '', 'source_type': st, 'event': name, 'init_rule': ir, 'adverse_rule': 'DT',
                  'impact_rule': 'IMP-01'} for rid, t, name, asset, st, ir, pk in SCENARIOS]
    due = lambda pk: (as_of + datetime.timedelta(days=max(DUE_DAYS[p['effort_tier']] for p in lib_pk
                                                           if p['package_id'] in pk))).isoformat()
    register = [{'risk_id': rid, 'template_id': t, 'family_id': 'FAM-' + rid[2:], 'asset_id': asset,
                 'vulnerability_condition': '', 'existing_controls': 'see controls.csv', 'applicable_packages': ';'.join(pk),
                 'treatment_option': 'mitigate', 'treatment_packages': ';'.join(pk), 'risk_owner': profile['director'],
                 'due_date': due(pk), 'decision_ref': 'chưa quyết định (giám đốc)', 'evidence_ref': 'answers.csv',
                 'status': 'proposed', 'last_reviewed': as_of.isoformat(),
                 'next_review': (as_of + datetime.timedelta(days=90)).isoformat()} for rid, t, name, asset, st, ir, pk in SCENARIOS]
    d = {'assets': assets, 'templates': templates, 'inputs': inputs, 'controls': controls, 'packages': packages,
         'effects': [], 'risk_register': register}
    d['effects'] = default_effects(d)
    model = ws / 'model'
    model.mkdir(exist_ok=True)
    for name, rows in d.items():
        fields = list(rows[0]) if rows else ['risk_id', 'package_ids', 'initiation', 'adverse', 'impact', 'basis_ref', 'basis_hash']
        write_csv(model / f'{name}.csv', rows, fields)
    return answers, profile


def default_effects(d):
    """Library default effects for the current ratings, stamped with the current basis (SPEC 8.4)."""
    rows, _ = risk.evaluate(d)
    out = []
    for r in rows:
        if risk.UNK in (r['initiation'], r['adverse'], r['impact']):
            continue

        def apply(kind):
            adv = r['adverse']
            if kind == 'adv=L':
                adv = L
            elif kind == 'adv<=M':
                adv = min(adv, M, key=risk.LEVELS.index)
            return r['initiation'], adv, r['impact']
        pkgs = [p for p in r['applicable_packages'].split(';') if p]
        for p in pkgs:
            ini, adv, imp = apply(EFFECT[(r['risk_id'], p)])
            out.append({'risk_id': r['risk_id'], 'package_ids': p, 'initiation': ini, 'adverse': adv, 'impact': imp,
                        'basis_ref': f"SME-LIB default: {EFFECT[(r['risk_id'], p)]}", 'basis_hash': r['basis']})
        singles = [apply(EFFECT[(r['risk_id'], p)]) for p in pkgs]
        best = [min((s[k] for s in singles), key=risk.LEVELS.index) for k in range(3)]
        if r['risk_id'] in BUNDLE:
            best = list(apply(BUNDLE[r['risk_id']]))
        out.append({'risk_id': r['risk_id'], 'package_ids': ';'.join(sorted(pkgs)), 'initiation': best[0], 'adverse': best[1],
                    'impact': best[2], 'basis_ref': 'SME-LIB default: bundle', 'basis_hash': r['basis']})
    return out


# ---------------------------------------------------------------- owner report
def top_actions(res, answers, profile, as_of, n=3):
    """Obligations first, then packages with a supported threshold crossing, then foundational gaps
    (unverified packages that would improve a Moderate+ or unknown risk), then evidence to collect."""
    lib = {p['package_id']: p for p in res['data']['packages']}
    rows = {r['risk_id']: r for r in res['rows']}
    name = {s[0]: s[2] for s in SCENARIOS}
    status = {c['package_id']: c['status'] for c in res['data']['controls']}
    roles = {'it': 'Người phụ trách IT', 'finance': 'Phụ trách tài chính'}
    owner = lambda role: profile.get(role) if profile.get(role) not in (None, '', UNK) else roles.get(role, 'Giám đốc')
    acts, used = [], set()

    def add(pkgs, reason):
        key = tuple(sorted(pkgs))
        if key in used or len(acts) >= n:
            return
        used.add(key)
        tier = max((lib[p]['effort_tier'] for p in pkgs), key=risk.EFFORT.index)
        acts.append({'title': ' + '.join(lib[p]['name'] for p in pkgs), 'reason': reason,
                     'owner': ', '.join(sorted({owner(lib[p]['owner']) for p in pkgs})),
                     'due': (as_of + datetime.timedelta(days=DUE_DAYS[tier])).isoformat(),
                     'effort': VI_EFFORT[tier] if len(pkgs) == 1 else 'chưa ước tính (nhiều gói)',
                     'cost': 'chưa ước tính', 'proof': ' '.join(lib[p]['verification_ref'] for p in pkgs)})
    for o in res['obligations']:
        if o['state'] == 'open' or o['state'].startswith('overdue'):
            acts.append({'title': f"Khắc phục {o['cve_id']} trên {o['component_id']}", 'reason': 'Lỗ hổng đã bị khai thác thực tế (CISA KEV)',
                         'owner': owner('it'), 'due': str(o['due']), 'effort': '—', 'cost': 'chưa ước tính',
                         'proof': 'Quét lại cho thấy đã vá'})
    fam_risk = {r['family_id']: r for r in res['rows']}
    front, dominated, bundles, incomplete, _ = res['ranking']
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
    for p in lib:
        if status.get(p) == 'implemented_assessed_effective':
            continue
        hits = []
        for r in rows.values():
            e = eff.get((r['risk_id'], p))
            if p in r['applicable_packages'].split(';') and (r['risk'] == UNK or risk.LEVELS.index(r['risk']) >= 2):
                improves = e is not None and any(risk.LEVELS.index(e[k]) < risk.LEVELS.index(r[k]) for k in ('initiation', 'adverse', 'impact'))
                hits.append((improves, 5 if r['risk'] == UNK else risk.LEVELS.index(r['risk']), r))
        if hits:
            best = max(hits, key=lambda h: (h[0], h[1]))
            gaps.append((not best[0], -best[1], risk.EFFORT.index(lib[p]['effort_tier']), p, best[2]))
    for _, _, _, p, r in sorted(gaps, key=lambda g: g[:4]):
        add([p], f"Biện pháp nền tảng chưa được kiểm chứng; liên quan “{name[r['risk_id']]}” (hiện: {VI_LEVEL[r['risk']]})")
    for qid, a in answers.items():
        if len(acts) >= n:
            break
        if a['value'] == UNK and not qid.startswith('PRO'):
            acts.append({'title': f'Trả lời/kiểm chứng câu hỏi {qid}', 'reason': a['text'], 'owner': owner('it'),
                         'due': (as_of + datetime.timedelta(days=7)).isoformat(), 'effort': 'Thấp', 'cost': '—',
                         'proof': 'Câu trả lời có nguồn (observed kèm evidence_ref)'})
    return acts[:n]


def vi_changes(prev, cur):
    out = []
    name = {s[0]: s[2] for s in SCENARIOS}
    for rid, b in cur['risks'].items():
        a = prev['risks'].get(rid)
        if a and a['risk'] != b['risk']:
            out.append(f"Rủi ro “{name.get(rid, rid)}”: {VI_LEVEL[a['risk']]} → {VI_LEVEL[b['risk']]}")
    vi = {'implemented_assessed_effective': 'đã làm và đã kiểm chứng', 'implemented': 'đã làm (chưa kiểm chứng)',
          'partial': 'làm một phần', 'planned_compensated': 'mới có kế hoạch', 'absent_unplanned': 'chưa có', UNK: 'chưa rõ'}
    names = {p['package_id']: p['name_vi'] for p in read_csv(LIB / 'packages.csv')}
    for k, s in cur['controls'].items():
        if prev['controls'].get(k) != s:
            p = k.split('@')[0]
            out.append(f"Biện pháp “{names.get(p, p)}”: {vi.get(prev['controls'].get(k), '—')} → {vi.get(s, s)}")
    return out


def read_version():
    return (LIB / 'VERSION').read_text(encoding='utf-8').strip() if (LIB / 'VERSION').exists() else 'SME-LIB'


def render_html(res, answers, company, as_of, acts):
    e = html.escape
    name = {s[0]: s[2] for s in SCENARIOS}
    rows = sorted(res['rows'], key=lambda r: [s[0] for s in SCENARIOS].index(r['risk_id']))
    unknown_q = [(q, a['text']) for q, a in answers.items() if a['value'] == UNK and not q.startswith('PRO')]
    check_q = []
    for subj, inp, alt, note in res['queue']:
        for q in ATTR_QUESTIONS.get((subj, inp.split(' = ')[0]), []):
            if (q, answers[q]['text']) not in check_q + unknown_q:
                check_q.append((q, answers[q]['text']))
    css = ('body{font-family:Segoe UI,Arial,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#222}'
           'h1{font-size:1.5em}h2{border-bottom:2px solid #ddd;padding-bottom:4px;margin-top:28px}'
           'table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:6px;vertical-align:top;text-align:left}'
           '.act{border:1px solid #bbb;border-radius:6px;padding:10px 14px;margin:10px 0}.lv{font-weight:bold}'
           '.note{color:#555;font-size:.9em}')
    h = [f'<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>Báo cáo rủi ro - {e(company)}</title>'
         f'<style>{css}</style></head><body>',
         f'<h1>Báo cáo rủi ro an toàn thông tin: {e(company)}</h1>',
         f'<p class="note">Ngày đánh giá {as_of} · Phạm vi: 3 dịch vụ (email/tài khoản SaaS, thanh toán cho nhà cung cấp, '
         f'khôi phục dữ liệu) · Thư viện {e(read_version())} · {ANS_VERSION} · {risk.SPEC_VERSION} · '
         f"mã kiểm tra {risk.state_sha(res['state'])[:12]}</p>", '<h2>3 việc nên làm tiếp</h2>']
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
    if res.get('baseline'):
        ch = vi_changes(res['baseline'], res['state'])
        h.append(f"<h2>Thay đổi so với lần đánh giá {e(res['baseline']['as_of'])}</h2><ul>" +
                 ''.join(f'<li>{e(c)}</li>' for c in ch) + ('' if ch else '<li>Không có thay đổi</li>') + '</ul>')
    h.append('<h2>Những điều chưa biết hoặc cần kiểm chứng</h2>')
    if unknown_q or check_q:
        h.append('<ul>' + ''.join(f'<li><b>{q}</b> (chưa có câu trả lời): {e(t)}</li>' for q, t in unknown_q) +
                 ''.join(f'<li><b>{q}</b> (nếu câu trả lời khác đi thì người cần quyết định sẽ khác): {e(t)}</li>'
                         for q, t in check_q) + '</ul>')
    else:
        h.append('<p>Không có.</p>')
    h += ['<h2>Giới hạn</h2><ul><li>Đây là đánh giá có hỗ trợ cho 3 dịch vụ, không phải chứng nhận tuân thủ.</li>'
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
    print(f'created workspace {ws} ({len(rows)} questions in answers.csv). Next: fill answers.csv, then: '
          f'python sme.py run "{ws}"')


def run(ws, as_of, baseline=None):
    ws = Path(ws)
    if not (ws / 'answers.csv').exists():
        raise SystemExit(f'{ws} is not a workspace (no answers.csv); create one with: python sme.py init "{ws}" --company "..."')
    company = json.loads((ws / 'company.json').read_text(encoding='utf-8'))['company'] if (ws / 'company.json').exists() else ws.name
    answers, profile = compile_model(ws, as_of)
    res = risk.run(as_of, ws / 'model', baseline)
    out = ws / 'runs' / as_of.isoformat()
    out.mkdir(parents=True, exist_ok=True)
    reg, mat, tr = risk.render(res['rows'], res['warnings'], res['feeds'], res['findings'], as_of)
    acts = top_actions(res, answers, profile, as_of)
    for name, text in (('bao_cao.html', render_html(res, answers, company, as_of, acts)),
                       ('action_report.md', risk.render_action(res, as_of)), ('register.md', reg), ('matrix.md', mat),
                       ('trace.md', tr), ('state.json', json.dumps(res['state'], indent=1, sort_keys=True) + '\n')):
        (out / name).write_text(text, encoding='utf-8')
    print(f'report: {out / "bao_cao.html"}')
    return res, acts, out


# ---------------------------------------------------------------- self-check
DEMO = {'PRO-01': 'IT thuê ngoài', 'PRO-02': 'Kế toán trưởng', 'PRO-03': 'Giám đốc',
        'EML-01': 'm365', 'EML-02': 'some', 'EML-03': 'unknown', 'EML-04': 'often', 'EML-05': 'nonpublic',
        'EML-06': 'to1000', 'EML-07': 'serious', 'PAY-01': 'yes', 'PAY-02': 'none', 'PAY-03': 'recent',
        'PAY-04': 'severe', 'PAY-05': 'no', 'REC-01': 'auto', 'REC-02': 'same', 'REC-03': 'never',
        'REC-04': 'once', 'REC-05': 'd3', 'REC-06': 'yes', 'REC-07': 'serious'}


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
        lv = {r['risk_id']: r['risk'] for r in res['rows']}
        assert lv == {'R-EMAIL': M, 'R-PAY': H, 'R-RECOVERY': M}, lv
        assert acts[0]['title'].startswith('Quy trình đổi tài khoản ngân hàng'), acts
        assert len(acts) == 3 and all(a['owner'] and a['due'] and a['proof'] for a in acts)
        page = (out / 'bao_cao.html').read_text(encoding='utf-8')
        assert '3 việc nên làm tiếp' in page and 'EML-03' in page          # unknown answer is shown to the owner
        # Excel variant: semicolon delimiter is read the same
        rows = list(csv.reader((ws / 'answers.csv').read_text(encoding='utf-8-sig').splitlines()))
        with open(ws / 'answers.csv', 'w', encoding='utf-8-sig', newline='') as f:
            csv.writer(f, delimiter=';', lineterminator='\n').writerows(rows)
        assert {r['risk_id']: r['risk'] for r in run(ws, day)[0]['rows']} == lv
        # invalid answers are reported together
        fill(ws, {**DEMO, 'EML-02': 'maybe', 'REC-03': ('recent', 'observed', '')})
        try:
            run(ws, day)
            raise AssertionError('invalid answers accepted')
        except SystemExit as e:
            assert "EML-02: answer 'maybe'" in str(e) and 'REC-03: source observed needs evidence_ref' in str(e), e
        # an unknown answer keeps the rating unknown
        fill(ws, {**DEMO, 'PAY-02': ''})
        assert next(r for r in run(ws, day)[0]['rows'] if r['risk_id'] == 'R-PAY')['risk'] == UNK
        # second cycle: payment verification done and observed -> lower risk, verified, change shown
        fill(ws, DEMO)
        base = run(ws, day)[0]['state']
        fill(ws, {**DEMO, 'PAY-02': ('both', 'observed', 'evidence/pay-test.pdf', '2026-12-01')}, '2026-12-05')
        res2, _, out2 = run(ws, datetime.date(2026, 12, 5), base)
        r_pay = next(r for r in res2['rows'] if r['risk_id'] == 'R-PAY')
        assert r_pay['risk'] == M, r_pay['risk']
        # P-AWARE is still open, so the treatment as a whole is not verified; P-PAYVERIFY itself is
        assert res2['state']['controls']['P-PAYVERIFY@SYS-SME'] == 'implemented_assessed_effective'
        assert r_pay['res_status'] == 'projected'
        page2 = (out2 / 'bao_cao.html').read_text(encoding='utf-8')
        assert 'Thay đổi so với lần đánh giá 2026-11-23' in page2 and 'Cao → Trung bình' in page2
        try:
            run(Path(tmp) / 'nothing', day)
            raise AssertionError('non-workspace accepted')
        except SystemExit:
            pass
    print('sme self-check passed')


def main(argv):
    if '--check' in argv:
        return check()
    opt = lambda name, default: argv[argv.index(name) + 1] if name in argv else default
    if argv[:1] == ['init'] and len(argv) >= 2:
        return init(Path(argv[1]), opt('--company', Path(argv[1]).name))
    if argv[:1] == ['run'] and len(argv) >= 2:
        base = opt('--baseline', None)
        baseline = json.loads(Path(base).read_text(encoding='utf-8')) if base else None
        run(Path(argv[1]), datetime.date.fromisoformat(opt('--as-of', datetime.date.today().isoformat())), baseline)
        return
    raise SystemExit(__doc__)


if __name__ == '__main__':
    main(sys.argv[1:])
