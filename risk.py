"""IA risk model v2.1 (SPEC.md, SPEC-2.1.0) on NIST SP 800-30 Rev.1 lookup tables G-5 and I-2.

    python risk.py           # validate data/, write out/register.md, out/matrix.md, out/trace.md
    python risk.py --check   # self-check

Ratings come from versioned rules (SPEC 3.1) or from recorded judgments with rationale.
The script flags what the decision policy requires; it never accepts a risk.
"""
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent
DATA = ROOT / 'data'
SPEC_VERSION = 'SPEC-2.1.0'
LEVELS = ['Very Low', 'Low', 'Moderate', 'High', 'Very High']
VL, L, M, H, VH = LEVELS
UNK = 'unknown'

# Verbatim from SP 800-30 Rev.1 (pages G-2 and I-1). Row = first factor, columns = second factor VL..VH.
G5 = {VH: [L, M, H, VH, VH], H: [L, M, M, H, VH], M: [L, L, M, M, H], L: [VL, L, L, M, M], VL: [VL, VL, L, L, L]}
I2 = {VH: [VL, L, M, H, VH], H: [VL, L, M, H, VH], M: [VL, L, M, M, H], L: [VL, L, L, L, M], VL: [VL, VL, VL, L, L]}

YESNO = {'yes', 'no'}
CONTROL_STATUS = ['implemented_assessed_effective', 'implemented', 'partial', 'planned_compensated', 'absent_unplanned']
# Declared input attributes (SPEC 3.1 / 6.2): name -> (type, allowed values). Anything else is rejected.
ATTRS = {
    'initiation_likelihood': ('enum', set(LEVELS)),
    'adverse_impact_likelihood': ('enum', set(LEVELS)),
    'annual_frequency': ('float', None),
    'info_class': ('enum', {'public', 'nonpublic', 'sensitive'}),
    'records_disclosed': ('int', None),
    'integrity_consequence': ('enum', {'negligible', 'limited', 'serious', 'severe'}),
    'corrected_before_use': ('enum', YESNO),
    'outage_hours': ('float', None),
    'in_critical_window': ('enum', YESNO),
    'multiple_severe_documented': ('enum', YESNO),
}
RULES = {'F2-01': '1.0', 'G3-01': '1.0', 'C-01': '1.0', 'I-01': '1.0', 'A-01': '1.0', 'IMP-01': '1.0'}
IMPACT_ATTRS = ['info_class', 'records_disclosed', 'integrity_consequence', 'corrected_before_use',
                'outage_hours', 'in_critical_window', 'multiple_severe_documented']


def parse(attr, raw):
    """Typed value of a declared attribute, or UNK. Raises ValueError on anything invalid."""
    if attr not in ATTRS:
        raise ValueError(f'undeclared attribute {attr!r}')
    if raw == UNK:
        return UNK
    kind, allowed = ATTRS[attr]
    if kind == 'enum':
        if raw not in allowed:
            raise ValueError(f'{attr}={raw!r} not in {sorted(allowed)}')
        return raw
    value = float(raw) if kind == 'float' else int(raw)
    if value < 0:
        raise ValueError(f'{attr}={raw!r} is negative')
    return value


# ---------------------------------------------------------------- rules (SPEC 3.1)
def f2_01(status):
    if status == UNK:
        return UNK
    return {'absent_unplanned': VH, 'planned_compensated': H, 'partial': M, 'implemented': L,
            'implemented_assessed_effective': VL}[status]


def g3_01(f):
    if f == UNK:
        return UNK
    return VL if f <= 0.1 else L if f < 1 else M if f < 10 else H if f <= 100 else VH


def c_01(info_class, n):
    if UNK in (info_class, n):
        return UNK
    if info_class == 'public' or n == 0:
        return VL
    band = 0 if n <= 9 else 1 if n <= 1000 else 2
    return ([L, M, H] if info_class == 'nonpublic' else [M, H, H])[band]


def i_01(consequence, corrected):
    if UNK in (consequence, corrected):
        return UNK
    level = {'negligible': VL, 'limited': L, 'serious': M, 'severe': H}[consequence]
    return min(level, L, key=LEVELS.index) if corrected == 'yes' else level


def a_01(hours, window):
    if UNK in (hours, window):
        return UNK
    if hours == 0:
        return VL
    if window == 'yes':
        return M if hours < 24 else H
    return VL if hours < 1 else L if hours < 24 else M if hours <= 168 else H


def imp_01(c, i, a, multiple):
    if UNK in (c, i, a, multiple):
        return UNK
    top = max((c, i, a), key=LEVELS.index)
    return VH if top == H and multiple == 'yes' else top


def overall_likelihood(initiation, adverse):
    return G5[initiation][LEVELS.index(adverse)]


def risk_level(likelihood, impact):
    return I2[likelihood][LEVELS.index(impact)]


def policy_flags(risk, impact):
    """report.md 1.6: what the decision policy requires. Never grants acceptance."""
    flags = {VL: 'owner may accept', L: 'owner may accept', M: 'treat or delegated acceptance',
             H: 'treat or senior exception', VH: 'treat or senior exception'}[risk]
    return flags + ('; ESCALATE' if impact == VH else '')


# ---------------------------------------------------------------- loading and validation
def load(name, root=DATA):
    with open(root / name, encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))


def load_all(root=DATA):
    names = ['assets', 'templates', 'inputs', 'controls', 'packages', 'effects', 'risk_register']
    return {n: load(n + '.csv', root) for n in names}


def validate(d):
    """Return a list of error strings (empty when the data set is valid)."""
    err = []

    def unique(rows, key, name):
        seen = set()
        for r in rows:
            k = tuple(r[x] for x in key)
            if k in seen:
                err.append(f'{name}: duplicate key {k}')
            seen.add(k)
        return seen

    assets = {k[0] for k in unique(d['assets'], ['asset_id'], 'assets')}
    systems = {a['system_id'] for a in d['assets']}
    templates = {t['template_id']: t for t in d['templates']}
    packages = {k[0] for k in unique(d['packages'], ['package_id'], 'packages')}
    risks = {k[0] for k in unique(d['risk_register'], ['risk_id'], 'risk_register')}
    unique(d['inputs'], ['subject_id', 'attribute'], 'inputs')
    unique(d['controls'], ['scope_id', 'package_id'], 'controls')
    for a in d['assets']:
        if a['exposure'] not in {'internet', 'internal', 'isolated'}:
            err.append(f"assets {a['asset_id']}: exposure={a['exposure']!r}")
    for p in d['packages']:
        if p['effort_tier'] not in {'Low', 'Medium', 'High'}:
            err.append(f"packages {p['package_id']}: effort_tier={p['effort_tier']!r}")
    for t in templates.values():
        if t['init_rule'] not in {'G3-01', 'G2-JUDG'} or t['impact_rule'] != 'IMP-01':
            err.append(f"templates {t['template_id']}: unknown rule")
    for i in d['inputs']:
        where = f"inputs {i['subject_id']}/{i['attribute']}"
        if i['subject_id'] not in risks | assets:
            err.append(f'{where}: unknown subject')
        try:
            parse(i['attribute'], i['value'])
        except ValueError as e:
            err.append(f'{where}: {e}')
        if i['mode'] not in {'evidence', 'judgment'} or i['confidence'] not in {'High', 'Medium', 'Low'}:
            err.append(f'{where}: invalid mode/confidence')
        if i['mode'] == 'evidence' and not i['evidence_ref']:
            err.append(f'{where}: evidence without evidence_ref')
        if i['mode'] == 'judgment' and not i['rationale']:
            err.append(f'{where}: judgment without rationale')
    for c in d['controls']:
        where = f"controls {c['scope_id']}/{c['package_id']}"
        if c['scope_id'] not in assets | systems or c['package_id'] not in packages:
            err.append(f'{where}: unknown scope or package')
        if c['status'] not in CONTROL_STATUS + [UNK]:
            err.append(f"{where}: status={c['status']!r}")
        if c['status'] == 'implemented_assessed_effective' and not c['verified_on']:
            err.append(f'{where}: assessed effective without verified_on')
    for e in d['effects']:
        where = f"effects {e['risk_id']}/{e['package_ids']}"
        if e['risk_id'] not in risks or not set(e['package_ids'].split(';')) <= packages:
            err.append(f'{where}: unknown risk or package')
        if any(e[k] not in LEVELS for k in ('initiation', 'adverse', 'impact')):
            err.append(f'{where}: invalid level')
    for r in d['risk_register']:
        where = f"risk_register {r['risk_id']}"
        if r['template_id'] not in templates:
            err.append(f'{where}: unknown template')
        if not set(r['asset_id'].split(';')) <= assets:
            err.append(f'{where}: unknown asset')
        applicable = set(filter(None, r['applicable_packages'].split(';')))
        chosen = set(filter(None, r['treatment_packages'].split(';')))
        if not applicable <= packages or not chosen <= applicable:
            err.append(f'{where}: treatment packages must be known and applicable')
        if r['treatment_option'] not in {'mitigate', 'accept', 'transfer', 'avoid'}:
            err.append(f"{where}: treatment_option={r['treatment_option']!r}")
    return err


# ---------------------------------------------------------------- evaluation
def evaluate(d):
    inputs = {}
    for i in d['inputs']:
        inputs.setdefault(i['subject_id'], {})[i['attribute']] = i
    templates = {t['template_id']: t for t in d['templates']}
    status = {(c['scope_id'], c['package_id']): c['status'] for c in d['controls']}
    effects = {(e['risk_id'], frozenset(e['package_ids'].split(';'))): e for e in d['effects']}
    system_of = {a['asset_id']: a['system_id'] for a in d['assets']}
    conf_rank = {'Low': 0, 'Medium': 1, 'High': 2}
    out, warnings = [], []
    for r in d['risk_register']:
        rid, tpl, got = r['risk_id'], templates[r['template_id']], inputs.get(r['risk_id'], {})
        trace, missing = [], []

        def val(attr):
            if attr not in got:
                missing.append(attr)
                return UNK
            row = got[attr]
            v = parse(attr, row['value'])
            if v == UNK:
                missing.append(attr)
            why = row['evidence_ref'] if row['mode'] == 'evidence' else row['rationale']
            trace.append(f"{attr} = {row['value']} ({row['mode']}, confidence {row['confidence']}; {why})")
            return v

        if tpl['init_rule'] == 'G3-01':
            f = val('annual_frequency')
            initiation = g3_01(f)
            trace.append(f'G3-01 v{RULES["G3-01"]}: annual_frequency {f} -> initiation {initiation}')
        else:
            initiation = val('initiation_likelihood')
        adverse = val('adverse_impact_likelihood')
        c = c_01(val('info_class'), val('records_disclosed'))
        i = i_01(val('integrity_consequence'), val('corrected_before_use'))
        a = a_01(val('outage_hours'), val('in_critical_window'))
        impact = imp_01(c, i, a, val('multiple_severe_documented'))
        trace.append(f'C-01 -> {c}; I-01 -> {i}; A-01 -> {a}; IMP-01 v{RULES["IMP-01"]} -> impact {impact}')
        # F-2 of the applicable packages (displayed context for the G-4 judgment, not a lookup input)
        sys_ids = {system_of[x] for x in r['asset_id'].split(';')}
        f2 = {p: f2_01(next((status[(s, p)] for s in sys_ids if (s, p) in status), UNK))
              for p in filter(None, r['applicable_packages'].split(';'))}
        conf = min((x['confidence'] for x in got.values() if x['mode'] == 'judgment'),
                   key=conf_rank.get, default='High')
        row = {**r, 'initiation': initiation, 'adverse': adverse, 'impact': impact, 'confidence': conf,
               'f2': f2, 'trace': trace, 'overall': UNK, 'risk': UNK, 'flags': '', 'res_risk': '', 'res_overall': '',
               'res_impact': '', 'res_basis': ''}
        if UNK in (initiation, adverse, impact):
            warnings.append(f'{rid}: rating unknown (missing or unknown: {", ".join(missing)}); added to investigation queue')
            out.append(row)
            continue
        row['overall'] = overall_likelihood(initiation, adverse)
        row['risk'] = risk_level(row['overall'], impact)
        row['flags'] = policy_flags(row['risk'], impact)
        trace.append(f"G-5 [{initiation} x {adverse}] -> {row['overall']}; "
                     f"I-2 [{row['overall']} x {impact}] -> {row['risk']}; policy: {row['flags']}")
        chosen = frozenset(filter(None, r['treatment_packages'].split(';')))
        if r['treatment_option'] == 'accept':
            row.update(res_overall=row['overall'], res_risk=row['risk'], res_impact=impact, res_basis='accepted: residual = current')
        elif chosen in {k[1] for k in effects if k[0] == rid}:
            e = effects[(rid, chosen)]
            row['res_overall'] = overall_likelihood(e['initiation'], e['adverse'])
            row.update(res_risk=risk_level(row['res_overall'], e['impact']), res_impact=e['impact'],
                       res_basis=f"effects {';'.join(sorted(chosen))} ({e['basis_ref']})")
        else:
            row['res_basis'] = 'no supported effect for the chosen package set'
        trace.append(f"residual: {row['res_risk'] or UNK} ({row['res_basis']})")
        out.append(row)
    known = [x for x in out if x['risk'] != UNK]
    known.sort(key=lambda x: (-LEVELS.index(x['risk']), -LEVELS.index(x['impact']), -LEVELS.index(x['overall']),
                              conf_rank[x['confidence']], x['risk_id']))
    return known + [x for x in out if x['risk'] == UNK], warnings


# ---------------------------------------------------------------- rendering
def matrix(rows, lk, ik, rk, title):
    lines = [f'### {title}', '', '| Likelihood \\ Impact | ' + ' | '.join(LEVELS) + ' |', '|---' * 6 + '|']
    for lv in reversed(LEVELS):
        cells = [', '.join(r['risk_id'] for r in rows if r[lk] == lv and r[ik] == iv) for iv in LEVELS]
        lines.append(f'| **{lv}** | ' + ' | '.join(cells) + ' |')
    counts = ', '.join(f'{lv} {sum(r[rk] == lv for r in rows)}' for lv in LEVELS)
    return lines + ['', f'Risk levels: {counts}', '']


def render(rows, warnings):
    note = (f'> Generated by `python risk.py` ({SPEC_VERSION}; rules '
            + ', '.join(f'{k} v{v}' for k, v in RULES.items()) + '). Do not edit by hand.\n')
    reg = ['# Risk register (generated)', '', note,
           '| # | Risk | Family | Assets | Overall likelihood | Impact | Risk | Policy flags | Confidence | Option | Residual risk |',
           '|---' * 11 + '|']
    for n, r in enumerate(rows, 1):
        reg.append(f"| {n} | {r['risk_id']} | {r['family_id']} | {r['asset_id'].replace(';', ', ')} | {r['overall']} | "
                   f"{r['impact']} | **{r['risk']}** | {r['flags'] or '-'} | {r['confidence']} | "
                   f"{r['treatment_option']} | {r['res_risk'] or '-'} |")
    if warnings:
        reg += ['', '## Warnings', ''] + [f'- {w}' for w in warnings]
    known = [r for r in rows if r['risk'] != UNK]
    mat = (['# Risk matrix (generated)', '', note] + matrix(known, 'overall', 'impact', 'risk', 'Current risk')
           + matrix([r for r in known if r['res_risk']], 'res_overall', 'res_impact', 'res_risk',
                    'Residual risk (projected unless verified)'))
    tr = ['# Explanation trace (generated)', '', note,
          'Each chain: inputs (with mode, confidence, evidence or rationale) -> rules -> G-5 cell -> I-2 cell -> '
          'policy requirement -> residual basis. F-2 of applicable packages is shown as context for the G-4 judgment.', '']
    for r in rows:
        f2 = ', '.join(f'{p}: {v}' for p, v in r['f2'].items()) or '-'
        tr += [f"## {r['risk_id']} ({r['family_id']})", '', f'- F-2 (F2-01) of applicable packages: {f2}']
        tr += [f'- {t}' for t in r['trace']] + ['']
    return '\n'.join(reg) + '\n', '\n'.join(mat), '\n'.join(tr)


def run(root=DATA):
    d = load_all(root)
    errors = validate(d)
    if errors:
        raise SystemExit('invalid data:\n  ' + '\n  '.join(errors))
    return evaluate(d)


# ---------------------------------------------------------------- self-check
def check():
    # 1. Lookup tables match the verbatim copies in PLAN.md.
    plan = (ROOT / 'PLAN.md').read_text(encoding='utf-8')
    abbr = {'VL': VL, 'L': L, 'M': M, 'H': H, 'VH': VH}
    for name, table in (('G-5', G5), ('I-2', I2)):
        block = plan.split(f'**{name},')[1].split('\n\n')[1]
        rows = re.findall(r'^\s*\| \*\*(\w+)\*\* \|(.*)\|$', block, re.M)
        assert len(rows) == 5, name
        for key, cells in rows:
            assert table[abbr[key]] == [abbr[c.strip()] for c in cells.split('|')], (name, key)
    # 2. Rule boundaries (SPEC 3.1).
    assert [g3_01(x) for x in (0.1, 0.11, 1, 9.99, 10, 100, 100.1)] == [VL, L, M, M, H, H, VH]
    assert [c_01('nonpublic', n) for n in (0, 9, 10, 1000, 1001)] == [VL, L, M, M, H]
    assert [c_01('sensitive', n) for n in (9, 10, 1001)] == [M, H, H] and c_01('public', 5000) == VL
    assert i_01('severe', 'yes') == L and i_01('severe', 'no') == H and i_01('negligible', 'yes') == VL
    assert [a_01(h, 'no') for h in (0, 0.5, 1, 23.9, 24, 168, 168.1)] == [VL, VL, L, L, M, M, H]
    assert [a_01(h, 'yes') for h in (1, 23.9, 24)] == [M, M, H]
    assert imp_01(H, L, M, 'yes') == VH and imp_01(M, L, M, 'yes') == M and imp_01(H, L, UNK, 'no') == UNK
    assert f2_01('implemented_assessed_effective') == VL and f2_01('absent_unplanned') == VH
    # 3. Worked examples (report.md 3.1 / 3.2) and escalation.
    assert risk_level(overall_likelihood(M, H), VH) == H and risk_level(overall_likelihood(H, L), L) == L
    assert policy_flags(M, VH).endswith('ESCALATE') and 'ESCALATE' not in policy_flags(H, H)
    # 4. Validation rejects undeclared attributes and bad values; unknown never becomes zero.
    for attr, raw in (('severity', 'High'), ('impact', 'Medium'), ('outage_hours', '-1'), ('info_class', 'secret')):
        try:
            parse(attr, raw)
            raise AssertionError(f'accepted {attr}={raw}')
        except ValueError:
            pass
    assert g3_01(parse('annual_frequency', UNK)) == UNK
    # 5. Migrated portal case (SPEC 7): expected v2.1 levels.
    rows, warns = run()
    got = {r['risk_id']: (r['risk'], r['res_risk']) for r in rows}
    expected = {'R-01': (H, M), 'R-02': (M, L), 'R-03': (M, M), 'R-04': (M, L), 'R-05': (M, L), 'R-06': (L, L),
                'R-07': (M, L), 'R-08': (L, L), 'R-09': (L, L), 'R-10': (L, L), 'R-11': (H, M), 'R-12': (M, L),
                'R-13': (L, L)}
    assert got == expected and not warns, (got, warns)
    print('self-check passed')


def main():
    if '--check' in sys.argv:
        return check()
    rows, warnings = run()
    reg, mat, tr = render(rows, warnings)
    (ROOT / 'out').mkdir(exist_ok=True)
    for name, text in (('register.md', reg), ('matrix.md', mat), ('trace.md', tr)):
        (ROOT / 'out' / name).write_text(text, encoding='utf-8')
    for w in warnings:
        print('WARNING:', w, file=sys.stderr)
    print(f'wrote out/register.md, out/matrix.md, out/trace.md ({len(rows)} risks)')


if __name__ == '__main__':
    main()
