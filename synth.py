"""Synthetic organisation and experiments E1-E6 (PLAN.md 9.5 / 9.10.4).

    python synth.py            # generate synthetic/ (seeded) and write out/experiments.md

The synthetic data only shows how the model BEHAVES at scale (assumption A-10). It is not evidence
that any rating is accurate. Rules in risk.py are fixed before generation; the generator adds
independently chosen counterexamples (unknown inputs, rule-boundary values, missing effects).
"""
import csv
import datetime
import random
import shutil
import tempfile
import time
from pathlib import Path

import risk

ROOT = Path(__file__).parent
SEED, GEN_VERSION = 20261122, 'SYNTH-1.0'
AS_OF = datetime.date(2026, 11, 22)
VL, L, M, H, VH = risk.LEVELS
SYSTEMS = ['SYS-A', 'SYS-B', 'SYS-C', 'SYS-D', 'SYS-E']
CLASSES = ['pii_database', 'web_service', 'identity_service', 'backup_store', 'admin_endpoint', 'email',
           'document_store', 'cloud_config', 'log_store']
# template id, asset class ('*' = system scope), source, threat profile, event, init rule, packages
TEMPLATES = [
    ('TPL-S01', 'pii_database', 'adversarial', 'TS-02', 'External attacker exfiltrates database records', 'G2-JUDG', ['T-03', 'T-06', 'T-07']),
    ('TPL-S02', 'web_service', 'adversarial', 'TS-02', 'Exploit of an Internet-facing web service', 'G2-JUDG', ['T-07', 'T-11']),
    ('TPL-S03', 'identity_service', 'adversarial', 'TS-02', 'Credential stuffing against staff accounts', 'G2-JUDG', ['T-01', 'T-06']),
    ('TPL-S04', 'backup_store', 'non_adversarial', 'TS-05', 'Backup deleted or unusable when needed', 'G3-01', ['T-02']),
    ('TPL-S05', 'admin_endpoint', 'adversarial', 'TS-01', 'Malware on an admin workstation steals admin sessions', 'G2-JUDG', ['T-01', 'T-08', 'T-12']),
    ('TPL-S06', 'email', 'adversarial', 'TS-01', 'Phishing leads to mailbox compromise', 'G2-JUDG', ['T-01', 'T-12']),
    ('TPL-S07', 'document_store', 'non_adversarial', 'TS-06', 'Internal documents shared publicly by mistake', 'G3-01', ['T-09', 'T-10']),
    ('TPL-S08', 'cloud_config', 'non_adversarial', 'TS-05', 'Misconfiguration exposes storage', 'G3-01', ['T-09']),
    ('TPL-S09', 'log_store', 'adversarial', 'TS-04', 'Insider alters audit logs', 'G2-JUDG', ['T-03', 'T-06']),
    ('TPL-S10', '*', 'adversarial', 'TS-01', 'Ransomware campaign against the system', 'G2-JUDG', ['T-01', 'T-02', 'T-03', 'T-08', 'T-13']),
    ('TPL-S11', '*', 'non_adversarial', 'TS-07', 'Hosting outage at any time (COND-01)', 'G3-01', ['T-02']),
]
# generator assumption for a single package's projected effect (synthetic only, see module docstring)
EFFECT = {('TPL-S01', 'T-03'): 'adv-1', ('TPL-S01', 'T-06'): 'none', ('TPL-S01', 'T-07'): 'adv=L',
          ('TPL-S02', 'T-07'): 'adv=L', ('TPL-S02', 'T-11'): 'adv-1', ('TPL-S03', 'T-01'): 'adv=L',
          ('TPL-S03', 'T-06'): 'none', ('TPL-S04', 'T-02'): 'adv=L', ('TPL-S05', 'T-01'): 'adv-1',
          ('TPL-S05', 'T-08'): 'adv=L', ('TPL-S05', 'T-12'): 'none', ('TPL-S06', 'T-01'): 'adv=L',
          ('TPL-S06', 'T-12'): 'none', ('TPL-S07', 'T-09'): 'init-1', ('TPL-S07', 'T-10'): 'impact-1',
          ('TPL-S08', 'T-09'): 'init-1', ('TPL-S09', 'T-03'): 'none', ('TPL-S09', 'T-06'): 'adv-1',
          ('TPL-S10', 'T-01'): 'adv-1', ('TPL-S10', 'T-02'): 'impact-1', ('TPL-S10', 'T-03'): 'adv-1',
          ('TPL-S10', 'T-08'): 'adv-1', ('TPL-S10', 'T-13'): 'none', ('TPL-S11', 'T-02'): 'none'}
UNKNOWN_RATE, MISSING_EFFECT_RATE = 0.03, 0.05     # counterexamples [generator choice]


def _write(path, rows):
    with open(path, 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n')
        w.writeheader()
        w.writerows(rows)


def _shift(level, n):
    return risk.LEVELS[max(0, min(4, risk.LEVELS.index(level) + n))]


def _apply(kind, ini, adv, imp):
    """Generator assumption for a single package; projected G-4 never goes below Low (EFF-01)."""
    if kind == 'adv=L':
        adv = L
    elif kind == 'adv-1':
        adv = max(_shift(adv, -1), L, key=risk.LEVELS.index)
    elif kind == 'impact-1':
        imp = _shift(imp, -1)
    elif kind == 'init-1':
        ini = _shift(ini, -1)
    return ini, adv, imp


def _impact(v):
    p = lambda a: risk.parse(a, v[a])
    return risk.imp_01(risk.c_01(p('info_class'), p('records_disclosed')),
                       risk.i_01(p('integrity_consequence'), p('corrected_before_use')),
                       risk.a_01(p('outage_hours'), p('in_critical_window')), p('multiple_severe_documented'))


def generate(out_dir, n_assets=200, seed=SEED):
    rnd = random.Random(seed)
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    feeds, _ = risk.load_snapshots(AS_OF)
    kev_ids = sorted(risk.parse_kev(risk.DATA / feeds['kev'][0]['path'])[1]) if 'kev' in feeds else []
    assets, inputs, controls, effects, register = [], [], [], [], []
    for n in range(1, n_assets + 1):
        cls = CLASSES[(n - 1) % len(CLASSES)] if n <= len(CLASSES) * 2 else rnd.choice(CLASSES)
        sys_id = SYSTEMS[(n - 1) % len(SYSTEMS)]
        lv = lambda: rnd.choice(['Low', 'Moderate', 'High'])
        assets.append({'asset_id': f'AS-{n:04d}', 'name': f'{cls} {n}', 'kind': 'component', 'component_ids': '',
                       'owner': f'Owner {sys_id}', 'confidentiality': lv(), 'integrity': lv(), 'availability': lv(),
                       'rationale': 'synthetic', 'asset_class': cls, 'system_id': sys_id,
                       'vendor': 'Apache' if cls == 'web_service' else '', 'product': 'Tomcat' if cls == 'web_service' else '',
                       'version': '', 'exposure': 'internet' if cls in ('web_service', 'identity_service', 'email')
                       else rnd.choice(['internal', 'internal', 'isolated'])})
    tpl_rows = [{'template_id': t, 'asset_classes': c, 'scope': 'system' if c == '*' else 'asset', 'threat_profile_id': tp,
                 'source_type': s, 'event': e, 'init_rule': ir, 'adverse_rule': 'G4-JUDG', 'impact_rule': 'IMP-01'}
                for t, c, s, tp, e, ir, _ in TEMPLATES]
    instances = []                                  # (risk_id, template, asset ids, system, family)
    for a in assets:
        for t in TEMPLATES:
            if t[1] == a['asset_class']:
                rid = f'R-{len(instances) + 1:04d}'
                fam = f"FAM-{a['system_id']}-RANSOM" if t[0] == 'TPL-S05' else 'FAM-' + rid
                instances.append((rid, t, a['asset_id'], a['system_id'], fam))
    for sys_id in SYSTEMS:
        members = ';'.join(a['asset_id'] for a in assets if a['system_id'] == sys_id)
        for t in TEMPLATES:
            if t[1] == '*':
                rid = f'R-{len(instances) + 1:04d}'
                instances.append((rid, t, members, sys_id, f'FAM-{sys_id}-RANSOM' if t[0] == 'TPL-S10' else 'FAM-' + rid))

    def add(sid, attr, value, mode, conf):
        if rnd.random() < UNKNOWN_RATE:
            value = 'unknown'
        inputs.append({'subject_id': sid, 'attribute': attr, 'value': value, 'mode': mode,
                       'evidence_ref': 'inventory: synthetic' if mode == 'evidence' else '',
                       'rationale': 'synthetic judgment' if mode == 'judgment' else '', 'confidence': conf,
                       'assessor': 'generator', 'observed_on': AS_OF.isoformat()})
    conf = lambda: rnd.choice(['Low', 'Medium', 'High'])
    ev = lambda: rnd.choice(['evidence', 'judgment'])
    for rid, t, aid, sys_id, fam in instances:
        tid, cls, init_rule = t[0], t[1], t[5]
        if init_rule == 'G3-01':
            add(rid, 'annual_frequency', rnd.choice([0.05, 0.1, 0.3, 1, 2, 9.99, 10, 30, 100, 150]), 'evidence', 'Medium')
        else:
            add(rid, 'initiation_likelihood', rnd.choice([L, M, M, H, VH]), 'judgment', conf())
        add(rid, 'adverse_impact_likelihood', rnd.choice([L, M, H, H, VH]), 'judgment', conf())
        add(rid, 'info_class', 'sensitive' if cls == 'pii_database' and rnd.random() < 0.5 else rnd.choice(['public', 'nonpublic']), ev(), conf())
        add(rid, 'records_disclosed', rnd.choice([0, 5, 9, 10, 500, 1000, 1001, 20000]), ev(), conf())
        add(rid, 'integrity_consequence', rnd.choice(['negligible', 'limited', 'serious', 'severe']), ev(), conf())
        add(rid, 'corrected_before_use', rnd.choice(['yes', 'no']), ev(), conf())
        add(rid, 'outage_hours', rnd.choice([0, 0.5, 1, 23.9, 24, 100, 168, 169, 500]), ev(), conf())
        add(rid, 'in_critical_window', rnd.choice(['yes', 'no']), ev(), conf())
        add(rid, 'multiple_severe_documented', 'yes' if tid == 'TPL-S10' and rnd.random() < 0.5 else 'no', ev(), conf())
    # effects: single packages from the generator assumption; multi-package bundle = best of its singles
    values = {}
    for i in inputs:
        values.setdefault(i['subject_id'], {})[i['attribute']] = i['value']
    for rid, t, aid, sys_id, fam in instances:
        v = values[rid]
        ini_raw = v['annual_frequency'] if t[5] == 'G3-01' else v['initiation_likelihood']
        if risk.UNK in (ini_raw, v['adverse_impact_likelihood']):
            continue
        cur_ini = risk.g3_01(float(ini_raw)) if t[5] == 'G3-01' else ini_raw
        cur_imp = _impact(v)
        if cur_imp == risk.UNK:
            continue
        singles = {p: _apply(EFFECT[(t[0], p)], cur_ini, v['adverse_impact_likelihood'], cur_imp) for p in t[6]}
        for p, s in singles.items():
            if rnd.random() >= MISSING_EFFECT_RATE:
                effects.append({'risk_id': rid, 'package_ids': p, 'initiation': s[0], 'adverse': s[1], 'impact': s[2],
                                'basis_ref': 'synthetic: ' + EFFECT[(t[0], p)]})
        if len(t[6]) > 1:
            best = [min((s[k] for s in singles.values()), key=risk.LEVELS.index) for k in range(3)]
            effects.append({'risk_id': rid, 'package_ids': ';'.join(sorted(t[6])), 'initiation': best[0], 'adverse': best[1],
                            'impact': best[2], 'basis_ref': 'synthetic: bundle = best of its singles (generator assumption)'})
    with_set = {(e['risk_id'], e['package_ids']) for e in effects}
    for rid, t, aid, sys_id, fam in instances:
        mitigate = rnd.random() < 0.8
        full = ';'.join(sorted(t[6]))
        if t[0] == 'TPL-S10' and (rid, full) in with_set:
            chosen = full
        else:
            chosen = next((p for p in t[6] if (rid, p) in with_set), '')
        register.append({'risk_id': rid, 'template_id': t[0], 'family_id': fam, 'asset_id': aid, 'vulnerability_condition': '',
                         'existing_controls': 'synthetic', 'applicable_packages': full,
                         'treatment_option': 'mitigate' if mitigate and chosen else 'accept',
                         'treatment_packages': chosen if mitigate and chosen else '', 'risk_owner': f'Owner {sys_id}',
                         'due_date': '2027-06-30', 'decision_ref': 'synthetic', 'evidence_ref': 'synthetic',
                         'status': 'treatment_planned' if mitigate and chosen else 'accepted',
                         'last_reviewed': AS_OF.isoformat(), 'next_review': '2027-11-22'})
    packages = risk.load('packages.csv')
    for sys_id in SYSTEMS:
        for p in packages:
            st = rnd.choice(risk.CONTROL_STATUS[1:] + ['unknown'])        # 'assessed effective' needs a test record
            controls.append({'scope_id': sys_id, 'package_id': p['package_id'], 'status': st,
                             'evidence_ref': 'config: synthetic', 'verified_on': ''})
    # findings on web services: real KEV CVE IDs, synthetic applicability
    web = [a for a in assets if a['asset_class'] == 'web_service']
    for n, a in enumerate(web[:20], 1):
        state = rnd.choice(['confirmed', 'confirmed', 'suspected'])
        rows = [('cve_id', rnd.choice(kev_ids) if kev_ids else f'CVE-2099-{n:04d}'), ('component_id', a['asset_id']),
                ('applicability', state), ('remediation_state', rnd.choice(['open', 'open', 'remediated_verified']))]
        if state == 'confirmed':
            rows.append(('first_confirmed_on', (AS_OF - datetime.timedelta(days=rnd.randint(0, 40))).isoformat()))
        for attr, value in rows:
            inputs.append({'subject_id': f'F-{1000 + n}', 'attribute': attr, 'value': value, 'mode': 'evidence',
                           'evidence_ref': 'scan: synthetic', 'rationale': '', 'confidence': 'High',
                           'assessor': 'generator', 'observed_on': AS_OF.isoformat()})
    for name, rows in (('assets', assets), ('templates', tpl_rows), ('inputs', inputs), ('controls', controls),
                       ('packages', packages), ('effects', effects), ('risk_register', register)):
        _write(out_dir / f'{name}.csv', rows)
    # a workspace must be complete (no fallback to data/): copy the KEV snapshot, then record the basis the
    # generated effects were derived from (they were computed from exactly these inputs and controls)
    if (risk.DATA / 'snapshots' / 'manifest.csv').exists():
        shutil.copytree(risk.DATA / 'snapshots', out_dir / 'snapshots', ignore=shutil.ignore_patterns('epss'))
    risk.stamp_effects(out_dir)
    return out_dir


# ---------------------------------------------------------------- experiments
def coverage(res):
    """E1: how each core factor was obtained (rule from evidence / rule using judgment / judgment / unknown)."""
    counts = {f: {'rule from evidence': 0, 'rule using judgment': 0, 'judgment': 0, 'unknown': 0}
              for f in ('initiation', 'adverse', 'impact')}
    for r in res['rows']:
        mode = lambda a: r['input_rows'][a]['mode'] if a in r['input_rows'] else 'missing'
        if r['initiation'] == risk.UNK:
            counts['initiation']['unknown'] += 1
        elif r['tpl']['init_rule'] == 'G3-01':
            counts['initiation']['rule from evidence' if mode('annual_frequency') == 'evidence' else 'rule using judgment'] += 1
        else:
            counts['initiation']['judgment'] += 1
        counts['adverse']['unknown' if r['adverse'] == risk.UNK else 'judgment'] += 1
        if r['impact'] == risk.UNK:
            counts['impact']['unknown'] += 1
        else:
            all_ev = all(mode(a) == 'evidence' for a in risk.IMPACT_ATTRS)
            counts['impact']['rule from evidence' if all_ev else 'rule using judgment'] += 1
    return counts


def order(rank):
    """Full recommendation order: complete Pareto front, complete combinations, then incomplete (lower-bound) candidates."""
    front, _, bundles, incomplete, _ = rank
    lower = [c for c in incomplete if c['below_high'] or c['below_moderate']]
    return [' + '.join(c['packages']) for c in front + bundles + lower]


def sensitivity(d, sample=None, seed=SEED):
    """E3: move each judgment level +-1 and halve/double each numeric input; count level changes and order changes."""
    rows, _ = risk.evaluate(d)
    base_levels = {r['risk_id']: r['risk'] for r in rows}
    base_order = order(risk.rank_candidates(risk.candidate_effects(rows, d)))
    perts = []
    for idx, i in enumerate(d['inputs']):
        if not i['subject_id'].startswith('R-') or i['value'] == risk.UNK:
            continue
        kind = risk.ATTRS[i['attribute']][1]
        if i['attribute'] in ('initiation_likelihood', 'adverse_impact_likelihood') and i['mode'] == 'judgment':
            n = risk.LEVELS.index(i['value'])
            perts += [(idx, risk.LEVELS[j]) for j in (n - 1, n + 1) if 0 <= j < 5]
        elif kind in ('float', 'int') and float(i['value']) > 0:
            cast = (lambda x: str(x)) if kind == 'float' else (lambda x: str(int(round(x))))
            perts += [(idx, cast(float(i['value']) * f)) for f in (0.5, 2)]
    if sample and len(perts) > sample:
        perts = random.Random(seed).sample(perts, sample)
    any_change = changed = top = rev = comparable = 0
    for idx, value in perts:
        dd = {**d, 'inputs': list(d['inputs'])}
        dd['inputs'][idx] = {**d['inputs'][idx], 'value': value}
        # E3 asks "would the recommendation change if this judgment were different?" with the projections kept as
        # assessed, so re-stamp the perturbed risk's effects instead of letting staleness exclude them
        rid = d['inputs'][idx]['subject_id']
        new_basis = next(r['basis'] for r in risk.evaluate(dd)[0] if r['risk_id'] == rid)
        dd['effects'] = [{**e, 'basis_hash': new_basis} if e['risk_id'] == rid else e for e in d['effects']]
        rows2, _ = risk.evaluate(dd)
        n = sum(r['risk'] != base_levels[r['risk_id']] for r in rows2)
        changed += n
        any_change += n > 0
        o2 = order(risk.rank_candidates(risk.candidate_effects(rows2, dd)))
        top += o2[:1] != base_order[:1]
        common = [c for c in base_order if c in o2]
        for a in range(len(common)):
            for b in range(a + 1, len(common)):
                comparable += 1
                rev += o2.index(common[a]) > o2.index(common[b])
    return {'perturbations': len(perts), 'any_level_change': any_change, 'risk_level_changes': changed,
            'top_changes': top, 'pair_reversals': rev, 'comparable_pairs': comparable, 'risks': len(base_levels)}


def baselines(res, k=3):
    """E5: model order vs risk-first vs effort-first, each picking single packages with the same effort tiers."""
    cands = risk.candidate_effects(res['rows'], res['data'])
    singles = {c['packages'][0]: c for c in cands if len(c['packages']) == 1}
    front, dominated, _, incomplete, _ = res['ranking']
    lower = [c for c in incomplete if len(c['packages']) == 1 and (c['below_high'] or c['below_moderate'])]
    model = [c['packages'][0] for c in front + dominated + lower][:k]
    tiers = sorted(singles[p]['effort'] for p in model)
    rows = [r for r in res['rows'] if r['risk'] != risk.UNK]

    def worst(p):
        lv = [risk.LEVELS.index(r['risk']) for r in rows if p in r['applicable_packages'].split(';')]
        return (max(lv) if lv else -1, len(lv))
    pool = sorted(singles)
    orders = {'risk-first': sorted(pool, key=lambda p: (-worst(p)[0], -worst(p)[1], p)),
              'effort-first': sorted(pool, key=lambda p: (risk.EFFORT.index(singles[p]['effort']), p))}

    def pick(ordering):
        need, out = list(tiers), []
        for p in ordering:
            if singles[p]['effort'] in need:
                need.remove(singles[p]['effort'])
                out.append(p)
        return out

    def result(sel):
        return (sel, sorted({f for p in sel for f in singles[p]['below_high']}),
                sorted({f for p in sel for f in singles[p]['below_moderate']}),
                sorted(p for p in sel if singles[p]['incomplete']))
    return {'tiers': tiers, 'model': result(model), **{k: result(pick(o)) for k, o in orders.items()}}


def traceability(res):
    rows = res['rows']
    ok = sum(1 for r in rows if any(t.startswith('G-5') for t in r['trace']) and any(t.startswith('residual:') for t in r['trace']))
    return ok, len(rows)


def file_hashes(folder):
    return {p.name: risk.sha256(p) for p in sorted(Path(folder).glob('*.csv'))}


def experiment(name, root, sample=None):
    t0 = time.perf_counter()
    res = risk.run(AS_OF, root)
    seconds = time.perf_counter() - t0
    again = risk.run(AS_OF, root)
    return {'name': name, 'res': res, 'runtime': seconds,
            'deterministic': risk.state_sha(res['state']) == risk.state_sha(again['state']),
            'state_sha': risk.state_sha(res['state']), 'coverage': coverage(res),
            'sensitivity': sensitivity(res['data'], sample), 'baselines': baselines(res), 'trace': traceability(res)}


def render(exps, gen):
    pct = lambda a, b: f'{100 * a / b:.1f}%' if b else '-'
    out = ['# Experiments E1-E6 (generated)', '',
           f'> Generated by `python synth.py`; assessment date {AS_OF}; generator {GEN_VERSION}, seed {SEED}; '
           f'{risk.SPEC_VERSION}. Run times vary by machine and are not part of any hashed state.',
           '> **Synthetic results show model behaviour only (A-10).** They do not show that any rating is accurate '
           'or that any control is effective.', '',
           '## E4 Scale and E2 determinism', '',
           '| Data set | Assets | Scenarios | Inputs | Effects | Findings | Run time | Same state twice | State SHA-256 |',
           '|---|---|---|---|---|---|---|---|---|']
    for e in exps:
        d = e['res']['data']
        out.append(f"| {e['name']} | {len(d['assets'])} | {len(d['risk_register'])} | {len(d['inputs'])} | {len(d['effects'])} | "
                   f"{len(e['res']['findings'])} | {e['runtime']:.2f} s | {'yes' if e['deterministic'] else 'NO'} | {e['state_sha'][:12]}… |")
    out += ['', f"Synthetic generation took {gen['seconds']:.2f} s; generating twice with seed {SEED} gave "
            f"{'identical' if gen['identical'] else 'DIFFERENT'} files (SHA-256 of each CSV at the end).", '',
            '## E1 Rule coverage of the core factors', '',
            '| Data set | Factor | Rule from evidence | Rule using judgment | Judgment | Unknown |', '|---|---|---|---|---|---|']
    for e in exps:
        for f, c in e['coverage'].items():
            n = sum(c.values())
            out.append(f"| {e['name']} | {f} | {pct(c['rule from evidence'], n)} | {pct(c['rule using judgment'], n)} | "
                       f"{pct(c['judgment'], n)} | {pct(c['unknown'], n)} |")
    out += ['', 'Determinism (E2) is repeatable computation, not valid evidence: the judgment shares above remain judgment.', '',
            '## E3 Sensitivity', '',
            '| Data set | Perturbations | Changing any risk level | Risks changed per perturbation | Top recommendation changed | Pair reversals / comparable pairs |',
            '|---|---|---|---|---|---|']
    for e in exps:
        s = e['sensitivity']
        out.append(f"| {e['name']} | {s['perturbations']} | {pct(s['any_level_change'], s['perturbations'])} | "
                   f"{s['risk_level_changes'] / max(1, s['perturbations']):.2f} of {s['risks']} | {pct(s['top_changes'], s['perturbations'])} | "
                   f"{s['pair_reversals']} / {s['comparable_pairs']} ({pct(s['pair_reversals'], s['comparable_pairs'])}) |")
    out += ['', 'Judgment levels move one step; numeric inputs are halved and doubled (the VOI-01 range). '
            'The synthetic set uses a fixed random sample of 300 perturbations.', '',
            '## E5 Package choice versus simple baselines (same effort tiers)', '',
            '| Data set | Effort tiers | Method | Packages | Families below High | Families below Moderate | Incomplete picks |',
            '|---|---|---|---|---|---|---|']
    for e in exps:
        b = e['baselines']
        for m in ('model', 'risk-first', 'effort-first'):
            sel, hi, mo, inc = b[m]
            out.append(f"| {e['name']} | {', '.join(b['tiers'])} | {m} | {', '.join(sel) or '-'} | {len(hi)} | {len(mo)} | {', '.join(inc) or '-'} |")
    out += ['', "Each method picks single packages with the same effort tiers as the model's top picks. A family counts when "
            'at least one selected package, assessed on its own, takes it below the threshold (combinations are not assumed '
            'additive). Comparisons are valid only inside each data set.', '',
            '## E6 Traceability and maintenance', '', '| Data set | Risks with a complete explanation chain |', '|---|---|']
    out += [f"| {e['name']} | {e['trace'][0]} / {e['trace'][1]} ({pct(*e['trace'])}) |" for e in exps]
    out += ['', 'Risks without a chain have an unknown rating and are listed in the investigation queue. The maintenance '
            'cycle (Task 4-1/4-2) is demonstrated in examples/cycle2 (SPEC 7.4).', '',
            '## Synthetic data files (SHA-256)', ''] + [f'- `{k}` {v}' for k, v in gen['hashes'].items()]
    return '\n'.join(out) + '\n'


def main():
    t0 = time.perf_counter()
    syn = generate(ROOT / 'synthetic')
    seconds = time.perf_counter() - t0
    with tempfile.TemporaryDirectory() as tmp:
        identical = file_hashes(generate(Path(tmp) / 'again')) == file_hashes(syn)
    exps = [experiment('portal case', risk.DATA), experiment('synthetic', syn, sample=300)]
    gen = {'seconds': seconds, 'identical': identical, 'hashes': file_hashes(syn)}
    (ROOT / 'out').mkdir(exist_ok=True)
    (ROOT / 'out' / 'experiments.md').write_text(render(exps, gen), encoding='utf-8')
    print('wrote out/experiments.md')


if __name__ == '__main__':
    main()
