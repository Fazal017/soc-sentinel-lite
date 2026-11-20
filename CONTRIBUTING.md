# Contributing to SOC Sentinel Lite

## Adding a detection rule

1. Add one YAML file in `rules/` (copy `R001_brute_force.yaml` as a template).
   Keep to the small YAML subset the loader supports: `key: value` pairs and
   one indented level under `mitre:`.
2. Add the detection logic in `src/detector.py` and register it in `DETECTORS`.
3. Add at least one positive test (fires at threshold) and one negative test
   (does not fire below threshold) in `tests/test_detector.py`.
4. Document the rule in the README rules table, with its MITRE technique.

## Ground rules

- **Stdlib only.** No new dependencies without discussion.
- **Sample data only.** Never commit real logs, real IPs, credentials, or
  anything from a production system. Use RFC 5737 TEST-NET addresses.
- **Defensive only.** No exploit code, scanners, or payloads.
- **Tests must pass:** `python3 -m unittest discover -s tests -v`
- **Run the sample end-to-end** before opening a PR:
  `python3 sentinel.py --input logs/sample_auth.log --output report.html --json alerts.json`
