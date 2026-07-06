# VERIFY.md – Fresh clone verification

This file records a clean end-to-end verification of the lab from a fresh git clone.

## Verification transcript

```
$ git clone https://github.com/necat101/python-archive-extraction-footgun-lab.git verify-clone2
Cloning into 'verify-clone2'...

$ python3 -m py_compile generate_cases.py run_lab.py
OK

$ python3 generate_cases.py
Wrote 50 cases to cases.json

$ python3 run_lab.py
Done. pass=530 fail=40 skip=180
Results written to RESULTS.md, output/results_rows.csv, output/results_rows.json
```

## Checks

- py_compile: PASS
- generate_cases.py: PASS – 50 cases written to cases.json
- run_lab.py: PASS – pass=530 fail=40 skip=180
- Network calls: 0
- Real archive input: none – synthetic fake member names only
- Shell unzip/tar: none
- Dangerous extraction: none
- Package manager: none
- External packages: none – Python stdlib only
- Files written outside repo: none
- output/results_rows.csv: generated
- output/results_rows.json: generated
- RESULTS.md: generated

## Environment

- Python: 3.12.3
- Platform: Linux-6.17.0-1009-aws-x86_64-with-glibc2.39
- Date: 2026-07-06

Verification: PASS
