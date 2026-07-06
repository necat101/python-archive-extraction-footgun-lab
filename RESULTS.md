# RESULTS

Python archive extraction footgun lab – correctness results

## Run info

- Python: 3.12.3
- Platform: Linux-6.17.0-1009-aws-x86_64-with-glibc2.39
- Cases: 50
- Methods: 15
- Total rows: 750
- Elapsed: 0.187s
- tracemalloc current: 430.1 KiB, peak: 431.1 KiB

Commands:
```
python3 -m py_compile generate_cases.py run_lab.py
python3 generate_cases.py
python3 run_lab.py
```

## Correctness summary

- pass: 530
- fail: 40
- skip: 180
- expected_naive_failures_triggered: 14

Traversal detection hits: 90
Absolute-path detection hits: 60
Windows/UNC caveat hits: 60
Symlink context not_run: 50
Collision context hits: 75

## Per-method

- preserve_original_member_baseline: pass 38, fail 0, skip 12
- naive_join_only_checker: pass 26, fail 12, skip 12
- naive_string_prefix_checker: pass 34, fail 4, skip 12
- naive_commonprefix_checker: pass 34, fail 4, skip 12
- normpath_prefix_checker: pass 35, fail 3, skip 12
- commonpath_checker: pass 35, fail 3, skip 12
- pathlib_resolve_relative_to_checker: pass 35, fail 3, skip 12
- zipfile_context_observer: pass 35, fail 3, skip 12
- tarfile_context_observer: pass 35, fail 3, skip 12
- symlink_context_not_run_marker: pass 38, fail 0, skip 12
- collision_policy_marker: pass 38, fail 0, skip 12
- safe_manifest_policy_guard: pass 35, fail 3, skip 12
- bounded_safe_extract_dry_run: pass 36, fail 2, skip 12
- copy_size_timing_marker: pass 38, fail 0, skip 12
- deliver_no_external_truth_marker: pass 38, fail 0, skip 12

## Safety / scope markers

- HN thread accessed: YES – https://news.ycombinator.com/item?id=17237295
- Network calls during lab run: 0
- Package manager used: none
- Real archive input: none – synthetic fake member names only
- Shell unzip/tar: none
- Dangerous extraction: none – dry_run / validation only, safe extraction only into controlled temp dir /tmp/archive_lab_ccuzu_v_
- Symlink following: not_run – context_only
- Compression bomb test: not_tested
- Production sandbox: not_tested
- External truth claims: none

## Artifacts

- cases.json – 50 deterministic cases
- output/results_rows.csv
- output/results_rows.json

## Conclusion

Naive string-prefix checks (`naive_string_prefix_checker`) and `os.path.commonprefix` (`naive_commonprefix_checker`) fail on sibling-prefix escapes (e.g. base `/safe/out` vs path `/safe/outside/file.txt`). `..` traversal, absolute paths, Windows drive names, UNC paths, and mixed separators are detected by the policy checkers (`normpath_prefix_checker`, `commonpath_checker`, `pathlib_resolve_relative_to_checker`, `safe_manifest_policy_guard`).

Tar symlink behavior is marked context_only / not_run – this toy lab does not follow symlinks, does not race symlinks, and does not extract untrusted archives.

This is a toy local correctness lab, not a production archive security solution. Path validation details matter – naive validators fail predictably.

No network, no real archives, no shell tools, no external packages.
