# python-archive-extraction-footgun-lab

A tiny, reproducible, local correctness and safety lab about Python stdlib archive extraction footguns – `zipfile`, `tarfile`, `pathlib`, `os.path`, path normalization, member-name validation, traversal rejection, Windows path caveats, symlink context markers, collision markers, and safe-manifest policies.

**Safety / scoping:** toy local lab only. Not an exploit kit, not a malware archive generator, not a real decompression sandbox, not a production archive scanner, not a filesystem-isolation framework. Deterministic fake member names only (`fake_archive_member`, `demo_payload`, `synthetic_zip_case`, etc.). No real archives, no network, no shell unzip/tar, no external packages, Python stdlib only.

## Hacker News thread access

The Hacker News tool (Hacker News Firebase API CLI) was used to read the linked HN thread **before** writing this README. This is mandatory – the sentiment summary below reflects the actual HN discussion, not just the Snyk article title.

- Thread: https://news.ycombinator.com/item?id=17237295
- Title: "Zip Slip Vulnerability"
- Linked article: https://security.snyk.io/research/zip-slip-vulnerability
- Evidence: `hn_thread_evidence.md`, `hn_comments_sanitized.txt`, `hn_nodes_sanitized.json`

## What Hacker News users were actually debating

(own-words summary derived from HN Firebase API output – do not invent quotes)

- **Old directory traversal, not a new vulnerability.** Multiple commenters said Zip Slip is classic archive path traversal, known since at least 2001 (CVE-2001-1268 Info-ZIP unzip, CVE-2001-1270 PKZip, CVE-2001-1271 rar), with PoC tar trojans in the '90s, a 2009 writeup, and a 2015 Samsung/SwiftKey root exploit (CVE-2015-4641).
- **Branding skepticism.** Strong pushback on "Zip Slip" as a named vulnerability with a logo – "you don't get to name this", "it's ZIP file directory traversal", "a code name and a logo for behavior that is basically by design?", Snyk self-promotion criticism.
- **Disclosure still had value.** Counter-sentiment: many projects / libraries were still vulnerable by default, so coordinated disclosure helped – "that so many libraries are still vulnerable by default means it hasn't exactly stuck."
- **Path validation is subtle.** A commenter showed the Snyk-suggested Node validation `filePath.indexOf(targetFolder) != 0` is wrong – `/var/foo` can be escaped to `/var/foo.secret` via `../foo.secret/blub`. String prefix checks fail on sibling paths.
- **Why `..` archive members are dangerous.** Directory traversal filenames in archive entries cause arbitrary file overwrite on extraction. Commenters debated whether `..` is ever valid in a ZIP (consensus: probably not, but archivers avoid special-casing).
- **Absolute paths / Windows drive names / UNC paths matter.** Cross-platform path handling came up – drive letters, backslashes, UNC shares all need handling, not just Unix `/` and `..`.
- **Tar symlink behavior.** A detailed comment showed macOS tar rejects `..` members AND rejects extracting through a symlink pointing outside the archive (`outside -> ../`, then `outside/foo.txt`). Other platforms' tar will happily extract through symlinks – a PaaS sandbox escape was mentioned. Zip symlink handling also varies.
- **Zip and tar semantics differ.** Zip stores a flat list of member names; tar preserves Unix filesystem metadata including symlinks, permissions, ownership, hardlinks, device files. Path traversal in the member name is one issue; symlink-following during extraction is a separate, harder issue.
- **Python zipfile / tarfile docs and behavior.** Extended debate: initial claim that Python's tarfile/zipfile/shutil have no protection. Then zipfile docs showing `..` stripping, drive/UNC stripping. Confusion over `extractall` warning – it says the module attempts mitigation but you should still inspect/validate paths. Source code check confirmed both `extract` and `extractall` call `_extract_member` which sanitizes. "Documentation, the other 'hard' task in CS." tarfile module was noted still vulnerable (bugs.python.org issue 17102).
- **Inspect archive members before extraction.** Multiple commenters argued you should list files that would be extracted and validate the list before running the extractor, rather than trusting the extractor blindly.
- **Toy validator vs complete security solution.** Validating member path strings (`..` stripping, prefix checks) is not the same as safely extracting untrusted archives. Symlinks, permissions, ownership, hardlinks, device files, case collisions, race conditions, compression bombs – all separate issues. "my local toy validator rejected bad paths" is different from "this is a complete archive security solution."

## What this lab does

50 deterministic fake archive path cases covering:

normal_relative_member, nested_safe_member, parent_directory_traversal, repeated_parent_traversal, absolute_unix_path, leading_slash, windows_drive_absolute, windows_backslash_traversal, windows_unc_path, mixed_separator, dot_component, empty_member_name, current_directory_member, trailing_slash_directory, hidden_file, unicode_filename_context, percent_encoded_context, null_byte_context, prefix_sibling_escape, commonprefix_false_positive, commonpath_policy, pathlib_resolve_policy, zipfile_extract_context, tarfile_extract_context, tar_symlink_context_not_followed, symlink_target_outside_context, duplicate_member_collision, case_insensitive_collision_context, overwrite_existing_file_context, long_path_caveat, size_limit, compression_bomb_not_tested, permission_bits_not_applied, ownership_metadata_not_applied, timestamp_metadata_context, directory_then_file_collision, file_then_directory_collision, safe_extract_manifest, inspect_before_extract, reject_or_sanitize_policy, no_real_archive_input, no_network_input, no_shell_unzip, no_external_truth, documentation_warning_context, old_vulnerability_branding_context, production_sandbox_not_tested, plus prefix-escape sibling tests.

Methods compared (stdlib only):

- `preserve_original_member_baseline`
- `naive_join_only_checker`
- `naive_string_prefix_checker` – intentionally fails sibling-prefix escape
- `naive_commonprefix_checker` – intentionally fails `os.path.commonprefix` false positive
- `normpath_prefix_checker`
- `commonpath_checker`
- `pathlib_resolve_relative_to_checker`
- `zipfile_context_observer`
- `tarfile_context_observer`
- `symlink_context_not_run_marker`
- `collision_policy_marker`
- `safe_manifest_policy_guard`
- `bounded_safe_extract_dry_run`
- `copy_size_timing_marker`
- `deliver_no_external_truth_marker`

Naive methods intentionally fail on sibling-prefix escapes, `..` traversal, Windows drive names, UNC paths, mixed separators, symlink-context cases. Safer policy methods classify/reject without writing outside the controlled temp directory.

## What this lab does NOT do

- No exploit chains, no real untrusted archives, no real user downloads
- No shell `unzip` / `tar` subprocess calls
- No symlink following, no symlink races
- No compression bombs, no permission/ownership tests, no hardlinks/device files
- No production sandboxing, chroot, containers
- No cross-language security conclusions
- No fuzzing, no CVE PoC downloads, no network calls
- No writing outside the repo's temp output directory

## Run it

```bash
python3 -m py_compile generate_cases.py run_lab.py
python3 generate_cases.py
python3 run_lab.py
```

Results: `RESULTS.md`, `results_rows.csv`, `results_rows.json`

## Results (summary)

Naive string-prefix and `commonprefix` checks fail on sibling paths (`/safe/out` vs `/safe/outside`). Policy checkers using `os.path.commonpath` / `pathlib.Path.relative_to` correctly reject `..` traversal, absolute paths, Windows drive/UNC paths, and mixed separators.

Tar symlink behavior: context_only / not_run.

See `RESULTS.md` for full tables.

## References

- HN thread: https://news.ycombinator.com/item?id=17237295
- Snyk article: https://security.snyk.io/research/zip-slip-vulnerability
- Python zipfile: https://docs.python.org/3/library/zipfile.html
- Python tarfile: https://docs.python.org/3/library/tarfile.html
- Python pathlib: https://docs.python.org/3/library/pathlib.html
- Python os.path: https://docs.python.org/3/library/os.path.html
- Evidence: `hn_thread_evidence.md`
