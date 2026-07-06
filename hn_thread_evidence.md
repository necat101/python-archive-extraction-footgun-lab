# HN Thread Evidence – Zip Slip Vulnerability

Thread: https://news.ycombinator.com/item?id=17237295
Title: Zip Slip Vulnerability
Linked article: https://security.snyk.io/research/zip-slip-vulnerability
Accessed via: Hacker News Firebase API CLI (`./hackernews get-item --id 17237295`, recursive kids)
Date accessed: 2026-07-06
Nodes retrieved: 40

Full sanitized comment dump: `hn_comments_sanitized.txt`
Raw nodes JSON: `hn_nodes_sanitized.json`

## Summary of sentiments (in own words, no invented quotes)

- Multiple commenters (tptacek, Fnoord, jaxbot, jwilk, evilDagmar) said Zip Slip is not a new vulnerability – it's classic directory traversal / path traversal in archive extractors, known since at least 2001 (CVE-2001-1268 Info-ZIP unzip, CVE-2001-1270 PKZip, CVE-2001-1271 rar), with PoC tar trojans in the 1990s, and a 2009 writeup, and a 2015 Samsung/SwiftKey root exploit (CVE-2015-4641).
- Strong pushback on the "Zip Slip" branding / code name / logo – commenters called it marketing/self-promotion, saying "you don't get to name this vulnerability", "it's ZIP file directory traversal", "a code name and a logo for behavior that is basically by design?"
- Counter-sentiment: even though old, many libraries were still vulnerable by default, so the coordinated disclosure had value – Snyk notified and helped projects fix it. "that so many libraries are still vulnerable by default means it hasn't exactly stuck."
- Path validation is subtle – a commenter (tlb) pointed out the Snyk-suggested Node.js validation `filePath.indexOf(targetFolder) != 0` is wrong: targetFolder `/var/foo` can be escaped to `/var/foo.secret` via `../foo.secret/blub`. String prefix checks fail on sibling paths.
- Archive members with `..` came up repeatedly – is `..` ever valid in a ZIP? Consensus: probably not intentionally, but archivers avoid special-casing, and users should inspect members before extraction, or extract into a chroot/jail.
- Tar symlink behavior is different from simple zip member names – benmmurphy gave detailed examples: macOS tar rejects `..` members, and also rejects extracting through a symlink that points outside the archive (symlink `outside -> ../`, then `outside/foo.txt`). Other platforms' tar will happily extract through symlinks. Described a PaaS sandbox escape via this. Zip symlink handling also varies by platform.
- Python zipfile / tarfile behavior was debated at length – jwilk initially claimed Python's tarfile/zipfile/shutil have no protection. masklinn pointed to zipfile docs showing `..` components are removed, drive/UNC stripping, etc. Then bjpbakker misread the `extractall` warning as saying it does NOT mitigate traversal. ishi checked CPython source – both `extract` and `extractall` call `_extract_member` which sanitizes paths. Documentation was confusing: the `extractall` warning says the module attempts mitigation but you should still inspect/validate archive paths before extraction. jwilk corrected: "I stand corrected. I was mislead by the scary warning." – but noted tarfile module is still vulnerable (bugs.python.org issue 17102).
- Documentation warnings came up as its own footgun – "Documentation, the other 'hard' task in CS." – zipfile docs say one thing in `extract`, warn in `extractall`, users misread it.
- Inspect before extract – multiple commenters argued you should list archive members and validate the list before running the extractor, rather than trusting the extractor.
- "my local toy validator rejected bad paths" vs "complete archive security solution" – the thread repeatedly distinguishes simple `..` stripping from real archive security: symlinks, permissions, ownership, hardlinks, device files, case collisions, etc. are separate issues. Validating member path strings is not the same as safely extracting untrusted archives.
- Other notes: OSX zip/unzip will create and list `..` members, unzip warns "skipped '..' path component(s)" and extracts to the current dir; tar on macOS rejects `..` paths; Windows Phone jailbreaks used this; Amiga LHA path delimiter quirks; per-file encryption in ZIP.

## How this lab reflects the HN discussion

- Tests naive string-prefix (`indexOf(targetFolder) == 0`) and `os.path.commonprefix` fooled by sibling paths (`/safe/out` vs `/safe/outside`) – directly from tlb's comment.
- Tests `..` traversal, absolute Unix paths, Windows drive names, UNC paths, mixed separators – all discussed in the thread.
- Includes zipfile/tarfile context observers – reflecting the Python docs / source code debate.
- Marks tar symlink behavior as context_only / not_run – reflecting benmmurphy's symlink escape examples, which this toy lab does NOT test.
- Includes documentation_warning_context_marker, old_vulnerability_branding_context_marker, production_sandbox_not_tested_marker – reflecting HN sentiments that Zip Slip is old directory traversal with marketing, docs are confusing, and toy validators aren't production security.
- Includes inspect_before_extract_marker, reject_or_sanitize_policy_marker – reflecting commenters saying you should inspect members before extraction.
- Explicitly does NOT test: real exploit chains, real untrusted archives, real shell tools, real symlink races, compression bombs, file permissions, ownership, hardlinks, device files, production sandboxing, or cross-language security conclusions.

This file exists so the HN thread reading step is auditable – the README sentiment summary is derived from the actual HN Firebase API output above, not from web search or the Snyk article alone.
