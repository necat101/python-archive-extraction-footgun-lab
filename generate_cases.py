#!/usr/bin/env python3
"""
generate_cases.py - deterministic fake archive member cases for archive extraction footgun lab
Safety: no real archives from internet, no network, no malware, stdlib only.
"""
import json
import os

OUTPUT = "cases.json"

cases = [
    # id, category, fake_archive, member_name, archive_type, expected_classification, expected_accept, traversal, absolute, windows_caveat, symlink_caveat, collision_caveat, docs_marker, reason, naive_fail
    ("c01_normal_relative_member_marker", "safe", "fake_archive_member", "example_extract_root/sample_safe_path.txt", "zip", "safe_relative", "accept", False, False, False, False, False, False, "normal relative member", False),
    ("c02_nested_safe_member_marker", "safe", "fake_archive_member", "example_extract_root/nested/sample_safe_path.txt", "zip", "safe_relative", "accept", False, False, False, False, False, False, "nested safe", False),
    ("c03_parent_directory_traversal_marker", "traversal", "synthetic_zip_case", "../demo_payload.txt", "zip", "traversal", "reject", True, False, False, False, False, False, "../ traversal", True),
    ("c04_repeated_parent_traversal_marker", "traversal", "synthetic_zip_case", "../../../demo_payload.txt", "zip", "traversal", "reject", True, False, False, False, False, False, "repeated ../", True),
    ("c05_absolute_unix_path_marker", "absolute", "synthetic_zip_case", "/etc/demo_payload.txt", "zip", "absolute", "reject_or_sanitize", True, True, False, False, False, False, "absolute unix path", True),
    ("c06_leading_slash_marker", "absolute", "synthetic_zip_case", "/sample_safe_path.txt", "zip", "absolute", "reject_or_sanitize", False, True, False, False, False, False, "leading slash", True),
    ("c07_windows_drive_absolute_marker", "windows", "fake_windows_drive_case", "C:\\Windows\\demo_payload.txt", "zip", "windows_drive", "reject_or_sanitize", False, True, True, False, False, False, "Windows drive absolute", True),
    ("c08_windows_backslash_traversal_marker", "windows", "fake_windows_drive_case", "..\\..\\demo_payload.txt", "zip", "windows_traversal", "reject_or_sanitize", True, False, True, False, False, False, "Windows backslash ..", True),
    ("c09_windows_unc_path_marker", "windows", "demo_unc_path", "\\\\server\\share\\demo_payload.txt", "zip", "unc_path", "reject_or_sanitize", False, True, True, False, False, False, "UNC path", True),
    ("c10_mixed_separator_marker", "windows", "fake_windows_drive_case", "example_extract_root\\..\\demo_payload.txt", "zip", "mixed_separator", "reject_or_sanitize", True, False, True, False, False, False, "mixed separators", True),
    ("c11_dot_component_marker", "safe", "fake_archive_member", "./example_extract_root/sample_safe_path.txt", "zip", "dot_component", "accept", False, False, False, False, False, False, "dot . component", False),
    ("c12_empty_member_name_marker", "edge", "synthetic_zip_case", "", "zip", "empty", "reject", False, False, False, False, False, False, "empty member name", False),
    ("c13_current_directory_member_marker", "safe", "fake_archive_member", "./sample_safe_path.txt", "zip", "dot_component", "accept", False, False, False, False, False, False, "current dir .", False),
    ("c14_trailing_slash_directory_marker", "safe", "fake_archive_member", "example_extract_root/nested/", "zip", "directory", "accept", False, False, False, False, False, False, "trailing slash dir", False),
    ("c15_hidden_file_marker", "safe", "fake_archive_member", "example_extract_root/.hidden_demo", "zip", "safe_relative", "accept", False, False, False, False, False, False, "hidden file", False),
    ("c16_unicode_filename_context_marker", "safe", "fake_archive_member", "example_extract_root/ünicode_demo.txt", "zip", "unicode", "accept", False, False, False, False, False, True, "unicode filename context", False),
    ("c17_percent_encoded_context_not_decoded_marker", "edge", "synthetic_zip_case", "example%2f..%2f/demo_payload.txt", "zip", "percent_encoded", "accept", False, False, False, False, False, True, "percent encoded – not decoded by stdlib", False),
    ("c18_null_byte_context_marker", "edge", "synthetic_zip_case", "example_extract_root/\x00demo_payload.txt", "zip", "null_byte", "reject", False, False, False, False, False, True, "null byte context", False),
    ("c19_prefix_sibling_escape_marker", "traversal", "archive_policy_case", "safe/outside/file.txt", "zip", "prefix_sibling", "accept_safe_only", False, False, False, False, False, True, "sibling prefix escape – /safe/out vs /safe/outside", True),
    ("c20_commonprefix_false_positive_marker", "traversal", "archive_policy_case", "safe/outside/file.txt", "zip", "commonprefix_fp", "accept_safe_only", False, False, False, False, False, True, "os.path.commonprefix false positive", True),
    ("c21_commonpath_policy_marker", "safe", "fake_archive_member", "safe/nested/sample_safe_path.txt", "zip", "commonpath_ok", "accept", False, False, False, False, False, False, "commonpath policy", False),
    ("c22_pathlib_resolve_policy_marker", "safe", "fake_archive_member", "example_extract_root/sample_safe_path.txt", "zip", "pathlib_ok", "accept", False, False, False, False, False, False, "pathlib resolve", False),
    ("c23_zipfile_extract_context_marker", "context", "synthetic_zip_case", "example_extract_root/sample_safe_path.txt", "zip", "zipfile_context", "accept", False, False, False, False, False, True, "zipfile extract context", False),
    ("c24_tarfile_extract_context_marker", "context", "toy_tar_case", "example_extract_root/sample_safe_path.txt", "tar", "tarfile_context", "accept", False, False, False, False, False, True, "tarfile extract context", False),
    ("c25_tar_symlink_context_not_followed_marker", "symlink", "toy_tar_case", "toy_symlink_marker", "tar", "symlink", "not_tested", False, False, False, True, False, True, "tar symlink context – not followed", False),
    ("c26_symlink_target_outside_context_marker", "symlink", "toy_tar_case", "toy_symlink_marker", "tar", "symlink_outside", "not_tested", False, False, False, True, False, True, "symlink target outside – not_run", False),
    ("c27_duplicate_member_collision_marker", "collision", "synthetic_collision_case", "example_extract_root/sample_safe_path.txt", "zip", "duplicate", "collision", False, False, False, False, True, True, "duplicate member collision", False),
    ("c28_case_insensitive_collision_context_marker", "collision", "synthetic_collision_case", "Example_Extract_Root/Sample_Safe_Path.TXT", "zip", "case_collision", "collision", False, False, False, False, True, True, "case-insensitive collision context", False),
    ("c29_overwrite_existing_file_context_marker", "collision", "synthetic_collision_case", "example_extract_root/sample_safe_path.txt", "zip", "overwrite", "collision", False, False, False, False, True, True, "overwrite existing file context", False),
    ("c30_long_path_caveat_marker", "edge", "fake_archive_member", "a/"*50 + "sample_safe_path.txt", "zip", "long_path", "accept", False, False, False, False, False, True, "long path caveat", False),
    ("c31_size_limit_marker", "policy", "archive_policy_case", "example_extract_root/sample_safe_path.txt", "zip", "size_limit", "accept", False, False, False, False, False, True, "size limit marker", False),
    ("c32_compression_bomb_not_tested_marker", "policy", "archive_policy_case", "example_extract_root/sample_safe_path.txt", "zip", "bomb_not_tested", "not_tested", False, False, False, False, False, True, "compression bomb – not tested", False),
    ("c33_permission_bits_not_applied_marker", "policy", "archive_policy_case", "example_extract_root/sample_safe_path.txt", "zip", "perm_not_applied", "not_tested", False, False, False, False, False, True, "permission bits not applied – context", False),
    ("c34_ownership_metadata_not_applied_marker", "policy", "archive_policy_case", "example_extract_root/sample_safe_path.txt", "tar", "ownership_not_applied", "not_tested", False, False, False, False, False, True, "ownership metadata not applied", False),
    ("c35_timestamp_metadata_context_marker", "policy", "archive_policy_case", "example_extract_root/sample_safe_path.txt", "zip", "timestamp_context", "accept", False, False, False, False, False, True, "timestamp metadata context", False),
    ("c36_directory_then_file_collision_marker", "collision", "synthetic_collision_case", "example_extract_root/nested", "zip", "dir_file_collision", "collision", False, False, False, False, True, True, "directory then file collision", False),
    ("c37_file_then_directory_collision_marker", "collision", "synthetic_collision_case", "example_extract_root/nested/", "zip", "file_dir_collision", "collision", False, False, False, False, True, True, "file then directory collision", False),
    ("c38_safe_extract_manifest_marker", "policy", "archive_policy_case", "example_extract_root/sample_safe_path.txt", "zip", "manifest_safe", "accept", False, False, False, False, False, True, "safe extract manifest", False),
    ("c39_inspect_before_extract_marker", "policy", "archive_policy_case", "example_extract_root/sample_safe_path.txt", "zip", "inspect_before_extract", "accept", False, False, False, False, False, True, "inspect before extract", False),
    ("c40_reject_or_sanitize_policy_marker", "policy", "archive_policy_case", "../demo_payload.txt", "zip", "reject_policy", "reject", True, False, False, False, False, True, "reject or sanitize policy", True),
    ("c41_no_real_archive_input_marker", "meta", "archive_policy_case", "N/A", "none", "meta", "not_tested", False, False, False, False, False, True, "no real archive input – meta marker", False),
    ("c42_no_network_input_marker", "meta", "archive_policy_case", "N/A", "none", "meta", "not_tested", False, False, False, False, False, True, "no network input – meta marker", False),
    ("c43_no_shell_unzip_marker", "meta", "archive_policy_case", "N/A", "none", "meta", "not_tested", False, False, False, False, False, True, "no shell unzip – meta marker", False),
    ("c44_no_external_truth_marker", "meta", "archive_policy_case", "N/A", "none", "meta", "not_tested", False, False, False, False, False, True, "no external truth – meta marker", False),
    ("c45_documentation_warning_context_marker", "meta", "archive_policy_case", "example_extract_root/sample_safe_path.txt", "zip", "docs_warning", "accept", False, False, False, False, False, True, "documentation warning context", False),
    ("c46_old_vulnerability_branding_context_marker", "meta", "archive_policy_case", "N/A", "none", "meta", "not_tested", False, False, False, False, False, True, "old vulnerability branding context – Zip Slip is directory traversal", False),
    ("c47_production_sandbox_not_tested_marker", "meta", "archive_policy_case", "N/A", "none", "meta", "not_tested", False, False, False, False, False, True, "production sandbox not tested", False),
    ("c48_prefix_escape_with_dotdot_sibling_marker", "traversal", "archive_policy_case", "../safe_outside_demo.txt", "zip", "traversal", "reject", True, False, False, False, False, False, "../ sibling escape", True),
    ("c49_safe_out_folder_member_marker", "safe", "fake_archive_member", "safe/out/sample_safe_path.txt", "zip", "safe_relative", "accept", False, False, False, False, False, False, "safe/out member – for prefix sibling test", False),
    ("c50_safe_outside_folder_member_marker", "edge", "archive_policy_case", "safe/outside/sample_safe_path.txt", "zip", "safe_relative", "accept", False, False, False, False, False, True, "safe/outside member – prefix sibling false positive test", False),
]

case_dicts = []
for (case_id, category, fake_archive, member_name, archive_type, expected_classification,
     expected_accept, traversal, absolute, windows_caveat, symlink_caveat, collision_caveat,
     docs_marker, reason, naive_fail) in cases:
    case_dicts.append({
        "case_id": case_id,
        "category": category,
        "fake_archive": fake_archive,
        "member_name": member_name,
        "archive_type": archive_type,
        "expected_classification": expected_classification,
        "expected_accept": expected_accept,
        "expected_traversal": traversal,
        "expected_absolute": absolute,
        "expected_windows_caveat": windows_caveat,
        "expected_symlink_caveat": symlink_caveat,
        "expected_collision_caveat": collision_caveat,
        "docs_marker": docs_marker,
        "reason": reason,
        "naive_fail_expected": naive_fail,
    })

with open(OUTPUT, "w") as f:
    json.dump({"seed": 42, "count": len(case_dicts), "cases": case_dicts}, f, indent=2)

print(f"Wrote {len(case_dicts)} cases to {OUTPUT}")
