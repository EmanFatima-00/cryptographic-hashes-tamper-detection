"""
task3.py - File Integrity Checker (CodeNova Cyber Security Internship, Task 3)

Creates a SHA-256 baseline manifest of every file in a folder (including
sub-folders) and later verifies the folder against it, reporting files that
were MODIFIED, NEW, or MISSING (deleted). Hashes are compared, not just size
or timestamp, so a one-byte change is detected even if the file size and
modified-time look unchanged.

Usage (Windows):
  python task3.py baseline  <folder> [-m manifest.json]
  python task3.py verify    <folder> [-m manifest.json]
  python task3.py demo      (builds a test folder and simulates tampering)

Exit codes (useful for scripts): 0 = intact, 1 = changes found, 2 = error.
Only the Python standard library is used (hashlib, os, json, argparse).
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import sys

ALGORITHM = "sha256"
CHUNK = 65536  # read files in 64 KB pieces so huge files do not fill memory
DEFAULT_MANIFEST = "manifest.json"
DEMO_DIR = "demo_folder"
DEMO_MANIFEST = "demo_manifest.json"
DEMO_MARKER = ".codenova_demo"   # safety: only delete folders we created

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GREEN, YELLOW, CYAN = "\033[91m", "\033[92m", "\033[93m", "\033[96m"


# ----------------------------------------------------------------- hashing
def hash_file(path):
    """Return the SHA-256 hex digest of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(
        timespec="seconds")


def scan_folder(folder, skip_abs=()):
    """
    Walk the folder tree and hash every regular file.
    Returns (files, errors):
      files  = {relative/path: {sha256, size, modified_utc, mtime_ns}}
      errors = [(relative/path, reason)] for files that could not be read.
    """
    files, errors = {}, []
    skip_abs = {os.path.abspath(p) for p in skip_abs}
    for current, dirs, names in os.walk(folder, onerror=lambda e: errors.append(
            (os.path.relpath(e.filename or folder, folder), e.strerror))):
        dirs.sort()
        for name in sorted(names):
            full = os.path.join(current, name)
            rel = os.path.relpath(full, folder).replace(os.sep, "/")
            if os.path.abspath(full) in skip_abs or os.path.islink(full):
                continue
            try:
                stat = os.stat(full)
                files[rel] = {"sha256": hash_file(full), "size": stat.st_size,
                              "modified_utc": iso(stat.st_mtime),
                              "mtime_ns": stat.st_mtime_ns}
            except (PermissionError, OSError) as err:
                errors.append((rel, err.strerror or str(err)))
    return files, errors


def manifest_digest(files):
    """Digest of the manifest's file table, to detect edits to the manifest."""
    blob = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------- commands
def create_baseline(folder, manifest_path):
    if not os.path.isdir(folder):
        raise NotADirectoryError(f"'{folder}' is not a folder.")
    files, errors = scan_folder(folder, skip_abs=[manifest_path])
    manifest = {
        "version": 1,
        "algorithm": ALGORITHM,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(
            timespec="seconds"),
        "root": os.path.abspath(folder),
        "file_count": len(files),
        "files": files,
        "manifest_digest": manifest_digest(files),
    }
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest, errors


def load_manifest(manifest_path):
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    if "files" not in manifest:
        raise ValueError("Manifest is missing the 'files' section.")
    return manifest


def verify_folder(folder, manifest_path):
    """Compare the folder to the manifest. Returns a result dictionary."""
    if not os.path.isdir(folder):
        raise NotADirectoryError(f"'{folder}' is not a folder.")
    manifest = load_manifest(manifest_path)
    baseline = manifest["files"]
    current, errors = scan_folder(folder, skip_abs=[manifest_path])
    unreadable = {rel for rel, _ in errors}

    modified, new, missing = [], [], []
    for rel, old in baseline.items():
        if rel in current:
            if current[rel]["sha256"] != old["sha256"]:
                same_meta = (current[rel]["size"] == old["size"] and
                             current[rel]["mtime_ns"] == old.get("mtime_ns"))
                modified.append({"path": rel, "old": old, "new": current[rel],
                                 "same_size_and_time": same_meta})
        elif rel not in unreadable:
            missing.append({"path": rel, "old": old})
    for rel, info in current.items():
        if rel not in baseline:
            new.append({"path": rel, "new": info})

    return {
        "manifest": manifest, "modified": modified, "new": new,
        "missing": missing, "unreadable": errors,
        "checked": len(current),
        "manifest_tampered": manifest.get("manifest_digest") not in
                             (None, manifest_digest(baseline)),
    }


# ------------------------------------------------------------------ output
def short(h):
    return h[:12] + "..."


def print_baseline(manifest, errors, manifest_path):
    print(f"\n{BOLD}BASELINE CREATED{RESET}")
    print("=" * 64)
    print(f"Folder     : {manifest['root']}")
    print(f"Manifest   : {os.path.abspath(manifest_path)}")
    print(f"Algorithm  : {manifest['algorithm'].upper()}")
    print(f"Files      : {manifest['file_count']}")
    print(f"Created    : {manifest['created_utc']}")
    if errors:
        print(f"\n{YELLOW}Could not read {len(errors)} file(s) "
              f"(skipped):{RESET}")
        for rel, why in errors:
            print(f"  - {rel}: {why}")
    print("=" * 64)


def print_report(res):
    m = res["manifest"]
    total_changes = len(res["modified"]) + len(res["new"]) + len(res["missing"])
    print(f"\n{BOLD}FILE INTEGRITY REPORT{RESET}")
    print("=" * 64)
    print(f"Baseline created : {m.get('created_utc', 'unknown')}")
    print(f"Verified at      : {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}")
    print(f"Files in baseline: {len(m['files'])}    Files checked now: {res['checked']}")
    if res["manifest_tampered"]:
        print(f"{RED}{BOLD}WARNING: the manifest itself was edited after it was "
              f"created. Results cannot be trusted.{RESET}")
    print("-" * 64)
    status = (f"{GREEN}{BOLD}INTACT - no changes detected{RESET}"
              if total_changes == 0 and not res["unreadable"]
              else f"{RED}{BOLD}CHANGES DETECTED: {total_changes}{RESET}")
    print(f"Status           : {status}")
    print(f"  Modified: {len(res['modified'])}   New: {len(res['new'])}   "
          f"Missing: {len(res['missing'])}   Unreadable: {len(res['unreadable'])}")

    if res["modified"]:
        print(f"\n{RED}{BOLD}[MODIFIED]{RESET}")
        for item in res["modified"]:
            print(f"  {item['path']}")
            print(f"     old hash: {short(item['old']['sha256'])}   "
                  f"new hash: {short(item['new']['sha256'])}")
            if item["same_size_and_time"]:
                print(f"     {YELLOW}Size and timestamp are IDENTICAL but the "
                      f"content changed (stealth modification).{RESET}")
            else:
                print(f"     size: {item['old']['size']} -> "
                      f"{item['new']['size']} bytes   "
                      f"modified: {item['new']['modified_utc']}")
    if res["new"]:
        print(f"\n{YELLOW}{BOLD}[NEW FILE]{RESET}")
        for item in res["new"]:
            print(f"  {item['path']}  ({item['new']['size']} bytes, "
                  f"{item['new']['modified_utc']})")
    if res["missing"]:
        print(f"\n{RED}{BOLD}[MISSING / DELETED]{RESET}")
        for item in res["missing"]:
            print(f"  {item['path']}  (was {item['old']['size']} bytes)")
    if res["unreadable"]:
        print(f"\n{YELLOW}{BOLD}[UNREADABLE - permission or I/O error]{RESET}")
        for rel, why in res["unreadable"]:
            print(f"  {rel}: {why}")
        print(f"  {DIM}These files could not be verified.{RESET}")
    print("=" * 64)


# -------------------------------------------------------------------- demo
def run_demo():
    """Build a test folder, baseline it, tamper with it and verify."""
    if os.path.exists(DEMO_DIR):
        if not os.path.exists(os.path.join(DEMO_DIR, DEMO_MARKER)):
            print(f"'{DEMO_DIR}' already exists and was not created by this "
                  f"demo. Rename or remove it first.")
            return 2
        shutil.rmtree(DEMO_DIR)
    os.makedirs(os.path.join(DEMO_DIR, "docs", "reports"))
    os.makedirs(os.path.join(DEMO_DIR, "bin"))
    with open(os.path.join(DEMO_DIR, DEMO_MARKER), "w") as fh:
        fh.write("demo folder created by task3.py\n")
    samples = {
        "readme.txt": b"Demo file for the File Integrity Checker.\n",
        "docs/policy.txt": b"Security policy v1.0\nPasswords must be 12+ chars.\n",
        "docs/reports/q3.csv": b"month,incidents\nJul,3\nAug,5\nSep,2\n",
        "bin/tool.bin": bytes(range(256)) * 4,
    }
    for rel, data in samples.items():
        with open(os.path.join(DEMO_DIR, *rel.split("/")), "wb") as fh:
            fh.write(data)

    print(f"{BOLD}STEP 1 - Create baseline of '{DEMO_DIR}'{RESET}")
    manifest, errors = create_baseline(DEMO_DIR, DEMO_MANIFEST)
    print_baseline(manifest, errors, DEMO_MANIFEST)

    print(f"\n{BOLD}STEP 2 - Verify untouched folder{RESET}")
    print_report(verify_folder(DEMO_DIR, DEMO_MANIFEST))

    print(f"\n{BOLD}STEP 3 - Simulate tampering{RESET}")
    target = os.path.join(DEMO_DIR, "docs", "policy.txt")
    before = os.stat(target)
    with open(target, "r+b") as fh:          # flip ONE byte ('1' -> '2')
        fh.seek(fh.read().index(b"1"))
        fh.write(b"2")
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))  # restore time
    print("  * flipped a single byte in docs/policy.txt "
          "(size and timestamp restored)")
    with open(os.path.join(DEMO_DIR, "docs", "new_file.txt"), "w") as fh:
        fh.write("unexpected file\n")
    print("  * created docs/new_file.txt")
    os.remove(os.path.join(DEMO_DIR, "bin", "tool.bin"))
    print("  * deleted bin/tool.bin")

    print(f"\n{BOLD}STEP 4 - Verify again{RESET}")
    res = verify_folder(DEMO_DIR, DEMO_MANIFEST)
    print_report(res)
    return 1 if (res["modified"] or res["new"] or res["missing"]) else 0


# -------------------------------------------------------------------- main
def main():
    parser = argparse.ArgumentParser(description="File Integrity Checker")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("baseline", "create a baseline manifest"),
                            ("verify", "verify a folder against a manifest")):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("folder")
        sp.add_argument("-m", "--manifest", default=DEFAULT_MANIFEST)
    sub.add_parser("demo", help="run a tamper-detection simulation")
    args = parser.parse_args()

    if os.name == "nt":
        os.system("")  # enable ANSI colours in Windows terminals
    try:
        if args.command == "demo":
            return run_demo()
        if args.command == "baseline":
            manifest, errors = create_baseline(args.folder, args.manifest)
            print_baseline(manifest, errors, args.manifest)
            return 0
        res = verify_folder(args.folder, args.manifest)
        print_report(res)
        return 1 if (res["modified"] or res["new"] or res["missing"]
                     or res["unreadable"]) else 0
    except FileNotFoundError as err:
        print(f"Error: file or folder not found - {err.filename or err}")
    except NotADirectoryError as err:
        print(f"Error: {err}")
    except (json.JSONDecodeError, ValueError) as err:
        print(f"Error: the manifest is not valid - {err}")
    except PermissionError as err:
        print(f"Error: permission denied - {err}")
    return 2


if __name__ == "__main__":
    sys.exit(main())