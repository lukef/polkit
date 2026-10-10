#!/usr/bin/env python3
"""Shows the suite would notice each protection going missing.

Builds polkit-agent-helper-1 once per mutant -- the PAM helper with one
protection removed -- from a configured meson build of the polkit fork, and runs
the suite cases that guard it. Every mutant should be caught.

    ./mutants.py <polkit-meson-builddir>

The patterns are exact lines of src/polkitagent/polkitagenthelper-pam.c; a
mutant whose pattern no longer matches is reported, not skipped silently.
"""
import json, os, shlex, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.abspath(sys.argv[1])
TARGET = "src/polkitagent/polkit-agent-helper-1"

MUTANTS = [
    # name, cases, [(pattern, replacement), ...]
    ("refuse prompts after a win", ["c8"],
     [("  if (conversation_data != NULL && conversation_data->concurrent_won)\n    return PAM_CONV_ERR;", "")]),
    ("skip the failure delay on a win", ["c16"],
     [("  if (conversation_data != NULL && conversation_data->concurrent_won)\n    return;", "")]),
    ("kill the whole process group", ["c1", "c3"], [("kill (-child, SIGKILL)", "kill (child, SIGKILL)")]),
    # Both sides, or neither: each makes the group so it exists whoever runs first.
    ("own process group", ["c1"], [("      setpgid (child, child);\n", ""), ("  setpgid (0, 0);\n", "")]),
    ("non-dumpable after the uid change", ["c1"],
     [("  if (!forbid_tracing ()\n      || getresuid", "  if (getresuid")]),
    ("account phase of a win", ["c6"], [("run_concurrent_account_check (user_to_auth)", "TRUE")]),
    ("retry a fast failure", ["c5"], [("attempt >= 5", "attempt >= 0")]),
    ("drop to the user", ["c1"], [("  if (!become_user_for_good (user_to_auth))", "  if (0)")]),
    ("reset inherited signals", ["c9"], [("  if (!reset_signal_state ())", "  if (0)")]),
    ("catch ending signals", ["c17", "c19"], [("  if (!catch_ending_signals ())", "  if (0)")]),
    ("die with the parent", ["c18"], [("  die_with_parent (parent);\n", "")]),
]


def main():
    entries = json.load(open(os.path.join(BUILD, "compile_commands.json")))
    entry = next(e for e in entries if e["file"].endswith("polkitagenthelper-pam.c")
                 and "polkit-agent-helper-1.p" in e["output"])
    source = os.path.normpath(os.path.join(BUILD, entry["file"]))
    original = open(source).read()
    link = subprocess.run(["ninja", "-C", BUILD, "-t", "commands", TARGET], capture_output=True,
                          text=True, check=True).stdout.strip().splitlines()[-1]
    missed = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, cases, edits in MUTANTS:
            if any(original.count(pattern) < 1 for pattern, _ in edits):
                print(f"?? {name}: pattern not found -- update mutants.py")
                missed.append(name)
                continue
            mutated = original
            for pattern, replacement in edits:
                mutated = mutated.replace(pattern, replacement, 1)
            src = os.path.join(tmp, "mutant.c")
            obj = os.path.join(tmp, "mutant.o")
            exe = os.path.join(tmp, "helper")
            open(src, "w").write(mutated)
            cmd = entry["command"].replace(entry["output"], obj).replace(entry["file"], src)
            cmd += " -I" + shlex.quote(os.path.dirname(source))
            # Quiet: a mutant often leaves a function unused, and says so.
            subprocess.run(cmd, shell=True, cwd=BUILD, check=True, stderr=subprocess.DEVNULL)
            subprocess.run(link.replace(entry["output"], obj).replace(f"-o {TARGET}", f"-o {exe}"),
                           shell=True, cwd=BUILD, check=True)
            r = subprocess.run([os.path.join(HERE, "run.sh"), exe] + cases, capture_output=True, text=True)
            caught = r.returncode != 0
            print(f"{'caught' if caught else 'MISSED'}  {name}  ({' '.join(cases)})")
            if not caught:
                missed.append(name)
    print(f"\n{len(MUTANTS) - len(missed)}/{len(MUTANTS)} mutants caught")
    sys.exit(1 if missed else 0)


main()
