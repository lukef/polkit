#!/usr/bin/env python3
"""Scenario suite for polkit-agent-helper-1's concurrent authentication stack.

Run it through run.sh, which puts it in a user+mount namespace with a throwaway
/etc/pam.d, passwd, shadow and group bind-mounted, so the host's PAM config is
never used. The "finger" is pam_test_finger.so, an in-process stand-in for
pam_fprintd: it takes time, asks nothing unless told to, may refuse, and
records what it saw (uid, dumpability, process group, signal state) to a trace.

The helper's final D-Bus report to polkitd cannot succeed from here, so a
request counts as authenticated when the helper got as far as making it.

    suite.py [--socket] <helper> <workdir> [case ...]     # cases by prefix: b1 c8 ...

--socket runs every case against the socket-activated helper instead of the setuid one.
"""
import os, select, signal, socket, subprocess, sys, time

ARGS = sys.argv[1:]
SOCKET = "--socket" in ARGS
if SOCKET:
    ARGS.remove("--socket")
HELPER, WORK = ARGS[0], ARGS[1]
ONLY = set(ARGS[2:])
PAMD = "/etc/pam.d"
USER, PASSWORD = "racer", "correct-horse"

PW_STACK = "auth required pam_unix.so\naccount required pam_unix.so\n"


def write(path, text, mode=0o644):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


def finger(name, delay, result, grandchild=False, prompt=False, account="account required pam_permit.so\n",
           faildelay_ms=0):
    """Concurrent stack built on the in-process test module."""
    trace = f"{WORK}/{name}.trace"
    if os.path.exists(trace):
        os.unlink(trace)
    opts = f"trace={trace} delay_ms={int(delay * 1000)} result={result}"
    if grandchild:
        opts += " grandchild"
    if prompt:
        opts += " prompt"
    if faildelay_ms:
        opts += f" faildelay_ms={faildelay_ms}"
    return f"auth required {WORK}/pam_test_finger.so {opts}\n{account}", trace


def configure(password_stack=PW_STACK, concurrent=None):
    for f in os.listdir(PAMD):
        os.unlink(os.path.join(PAMD, f))
    write(f"{PAMD}/polkit-1", password_stack)
    if concurrent is not None:
        write(f"{PAMD}/polkit-1-concurrent", concurrent)


def read_trace(trace):
    try:
        with open(trace) as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []


def run_helper(answers=(), cookie_line="test-cookie\n", argv_cookie=False, sigchld_ignored=False,
               timeout=60):
    """Runs one request. answers: (delay_s, text | None | ("signal", n)); None closes the
    agent's side for writing. In socket mode the helper gets --socket-activated and one end of
    a socketpair as stdin and stdout, and the user name goes first, as libpolkit-agent sends it."""
    pre = (lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN)) if sigchld_ignored else None
    if SOCKET:
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        p = subprocess.Popen([HELPER, "--socket-activated"], stdin=theirs, stdout=theirs,
                             stderr=subprocess.PIPE, preexec_fn=pre)
        theirs.close()
        to_helper = from_helper = ours.fileno()
        first = USER + "\n"
    else:
        ours = None
        args = [HELPER, USER] + (["test-cookie"] if argv_cookie else [])
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, preexec_fn=pre)
        to_helper, from_helper = p.stdin.fileno(), p.stdout.fileno()
        first = ""
    err_fd = p.stderr.fileno()
    start = time.monotonic()

    def send(text):
        try:
            os.write(to_helper, text.encode())
        except (BrokenPipeError, OSError):
            pass

    def close_write():
        try:
            if ours is not None:
                ours.shutdown(socket.SHUT_WR)
            else:
                p.stdin.close()
        except OSError:
            pass

    if not argv_cookie and cookie_line is not None:
        send(first + cookie_line)
    elif first:
        send(first)
    pending = list(answers)
    out, err, prompts, buf = [], b"", [], b""
    readers = {from_helper, err_fd}
    for fd in readers:
        os.set_blocking(fd, False)

    def stamp():
        return round(time.monotonic() - start, 2)

    def take(chunk):
        nonlocal buf
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.decode(errors="replace")
            out.append((stamp(), line))
            if line.startswith("PAM_PROMPT"):
                prompts.append(stamp())

    while True:
        now = time.monotonic() - start
        while pending and now >= pending[0][0]:
            _, text = pending.pop(0)
            if isinstance(text, tuple) and text[0] == "signal":
                p.send_signal(text[1])
            elif text is None:
                close_write()
            else:
                send(text)
        r, _, _ = select.select(list(readers), [], [], 0.02)
        for fd in r:
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            if not chunk:
                readers.discard(fd)
            elif fd == err_fd:
                err += chunk
            else:
                take(chunk)
        if p.poll() is not None and not readers:
            break
        if p.poll() is not None:
            # Gone; drain whatever is left without waiting on a socket peer that may be open.
            for fd in list(readers):
                try:
                    while True:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            break
                        err += chunk if fd == err_fd else b""
                        if fd != err_fd:
                            take(chunk)
                except (BlockingIOError, OSError):
                    pass
            break
        if now > timeout:
            p.kill(); p.wait()
            if ours is not None:
                ours.close()
            return dict(ok=None, elapsed=now, prompts=prompts, out=out, err=err.decode(errors="replace"),
                        timed_out=True)
    elapsed = time.monotonic() - start
    if ours is not None:
        ours.close()
    err = err.decode(errors="replace")
    return dict(ok="error response to PolicyKit daemon" in err, elapsed=elapsed, prompts=prompts,
                out=out, err=err, timed_out=False)


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def leftover_pids(trace_lines):
    pids = []
    for line in trace_lines:
        for tok in line.split():
            if tok.startswith("pid="):
                pids.append(int(tok[4:]))
        if line.startswith("grandchild "):
            pids.append(int(line.split()[1]))
    time.sleep(0.2)
    return [p for p in pids if pid_alive(p)]


RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(f"  {'ok  ' if cond else 'FAIL'} {detail}")


def sanitizer_clean(r):
    bad = [l for l in r["err"].splitlines()
           if "AddressSanitizer" in l or "runtime error:" in l or "LeakSanitizer" in l]
    return not bad, bad[:3]


CASES = []


def case(fn):
    CASES.append(fn)
    return fn


def common(name, r):
    if r.get("timed_out"):
        check(name, False, "helper timed out")
        return False
    clean, bad = sanitizer_clean(r)
    check(name, clean, "no sanitizer reports" if clean else f"sanitizer: {bad}")
    return True


# ---------------------------------------------------------------- no concurrent stack

@case
def a1_sequential_reader_blocks_password():
    # The arrangement this replaces: the reader ahead of pam_unix in polkit-1.
    # The typed password waits until the reader gives up (5s here; 30s with
    # pam_fprintd's default timeout).
    stack, trace = finger("a1", 5, 1)
    configure("auth sufficient " + stack.split("\n")[0].split(" ", 2)[2] + "\n" + PW_STACK)
    r = run_helper([(0.3, PASSWORD + "\n")], timeout=20)
    if common("a1", r):
        check("a1", r["ok"] and r["elapsed"] >= 5.0,
              f"password honoured only after the reader timed out ({r['elapsed']:.2f}s >= 5.0)")


@case
def b1_correct_password():
    configure()
    r = run_helper([(0.2, PASSWORD + "\n")])
    if common("b1", r):
        check("b1", r["ok"], f"authenticated ({r['elapsed']:.2f}s)")
        check("b1", len(r["prompts"]) == 1, f"one prompt ({len(r['prompts'])})")


@case
def b2_wrong_password():
    configure()
    r = run_helper([(0.2, "wrong\n")])
    if common("b2", r):
        check("b2", r["ok"] is False, "rejected")
        # pam_unix asks for 2s; libpam randomises a delay to 0.5-1.5 times that.
        check("b2", r["elapsed"] >= 1.0, f"paid the failure delay ({r['elapsed']:.2f}s >= 1.0)")


@case
def b3_cookie_in_argv():
    if SOCKET:
        print("  skip: the socket-activated helper takes no cookie in argv")
        return
    configure()
    r = run_helper([(0.2, PASSWORD + "\n")], argv_cookie=True)
    if common("b3", r):
        check("b3", r["ok"], "authenticated")


@case
def b4_empty_cookie():
    configure()
    r = run_helper([], cookie_line="\n", timeout=10)
    if common("b4", r):
        check("b4", r["ok"] is False and not r["prompts"], "refused before any prompt")


@case
def b5_agent_closes_stdin():
    configure()
    r = run_helper([(0.3, None)], timeout=10)
    if common("b5", r):
        check("b5", r["ok"] is False and r["elapsed"] < 5, f"failed promptly ({r['elapsed']:.2f}s)")


@case
def b6_overlong_answer():
    configure()
    r = run_helper([(0.2, "x" * 600 + "\n")], timeout=10)
    if common("b6", r):
        check("b6", r["ok"] is False, "600-byte answer refused")


@case
def b7_two_prompts_answered_together():
    # Two different prompts (the test module, then pam_unix). Both answers are
    # written in one go right after the first prompt: the second must be
    # served from the helper's own buffer, not lost to it.
    stack, trace = finger("b7", 0, 0, prompt=True)
    configure(stack.split("\n")[0] + "\n" + PW_STACK)
    r = run_helper([(0.3, "anything\n" + PASSWORD + "\n")])
    if common("b7", r):
        check("b7", r["ok"], f"authenticated, prompts={len(r['prompts'])}")
        check("b7", len(r["prompts"]) == 2, "both prompts were asked")


@case
def b8_cookie_and_password_together():
    # Cookie and password arrive in the same write, before any prompt.
    configure()
    r = run_helper([], cookie_line="test-cookie\n" + PASSWORD + "\n")
    if common("b8", r):
        check("b8", r["ok"], "authenticated from read-ahead")


# ---------------------------------------------------------------- concurrent stack

def starts(t):
    return [l for l in t if l.startswith("start")]


def field(line, key):
    for tok in line.split():
        if tok.startswith(key + "="):
            return tok[len(key) + 1:]
    return None


@case
def c1_password_while_finger_waits():
    stack, trace = finger("c1", 30, 0, grandchild=True)
    configure(concurrent=stack)
    r = run_helper([(0.5, PASSWORD + "\n")])
    if common("c1", r):
        t = read_trace(trace)
        st = starts(t)
        check("c1", r["ok"] and r["elapsed"] < 1.5, f"authenticated by password ({r['elapsed']:.2f}s)")
        check("c1", st and field(st[0], "uid") == "4242" and field(st[0], "euid") == "4242",
              f"concurrent stack ran as the user: {st[:1]}")
        check("c1", st and field(st[0], "dumpable") == "0", "concurrent child is non-dumpable")
        check("c1", st and field(st[0], "pgid") == field(st[0], "pid"), "concurrent child leads its own process group")
        left = leftover_pids(t)
        check("c1", not left, f"concurrent child and its grandchild killed (left: {left})")


@case
def c2_wrong_password_while_finger_waits():
    stack, trace = finger("c2", 30, 0, grandchild=True)
    configure(concurrent=stack)
    r = run_helper([(0.5, "wrong\n")])
    if common("c2", r):
        check("c2", r["ok"] is False, "rejected")
        check("c2", r["elapsed"] >= 1.5, f"paid the failure delay ({r['elapsed']:.2f}s >= 1.5)")
        check("c2", not leftover_pids(read_trace(trace)), "concurrent child and grandchild killed")


@case
def c3_finger_accepts_nobody_types():
    stack, trace = finger("c3", 2, 0, grandchild=True)
    configure(concurrent=stack)
    r = run_helper([])
    if common("c3", r):
        check("c3", r["ok"], "authenticated by finger")
        check("c3", 2.0 <= r["elapsed"] < 2.6,
              f"no failure delay after the win ({r['elapsed']:.2f}s, finger took 2.0)")
        check("c3", not leftover_pids(read_trace(trace)), "grandchild of the winner killed too")


@case
def c4_finger_refuses_slowly_then_password():
    stack, trace = finger("c4", 1.5, 1)
    configure(concurrent=stack)
    r = run_helper([(3.0, PASSWORD + "\n")])
    if common("c4", r):
        n = len(starts(read_trace(trace)))
        check("c4", r["ok"], f"authenticated by password ({r['elapsed']:.2f}s)")
        check("c4", n == 1, f"a slow refusal is not retried (starts={n})")


@case
def c5_finger_refuses_fast_is_retried():
    stack, trace = finger("c5", 0.05, 1)
    configure(concurrent=stack)
    r = run_helper([(5.0, PASSWORD + "\n")])
    if common("c5", r):
        n = len(starts(read_trace(trace)))
        check("c5", r["ok"], "authenticated by password")
        check("c5", n == 6, f"fast refusal retried, bounded (starts={n}, expect 6)")


@case
def c6_finger_accepts_account_denies():
    stack, trace = finger("c6", 1, 0, account="account required pam_deny.so\n")
    configure(concurrent=stack)
    r = run_helper([(4.0, PASSWORD + "\n")], timeout=15)
    if common("c6", r):
        t = read_trace(trace)
        check("c6", any(l.startswith("finish result=0") for l in t), "the finger did accept")
        check("c6", r["ok"] is False, f"a denied account is not let in by a finger ({r['elapsed']:.2f}s)")


@case
def c7_concurrent_stack_that_prompts():
    stack, trace = finger("c7", 0, 0, prompt=True)
    configure(concurrent=stack)
    r = run_helper([(1.0, PASSWORD + "\n")])
    if common("c7", r):
        t = read_trace(trace)
        check("c7", r["ok"], "password still works")
        check("c7", len(r["prompts"]) == 1, f"the agent saw only its own prompt ({len(r['prompts'])})")
        check("c7", any(l.startswith("prompt rc=") and l != "prompt rc=0" for l in t),
              f"the concurrent prompt was refused: {[l for l in t if 'prompt' in l][:1]}")


@case
def c8_win_refuses_later_prompts():
    # The first password module shrugs off a conversation error; the second
    # (the test module) then asks. After a win that question must be refused
    # by the helper, not shown to the agent, and the request must succeed.
    stack, trace = finger("c8", 1, 0)
    pw_stack, pw_trace = finger("c8pw", 0, 0, prompt=True)
    configure("auth [default=ignore] pam_unix.so\n" + pw_stack.split("\n")[0] + "\naccount required pam_unix.so\n",
              concurrent=stack)
    r = run_helper([])
    if common("c8", r):
        pt = read_trace(pw_trace)
        check("c8", r["ok"], f"authenticated by finger ({r['elapsed']:.2f}s)")
        check("c8", len(r["prompts"]) == 1, f"no second prompt reached the agent ({len(r['prompts'])})")
        check("c8", any(l.startswith("prompt rc=") and l != "prompt rc=0" for l in pt),
              f"the later prompt was refused by the helper: {[l for l in pt if 'prompt' in l][:1]}")
        check("c8", r["elapsed"] < 1.6, "no failure delay")


@case
def c9_inherited_sigchld_ignored():
    stack, trace = finger("c9", 1, 0)
    pw_stack, pw_trace = finger("c9pw", 0, 1)  # records parent state, then fails over to pam_unix
    configure("auth optional " + pw_stack.split("\n")[0].split(" ", 2)[2] + "\n" + PW_STACK, concurrent=stack)
    r = run_helper([], sigchld_ignored=True)
    if common("c9", r):
        check("c9", r["ok"], "finger win with SIGCHLD ignored by the invoker")
        SIGCHLD_BIT = 1 << (17 - 1)
        for who, tr in (("helper", pw_trace), ("concurrent child", trace)):
            st = starts(read_trace(tr))
            ign = int(field(st[0], "sigign"), 16) if st else None
            check("c9", ign is not None and not (ign & SIGCHLD_BIT),
                  f"{who} no longer ignores SIGCHLD (SigIgn={field(st[0], 'sigign') if st else '?'})")
    stack, trace = finger("c9b", 30, 0, grandchild=True)
    configure(concurrent=stack)
    r = run_helper([(0.5, PASSWORD + "\n")], sigchld_ignored=True)
    if common("c9", r):
        check("c9", r["ok"], "password win with SIGCHLD ignored")
        check("c9", not leftover_pids(read_trace(trace)), "concurrent child and grandchild killed")


@case
def c10_agent_closes_stdin_during_race():
    stack, trace = finger("c10", 30, 0, grandchild=True)
    configure(concurrent=stack)
    r = run_helper([(0.5, None)], timeout=10)
    if common("c10", r):
        check("c10", r["ok"] is False and r["elapsed"] < 3, f"failed promptly ({r['elapsed']:.2f}s)")
        check("c10", not leftover_pids(read_trace(trace)), "concurrent child and grandchild killed")


@case
def c11_password_and_finger_at_once():
    stack, trace = finger("c11", 1, 0)
    configure(concurrent=stack)
    r = run_helper([(1.0, PASSWORD + "\n")])
    if common("c11", r):
        check("c11", r["ok"], f"authenticated ({r['elapsed']:.2f}s)")


@case
def c12_finger_and_cookie_read_ahead():
    stack, trace = finger("c12", 30, 0)
    configure(concurrent=stack)
    r = run_helper([], cookie_line="test-cookie\n" + PASSWORD + "\n")
    if common("c12", r):
        check("c12", r["ok"] and r["elapsed"] < 1.5, "password buffered with the cookie is still seen by poll()")


@case
def c13_concurrent_module_missing():
    configure(concurrent=f"auth required {WORK}/does-not-exist.so\naccount required pam_permit.so\n")
    r = run_helper([(3.0, PASSWORD + "\n")])
    if common("c13", r):
        check("c13", r["ok"], f"password works ({r['elapsed']:.2f}s)")


@case
def c14_wrong_password_then_finger():
    # A wrong password ends the request (polkit-1 has no retry here); the
    # finger that would have accepted later must not resurrect it.
    stack, trace = finger("c14", 4, 0, grandchild=True)
    configure(concurrent=stack)
    r = run_helper([(0.3, "wrong\n")], timeout=15)
    if common("c14", r):
        check("c14", r["ok"] is False, f"rejected ({r['elapsed']:.2f}s)")
        check("c14", not leftover_pids(read_trace(trace)), "concurrent child killed")


@case
def c15_finger_wins_during_failure_delay():
    # Wrong password at 0.3s starts pam_unix's ~2s delay; the finger accepts at
    # 1s, inside it. The request was already lost to the password stack, so
    # it must stay rejected.
    stack, trace = finger("c15", 1, 0)
    configure(concurrent=stack)
    r = run_helper([(0.3, "wrong\n")], timeout=15)
    if common("c15", r):
        check("c15", r["ok"] is False, f"rejected ({r['elapsed']:.2f}s)")


@case
def c16_win_skips_a_registered_failure_delay():
    # The password stack registers a 3s failure delay before asking (as a PIN
    # or faillock-style module might). A finger win at 1s must not pay it; a
    # real failure must.
    stack, trace = finger("c16", 1, 0)
    pw_stack, pw_trace = finger("c16pw", 0, 0, prompt=True, faildelay_ms=3000)
    configure(pw_stack.split("\n")[0] + "\naccount required pam_unix.so\n", concurrent=stack)
    r = run_helper([])
    if common("c16", r):
        check("c16", r["ok"] and r["elapsed"] < 1.6, f"finger win skips the delay ({r['elapsed']:.2f}s)")
    configure(pw_stack.split("\n")[0].replace("result=0", "result=1") + "\naccount required pam_unix.so\n")
    r = run_helper([(0.2, "anything\n")], timeout=15)
    if common("c16", r):
        # At least half of the 3s asked for, after the answer at 0.2s: libpam
        # randomises a delay to 0.5-1.5 times the request.
        check("c16", r["ok"] is False and r["elapsed"] >= 1.7,
              f"a real failure still pays it ({r['elapsed']:.2f}s >= 1.7)")


@case
def c17_agent_cancels_mid_race():
    # A cancelled request: the agent sends the helper SIGTERM while the reader
    # waits. The concurrent child and anything it started must go with it.
    stack, trace = finger("c17", 30, 0, grandchild=True)
    configure(concurrent=stack)
    r = run_helper([(1.0, ("signal", signal.SIGTERM))], timeout=10)
    if common("c17", r):
        t = read_trace(trace)
        check("c17", r["ok"] is False and r["elapsed"] < 2, f"helper ended on SIGTERM ({r['elapsed']:.2f}s)")
        check("c17", starts(t), "the concurrent stack had started")
        left = leftover_pids(t)
        check("c17", not left, f"concurrent child and grandchild killed (left: {left})")


@case
def c18_helper_killed_mid_race():
    # SIGKILL cannot be caught; the parent-death signal must still take the
    # child down. (A grandchild survives this one: pam_fprintd starts none.)
    stack, trace = finger("c18", 30, 0)
    configure(concurrent=stack)
    r = run_helper([(1.0, ("signal", signal.SIGKILL))], timeout=10)
    if not r.get("timed_out"):
        t = read_trace(trace)
        check("c18", starts(t), "the concurrent stack had started")
        left = leftover_pids(t)
        check("c18", not left, f"concurrent child died with the helper (left: {left})")
    else:
        check("c18", False, "helper timed out")


@case
def c19_agent_hangs_up_mid_race():
    # SIGHUP, as from a dying session.
    stack, trace = finger("c19", 30, 0, grandchild=True)
    configure(concurrent=stack)
    r = run_helper([(1.0, ("signal", signal.SIGHUP))], timeout=10)
    if common("c19", r):
        check("c19", not leftover_pids(read_trace(trace)), "concurrent child and grandchild killed")


for fn in CASES:
    key = fn.__name__.split("_")[0]
    if ONLY and key not in ONLY:
        continue
    print(f"### {fn.__name__}")
    try:
        fn()
    except Exception as e:  # keep going
        check(key, False, f"exception: {e!r}")

failed = [r for r in RESULTS if not r[1]]
print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
sys.exit(1 if failed else 0)
