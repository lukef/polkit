# Concurrent-authentication scenario suite

Tests `polkit-agent-helper-1` and its optional `polkit-1-concurrent` stack
against a throwaway `/etc/pam.d`, `passwd`, `shadow` and `group` inside an
unprivileged user namespace, so the host's PAM configuration and polkitd are
never involved.

    meson setup /tmp/pb . -Dintrospection=false
    ninja -C /tmp/pb src/polkitagent/polkit-agent-helper-1
    test/concurrent-auth/run.sh /tmp/pb/src/polkitagent/polkit-agent-helper-1
    test/concurrent-auth/run.sh --socket /tmp/pb/src/polkitagent/polkit-agent-helper-1
    test/concurrent-auth/run.sh /tmp/pb/src/polkitagent/polkit-agent-helper-1 c8 c17
    test/concurrent-auth/mutants.py /tmp/pb

- `run.sh` runs every case, or the ones named by prefix. `--socket` runs them
  against the socket-activated helper (`--socket-activated`, stdin and stdout on
  one socket, user name sent first) instead of the setuid one.
- `mutants.py` rebuilds the helper with each protection removed in turn and
  checks that the cases guarding it fail. All of them should be caught.
- For ASan/UBSan, configure a second build with
  `-Db_sanitize=address,undefined -Db_lundef=false`. Any sanitizer report fails
  the case.

What is in here:

- `suite.py` speaks the agent side of the helper protocol and times what comes
  back. The helper's final report to polkitd cannot succeed from a namespace,
  so a request counts as authenticated when the helper got as far as sending it.
- `pam_test_finger.c` stands in for `pam_fprintd`. It runs in-process, takes
  time, asks nothing unless told to, may refuse, can start a grandchild, and
  writes its uid, dumpability, process group and signal state to a trace.
  `run.sh` builds it fresh each run.
- `passwd`, `shadow`, `group` define the user `racer` (uid 4242, password
  `correct-horse`).

Requirements: subordinate ids for your user (`/etc/subuid`, `/etc/subgid`),
because the concurrent child drops to uid 4242, which a namespace that maps
only root cannot do. Python 3, a C compiler and the PAM headers.

Not covered: a real reader, polkitd and agent, and the systemd sandbox of
`polkit-agent-helper@.service`.
