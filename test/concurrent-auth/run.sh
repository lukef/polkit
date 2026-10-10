#!/bin/bash
# Runs suite.py against a polkit-agent-helper-1 in a throwaway user+mount
# namespace, so the host's PAM config is never touched.
#
#   ./run.sh [--socket] <helper> [case ...]
#
# --socket drives the helper as the socket-activated service does
# (--socket-activated, stdin and stdout on one socket).
#
# Needs subordinate ids for the user (/etc/subuid, /etc/subgid): the concurrent
# child drops to uid 4242, which a namespace mapping only root cannot do.
set -u
D="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
mode=()
if [[ ${1:-} == --socket ]]; then
	mode=(--socket)
	shift
fi
helper=$(realpath "${1:?usage: run.sh [--socket] <helper> [case ...]}"); shift

# World-traversable and sticky: the concurrent child runs as 4242 and must reach
# the test module and write its trace. /dev/shm because the scratch directories
# a session gets are mode 700.
W=$(mktemp -d /dev/shm/polkit-suite.XXXXXX)
trap 'rm -rf "$W"' EXIT
chmod 1777 "$W"
mkdir "$W/pam.d"
cc -shared -fPIC -Wall -Wextra -o "$W/pam_test_finger.so" "$D/pam_test_finger.c" -lpam || exit 1
chmod 755 "$W/pam_test_finger.so"

unshare -r --map-auto -m --propagation private -- /bin/bash -c '
  set -e
  mount --bind "$1/pam.d" /etc/pam.d
  mount --bind "$2/passwd" /etc/passwd
  mount --bind "$2/shadow" /etc/shadow
  mount --bind "$2/group"  /etc/group
  shift 2
  exec python3 -I "$@"' -- "$W" "$D" "$D/suite.py" "${mode[@]}" "$helper" "$W" "$@"
