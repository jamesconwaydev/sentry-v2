#!/usr/bin/env bash
# One failing service, two SELinux denials and a memory hog, on a test box.
#
#   sudo examples/demo/run.sh        (PACE=0 to skip the pauses)
#
# Needs root on an EL10 VM you don't mind poking, with SELinux enforcing,
# PSI on, selinux-policy-devel installed, and sentry-v2 running. Everything
# runs in sentry-test.slice and both demo policies are dry-run, so nothing
# is throttled or frozen. On exit, even on Ctrl-C, the script stops its
# units and removes its SELinux module, files and policy.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SLICE=sentry-test.slice
LIBEXEC=/usr/local/libexec
APP_BIN=$LIBEXEC/sentry-demo-app
OTHER_BIN=$LIBEXEC/sentry-demo-other
SECRET=$LIBEXEC/sentry-demo-secret
POLICY=/etc/sentry-v2/policies.d/90-demo.toml
SUFFIX=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
APP=demo-app-$SUFFIX.service
OTHER=demo-other-$SUFFIX.service
HOG=demo-hog-$SUFFIX.service

say() {
	printf '\n\033[1;36m# %s\033[0m\n' "$*"
	sleep "${PACE:-1.5}"
}
die() {
	echo "run.sh: $*" >&2
	exit 1
}

[ "$(id -u)" = 0 ] || die "run me as root"
[ "$(getenforce 2>/dev/null)" = Enforcing ] || die "SELinux has to be enforcing"
[ -e /usr/share/selinux/devel/Makefile ] || die "needs selinux-policy-devel (dnf install selinux-policy-devel)"
[ -e /proc/pressure/memory ] || die "PSI is off, see docs/installation.md#turn-on-psi"
sentry-v2ctl status >/dev/null || die "sentry-v2 isn't running (systemctl enable --now sentry-v2)"
[ ! -e "$POLICY" ] || die "$POLICY already exists; is another demo running?"

WORK=$(mktemp -d)
cleanup() {
	set +e
	for unit in "$APP" "$OTHER" "$HOG"; do
		systemctl stop "$unit" 2>/dev/null
		systemctl reset-failed "$unit" 2>/dev/null
	done
	if [ -e "$POLICY" ]; then
		rm -f "$POLICY"
		sentry-v2ctl reload >/dev/null
	fi
	rm -f "$APP_BIN" "$OTHER_BIN" "$SECRET"
	semodule -l | grep -qx sentry_demo && semodule -r sentry_demo >/dev/null 2>&1
	rm -rf "$WORK"
}
trap cleanup EXIT

# Print the id of the first incident of this kind for this unit.
wait_incident() {
	local unit=$1 kind=$2 tries=$(($3 * 4)) id
	while ((tries-- > 0)); do
		id=$(sentry-v2ctl --json incidents --unit "$unit" | python3 -c '
import json, sys
print(next((i["id"] for i in json.load(sys.stdin)["incidents"] if i["kind"] == sys.argv[1]), ""))
' "$kind")
		if [ -n "$id" ]; then
			echo "$id"
			return
		fi
		sleep 0.25
	done
	die "no $kind incident for $unit after $3 s"
}

# The part of a bundle worth reading in a terminal. argv[1] lists the
# domains that were denied in the window, to show which ones were left out.
read -r -d '' EXCERPT <<'PY' || true
import json, sys

b = json.load(sys.stdin)["bundle"]
inc = b["incident"]
print(f"incident   {inc['kind']}  {inc['target']}  severity={b['severity']}")
if inc["kind"] == "unit_failed":
    print(f"           result={inc['trigger'].get('result')}")
# One line per distinct denial, at its best score. A retried open is
# denied again, and the repeat also scores on the domain the first taught.
best = {}
for c in inc["correlations"]:
    a = c["avc"]
    key = (a["scontext_type"], " ".join(a["perms"]), a["tcontext"].split(":")[2], a["comm"])
    if key not in best or c["confidence"] > best[key]["confidence"]:
        best[key] = c
seen = {key[0] for key in best}
for (scontext, perms, tcontext, comm), c in best.items():
    print(f"linked     {scontext} denied {perms} on {tcontext} (comm {comm})")
    print(f"           confidence {c['confidence']}")
    for reason in c["reasons"]:
        print(f"             + {reason}")
for other in sys.argv[1].split():
    if other not in seen:
        print(f"left out   {other}: denied in the same window, scored below min_confidence")
for cgroup, res in b["context"]["psi"].items():
    if "memory" in res:
        m = res["memory"]["some"]
        print(f"pressure   {cgroup} memory some avg10={m['avg10']}")
for a in b["decision"]["actions"]:
    params = " ".join(f"{k}={v}" for k, v in a["params"].items())
    print(f"decision   {a['policy']}: {a['action']} {params}".rstrip() + f"  [{a['status']}]")
PY

say "Load a demo SELinux module: two domains, and a file neither may read"
cp "$HERE/sentry_demo.te" "$WORK/"
make -s -C "$WORK" -f /usr/share/selinux/devel/Makefile sentry_demo.pp >"$WORK/make.log" 2>&1 ||
	die "building the SELinux module failed: $(tail -5 "$WORK/make.log")"
semodule -i "$WORK/sentry_demo.pp"
cp /usr/bin/bash "$APP_BIN"
cp /usr/bin/bash "$OTHER_BIN"
echo "demo secret" >"$SECRET"
chcon -t sentry_demo_app_exec_t "$APP_BIN"
chcon -t sentry_demo_other_exec_t "$OTHER_BIN"
chcon -t sentry_demo_secret_t "$SECRET"
semodule -l | grep -x sentry_demo

say "Add two dry-run policies and reload"
install -m 0644 "$HERE/90-demo.toml" "$POLICY"
restorecon "$POLICY"
sentry-v2ctl reload
sentry-v2ctl policies | grep -E '^(POLICY|demo-)'

say "Start a memory hog: 80 MiB of churn under MemoryHigh=40M"
systemd-run --quiet --unit "$HOG" --slice "$SLICE" \
	-p MemoryHigh=40M -p MemorySwapMax=64M -p MemoryMax=96M -- python3 -c '
b = bytearray(80 << 20)
while True:
    for i in range(0, len(b), 4096):
        b[i] = (b[i] + 1) & 255
'
psi=$(wait_incident "$HOG" psi 60)
echo "pressure incident $psi"

say "Now two services hit SELinux at the same moment. Only one of them dies."
read -r sdate stime < <(LC_ALL=C date '+%x %T')
systemd-run --quiet --unit "$OTHER" --slice "$SLICE" -- \
	"$OTHER_BIN" -c "read -r line < $SECRET; sleep 30"
systemd-run --quiet --unit "$APP" --slice "$SLICE" -- \
	"$APP_BIN" -c "echo 'loading config'; read -r line < $SECRET; sleep 2; exit 1"
failed=$(wait_incident "$APP" unit_failed 30)
systemctl is-failed "$APP" || true

say "What the audit log saw in that window"
LC_ALL=C ausearch --input-logs -m AVC -ts "$sdate" "$stime" --raw 2>/dev/null |
	grep -o 'comm="[^"]*".*scontext=[^ ]*' | sed -E 's/comm="([^"]+)".*scontext=[^:]+:[^:]+:([^:]+):.*/denied  \2  (comm \1)/' |
	sort | uniq -c || true

say "What Sentry-v2 made of it: the failure"
sentry-v2ctl --json show "$failed" | python3 -c "$EXCERPT" "sentry_demo_app_t sentry_demo_other_t"

say "And the memory hog"
sentry-v2ctl --json show "$psi" | python3 -c "$EXCERPT" ""

say "Full bundles, still on disk after this script cleans up:"
echo "sentry-v2ctl show $failed"
echo "sentry-v2ctl show $psi"
