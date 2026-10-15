#!/usr/bin/env bash
# Runs the integration suite on the Rocky 10 host.
#
# From a checkout:  scripts/itest.sh            (or `make itest`)
#   HOST=user@host  the test host (default rocky@198.211.115.158)
#   KEEP=1          leave the daemon, RPMs and config installed afterwards
#   PYTEST_ARGS     extra pytest arguments, e.g. "-k throttle"
#
# The tree is copied to ~/sentry-v2-itest on the host, the RPMs are built
# there with `make rpm`, installed, configured from tests/integration/config
# and started. The pytest virtualenv, the build log and the artifacts live
# in a private mktemp directory inside that tree, never under a fixed /tmp
# name, and the only binary sudo runs from it is that venv's pytest. Logs
# and audit records from the run end up in itest-artifacts/<timestamp>/
# locally. Without KEEP=1 the host is left as it was found, apart from the
# RPM build dependencies.
set -euo pipefail

HOST=${HOST:-rocky@198.211.115.158}
REMOTE_DIR=sentry-v2-itest

teardown() {
	sudo systemctl stop sentry-v2 2>/dev/null || true
	sudo systemctl disable sentry-v2 2>/dev/null || true
	sudo rm -rf /run/systemd/system/sentry-v2.service.d
	sudo dnf remove -y -q sentry-v2 sentry-v2-selinux sentry-v2-cockpit || true
	sudo systemctl daemon-reload
	sudo systemctl reset-failed sentry-v2 2>/dev/null || true
	# The tests' units are gone, but their slices outlive them until stopped.
	# sentry.slice is only ours to stop if sentry-test.slice was all it held.
	sudo systemctl stop sentry-test.slice 2>/dev/null || true
	local parent=/sys/fs/cgroup/sentry.slice
	if [ -d "$parent" ] && [ ! -s "$parent/cgroup.procs" ] &&
		[ -z "$(find "$parent" -mindepth 1 -maxdepth 1 -type d)" ]; then
		sudo systemctl stop sentry.slice 2>/dev/null || true
	fi
	sudo rm -rf /etc/sentry-v2 /var/lib/sentry-v2
	# the RPM creates these from its sysusers.d file and dnf leaves them
	sudo groupdel sentry-v2-admin 2>/dev/null || true
	sudo groupdel sentry-v2 2>/dev/null || true
}

remote() {
	cd ~/"$REMOTE_DIR"
	# Private to us: the home directory and mktemp's 0700 keep others out of
	# the venv that sudo runs pytest from.
	local work venv out
	work=$(mktemp -d "$PWD/.itest-XXXXXX")
	venv=$work/venv
	out=$work/artifacts
	mkdir "$out"

	# a KEEP=1 run leaves the same version installed, which dnf would skip
	if rpm -q sentry-v2 >/dev/null; then teardown; fi
	make rpm >"$out/rpmbuild.log" 2>&1 || { tail -40 "$out/rpmbuild.log"; exit 1; }
	sudo dnf install -y -q rpmbuild/RPMS/noarch/sentry-v2-*.rpm
	python3 -m venv --system-site-packages "$venv"
	"$venv/bin/pip" install -q pytest

	sudo rm -f /etc/sentry-v2/policies.d/*.toml
	sudo install -m 0644 tests/integration/config/sentry-v2.toml /etc/sentry-v2/
	sudo install -m 0644 tests/integration/config/policies.d/*.toml /etc/sentry-v2/policies.d/
	sudo restorecon -R /etc/sentry-v2

	# ausearch parses -ts with the locale's date format, so pin both to C
	local sdate stime epoch rc=0
	read -r sdate stime < <(LC_ALL=C date '+%x %T')
	epoch=$(date +%s)
	sudo systemctl start sentry-v2
	# shellcheck disable=SC2086 # PYTEST_ARGS is a list of words on purpose
	sudo PYTHONDONTWRITEBYTECODE=1 SV2_SUITE_START="$sdate $stime" "$venv/bin/pytest" \
		-m integration tests/integration -p no:cacheprovider -o addopts='' -v ${PYTEST_ARGS:-} || rc=$?

	# The redirects run as us on purpose, so the artifacts stay ours to copy.
	# shellcheck disable=SC2024
	{
		sudo journalctl -u sentry-v2 --since "@$epoch" --no-pager >"$out/journal.txt"
		sudo env LC_ALL=C ausearch --input-logs -i -m AVC,USER_AVC,SELINUX_ERR -ts "$sdate" "$stime" >"$out/avc.txt" 2>&1
		# systemd sends the USER_AVCs for refused D-Bus calls, so match on scontext
		grep sentry_v2_t "$out/avc.txt" >"$out/avc-sentry_v2_t.txt"
		systemctl show sentry-v2 -p CapabilityBoundingSet,ActiveState,NRestarts >"$out/unit.txt"
	} || true

	[ "${KEEP:-0}" = 1 ] || teardown
	return "$rc"
}

if [ "${1:-}" = --remote ]; then
	remote
	exit
fi

cd "$(dirname "$0")/.."
rsync -a --delete --exclude .git --exclude .venv --exclude rpmbuild --exclude itest-artifacts \
	--exclude __pycache__ ./ "$HOST:$REMOTE_DIR/"
rc=0
# shellcheck disable=SC2029 # expanding here, on the client, is the point
ssh "$HOST" "KEEP=${KEEP:-0} PYTEST_ARGS='${PYTEST_ARGS:-}' bash $REMOTE_DIR/scripts/itest.sh --remote" || rc=$?
dest=itest-artifacts/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$dest"
# rsync --delete removed any older run's directory, so this matches one
rsync -a "$HOST:$REMOTE_DIR/.itest-*/artifacts/" "$dest/" || true
if [ "${KEEP:-0}" != 1 ]; then
	# shellcheck disable=SC2029
	ssh "$HOST" "rm -rf ~/$REMOTE_DIR"
fi
echo "artifacts in $dest"
exit "$rc"
