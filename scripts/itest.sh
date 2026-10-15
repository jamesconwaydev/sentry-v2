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
# and started. Logs and audit records from the run end up in
# itest-artifacts/<timestamp>/ locally.
set -euo pipefail

HOST=${HOST:-rocky@198.211.115.158}
REMOTE_DIR=sentry-v2-itest
VENV=/tmp/sv2-venv
OUT=/tmp/sv2-itest-artifacts

teardown() {
	sudo systemctl stop sentry-v2 2>/dev/null || true
	sudo systemctl disable sentry-v2 2>/dev/null || true
	sudo rm -rf /run/systemd/system/sentry-v2.service.d
	sudo dnf remove -y -q sentry-v2 sentry-v2-selinux sentry-v2-cockpit || true
	sudo systemctl daemon-reload
	sudo systemctl reset-failed sentry-v2 2>/dev/null || true
	sudo rm -rf /etc/sentry-v2 /var/lib/sentry-v2 "$VENV"
}

remote() {
	cd ~/"$REMOTE_DIR"
	# a KEEP=1 run leaves the same version installed, which dnf would skip
	if rpm -q sentry-v2 >/dev/null; then teardown; fi
	make rpm >/tmp/sv2-rpmbuild.log 2>&1 || { tail -40 /tmp/sv2-rpmbuild.log; exit 1; }
	sudo dnf install -y -q rpmbuild/RPMS/noarch/sentry-v2-*.rpm
	if [ ! -x "$VENV/bin/pytest" ]; then
		python3 -m venv --system-site-packages "$VENV"
		"$VENV/bin/pip" install -q pytest
	fi

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
	sudo PYTHONDONTWRITEBYTECODE=1 SV2_SUITE_START="$sdate $stime" "$VENV/bin/pytest" -m integration tests/integration \
		-p no:cacheprovider -o addopts='' -v ${PYTEST_ARGS:-} || rc=$?

	rm -rf "$OUT" && mkdir -p "$OUT"
	# The redirects run as us on purpose, so the artifacts stay ours to copy.
	# shellcheck disable=SC2024
	{
		cp /tmp/sv2-rpmbuild.log "$OUT/rpmbuild.log"
		sudo journalctl -u sentry-v2 --since "@$epoch" --no-pager >"$OUT/journal.txt"
		sudo env LC_ALL=C ausearch --input-logs -i -m AVC,USER_AVC,SELINUX_ERR -ts "$sdate" "$stime" >"$OUT/avc.txt" 2>&1
		# systemd sends the USER_AVCs for refused D-Bus calls, so match on scontext
		grep sentry_v2_t "$OUT/avc.txt" >"$OUT/avc-sentry_v2_t.txt"
		systemctl show sentry-v2 -p CapabilityBoundingSet,ActiveState,NRestarts >"$OUT/unit.txt"
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
# shellcheck disable=SC2029
rsync -a "$HOST:$OUT/" "$dest/" && ssh "$HOST" "rm -rf $OUT"
echo "artifacts in $dest"
exit "$rc"
