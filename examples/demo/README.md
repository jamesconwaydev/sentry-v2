# Demo: one failure, two denials, one memory hog

`run.sh` stages a small incident on a test VM and shows what Sentry-v2
makes of it. Two services are denied the same file at the same moment.
One of them dies. Sentry-v2 links the dying service to its own denial,
leaves the other denial out, and records the memory pressure around it.
Both policies are dry-run, so nothing is throttled or frozen.

![The demo running on a Rocky Linux 10 test VM](../../assets/demo.gif)

## Run it

You need a VM you don't mind poking, not a production host. It should run
EL10 with SELinux enforcing and PSI on, with `selinux-policy-devel`
installed and Sentry-v2 running (see [Installation](../../docs/installation.md)).

```console
# dnf install selinux-policy-devel
# examples/demo/run.sh
```

It takes about a minute, most of it spent building the SELinux module.
`PACE=0` drops the pauses between steps.

## What it does

1. Builds and loads `sentry_demo.te`. It defines two confined domains,
   `sentry_demo_app_t` and `sentry_demo_other_t`, and a file type neither
   may read.
2. Installs `90-demo.toml` into `/etc/sentry-v2/policies.d/` and reloads.
   `demo-app-failed` writes a bundle when a `demo-app-*` unit fails.
   `demo-memory-throttle` plans a throttle for a `demo-hog-*` unit under
   memory pressure. Both are `mode = "dry-run"`.
3. Starts `demo-hog-*`, which churns 80 MiB under `MemoryHigh=40M`, and
   waits for the pressure incident.
4. Starts `demo-other-*` and then `demo-app-*` in `sentry-test.slice`. Both
   try to read the demo file and are denied. The app exits 1 two seconds
   later; the other keeps running.
5. Prints the denials `ausearch` saw in that window, then the parts of
   each bundle worth reading in a terminal.

On exit, including Ctrl-C, it stops its units and removes the module, the
labelled files and the policy file. The bundles stay in
`/var/lib/sentry-v2/bundles/`.

## A captured run

These two bundles came from one run on a Rocky Linux 10.2 test VM. They
are unedited apart from the hostname and machine ID:

- [`incident-unit-failed.json`](incident-unit-failed.json): the app's
  failure. The audit log recorded its denial twice. The first scores 0.94
  (cgroup and name), the second 0.976, because by then the first had
  taught the correlator the unit's SELinux domain. There is
  no correlation for `sentry_demo_other_t`, though `ausearch` shows its
  denial in the same window. `context.psi` holds the pressure in the
  unit's slice at the time.
- [`incident-memory-pressure.json`](incident-memory-pressure.json): the
  hog's pressure incident and the throttle it would have applied,
  `memory_high = "80%"` and `cpu_weight = 50`, marked `dry_run`.

Why one denial is linked and the other isn't is set out in
[Correlation](../../docs/correlation.md#scoring). The integration test
`test_unrelated_denial_in_window_is_left_out` in
[`tests/integration/test_avc_correlation.py`](../../tests/integration/test_avc_correlation.py)
checks the same thing on every `make itest`: the unrelated denial lands
inside the window and still stays out of the bundle.
