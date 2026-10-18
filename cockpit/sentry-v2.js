/* Sentry-v2 page for Cockpit: talks to the daemon's control socket.
 * Protocol: newline-delimited JSON, {"id", "cmd", "args"} -> {"id", "ok", ...}. */

/* global cockpit */

const SOCKET = "/run/sentry-v2/control.sock";
const POLL_MS = 5000;
const CALL_TIMEOUT_MS = 15000;

const main = document.getElementById("main");
const announcer = document.getElementById("announce");

// ---------------------------------------------------------------------------
// Theme: Cockpit's shell stores the choice in localStorage "shell:style" and
// tells open frames with a "cockpit-style" event. Mirror its own logic.

function applyTheme(style) {
    style = style || safeStorage("shell:style") || "auto";
    const systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const dark = style === "dark" || (style === "auto" && systemDark);
    document.documentElement.classList.toggle("pf-v6-theme-dark", dark);
}

function safeStorage(key) {
    try {
        return window.localStorage.getItem(key);
    } catch {
        return null;
    }
}

window.addEventListener("storage", ev => { if (ev.key === "shell:style") applyTheme(); });
window.addEventListener("cockpit-style", ev => applyTheme(ev.detail?.style));
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => applyTheme());
applyTheme();

// ---------------------------------------------------------------------------
// Control socket client

class DaemonError extends Error {
    constructor(message, problem) {
        super(message);
        this.problem = problem; // cockpit channel problem code, or null for ok:false
    }
}

/** Calls `onLine` with each parsed JSON line received on `channel`. */
function readLines(channel, onLine) {
    let buffer = "";
    channel.addEventListener("message", (_ev, data) => {
        buffer += data;
        let nl;
        while ((nl = buffer.indexOf("\n")) >= 0) {
            const line = buffer.slice(0, nl).trim();
            buffer = buffer.slice(nl + 1);
            if (!line) continue;
            let msg;
            try {
                msg = JSON.parse(line);
            } catch (e) {
                console.warn("sentry-v2: unreadable line from daemon", e);
                continue;
            }
            onLine(msg);
        }
    });
}

function openChannel() {
    return cockpit.channel({ payload: "stream", unix: SOCKET, superuser: "try" });
}

const client = {
    channel: null,
    pending: new Map(),
    nextId: 1,

    call(cmd, args = {}) {
        if (!this.channel) this.connect();
        const id = this.nextId++;
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                if (this.pending.delete(id))
                    reject(new DaemonError("Sentry-v2 didn't answer within 15 seconds", "timeout"));
            }, CALL_TIMEOUT_MS);
            this.pending.set(id, { resolve, reject, timer });
            this.channel.send(JSON.stringify({ id, cmd, args }) + "\n");
        });
    },

    connect() {
        const channel = openChannel();
        this.channel = channel;
        readLines(channel, msg => {
            const waiter = this.pending.get(msg.id);
            if (!waiter) return;
            this.pending.delete(msg.id);
            clearTimeout(waiter.timer);
            if (msg.ok) waiter.resolve(msg.result);
            else waiter.reject(new DaemonError(msg.error || "the daemon refused the request", null));
        });
        // The daemon closes idle connections; the next call simply reconnects.
        channel.addEventListener("close", (_ev, options) => {
            if (this.channel === channel) this.channel = null;
            const problem = options?.problem || "disconnected";
            for (const waiter of this.pending.values()) {
                clearTimeout(waiter.timer);
                waiter.reject(new DaemonError(options?.message || problem, problem));
            }
            this.pending.clear();
        });
    },
};

/** Keep a subscribe stream open. `onEvent` gets every pushed event;
 * `onReconnect` runs after each successful resubscribe, to catch up on what was missed. */
function subscribe(onEvent, onReconnect) {
    let retry = 2000;
    let everConnected = false;
    const start = () => {
        const channel = openChannel();
        let up = false;
        const connected = () => {
            if (up) return;
            up = true;
            retry = 2000;
            if (everConnected) onReconnect();
            everConnected = true;
        };
        channel.addEventListener("ready", connected);
        readLines(channel, msg => {
            connected();
            if (msg.event) onEvent(msg.event);
        });
        channel.addEventListener("close", () => {
            setTimeout(start, retry);
            retry = Math.min(retry * 2, 60000);
        });
        channel.send(JSON.stringify({ id: "subscribe", cmd: "subscribe", args: {} }) + "\n");
    };
    start();
}

// ---------------------------------------------------------------------------
// DOM helpers. Everything from the daemon goes in as text, never as markup.

function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
        if (value === null || value === undefined || value === false) continue;
        if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
        else if (key === "class") el.className = value;
        else el.setAttribute(key, value === true ? "" : value);
    }
    for (const child of children.flat(Infinity)) {
        if (child === null || child === undefined || child === false) continue;
        el.append(child instanceof Node ? child : String(child));
    }
    return el;
}

function announce(text) {
    announcer.textContent = "";
    // Clearing first makes screen readers repeat an identical message too.
    setTimeout(() => { announcer.textContent = text; }, 50);
}

function table(caption, headers, rows) {
    return h("div", { class: "table-wrap" },
        h("table", null,
            h("caption", { class: "sr-only" }, caption),
            h("thead", null, h("tr", null, headers.map(([label, cls]) =>
                h("th", { scope: "col", class: cls }, label || h("span", { class: "sr-only" }, "Actions"))))),
            h("tbody", null, rows)));
}

function facts(pairs) {
    return h("dl", { class: "facts" }, pairs
        .filter(([, v]) => v !== null && v !== undefined && v !== "")
        .map(([k, v]) => [h("dt", null, k), h("dd", null, v)]));
}

let headingSeq = 0;

/** A titled card. `key` makes the heading a focus target: [data-heading=key]. */
function card(title, body, extra, key) {
    const id = `card-${++headingSeq}`;
    return h("section", { class: "card", "aria-labelledby": id },
        h("div", { class: "card-head" },
            h("h2", { id, "data-heading": key, tabindex: key ? "-1" : null }, title), extra),
        body);
}

function alertBox(kind, title, text, action) {
    return h("div", { class: `alert ${kind}` },
        h("div", null, h("h2", null, title), text && h("p", null, text)), action);
}

// ---------------------------------------------------------------------------
// Formatting. Every helper copes with missing fields, so a partial record
// renders a dash rather than "undefined".

const KIND_LABELS = { unit_failed: "Unit failed", psi: "Pressure", avc: "SELinux denial", alert: "Alert" };
const STATUS_LABELS = {
    planned: "Planned", applied: "Applied", rolled_back: "Rolled back", failed: "Failed",
    rollback_failed: "Rollback failed", dry_run: "Dry run only",
};
const STATUS_CLASS = { applied: "warning", failed: "danger", rollback_failed: "danger", rolled_back: "ok", dry_run: "info" };
const SEVERITY_CLASS = { critical: "danger", warning: "warning", info: "info" };
const COLLECTOR_LABELS = { psi: "PSI", journal: "Journal", audit: "SELinux audit" };
const ROLLBACK_STATUSES = new Set(["applied", "planned"]);

const isNum = v => typeof v === "number" && Number.isFinite(v);
const dash = v => (v === null || v === undefined || v === "" ? "–" : String(v));
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const capitalise = s => (s ? String(s)[0].toUpperCase() + String(s).slice(1) : "");
const modeLabel = m => (m === "dry-run" ? "Dry run" : m === "enforce" ? "Enforce" : capitalise(m) || "Unknown");
const kindLabel = k => KIND_LABELS[k] || capitalise(k) || "Unknown";
const fixed = v => (isNum(v) ? v.toFixed(1) : "–");
const describe = rec => `${rec.action || "action"} on ${rec.target || "an unknown target"}`;

function when(value) {
    if (value === null || value === undefined || value === "") return "–";
    const d = typeof value === "number" ? new Date(value * 1000) : new Date(value);
    return isNaN(d) ? String(value) : d.toLocaleString();
}

function relative(epochSeconds) {
    if (!isNum(epochSeconds)) return "–";
    const mins = Math.round((epochSeconds * 1000 - Date.now()) / 60000);
    if (Math.abs(mins) < 1) return "now";
    const span = Math.abs(mins) < 120 ? `${Math.abs(mins)} min` : `${Math.round(Math.abs(mins) / 60)} h`;
    return mins > 0 ? `in ${span}` : `${span} ago`;
}

function duration(seconds) {
    if (!isNum(seconds)) return null;
    const d = Math.floor(seconds / 86400);
    const hrs = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d) return `${d} d ${hrs} h`;
    if (hrs) return `${hrs} h ${m} min`;
    return `${m} min`;
}

const statusLabel = s => h("span", { class: `label ${STATUS_CLASS[s] || ""}` }, STATUS_LABELS[s] || capitalise(s) || "Unknown");
const severityLabel = s => h("span", { class: `label ${SEVERITY_CLASS[s] || ""}` }, capitalise(s) || "Unknown");

// ---------------------------------------------------------------------------
// Failure states

function explainFailure(err) {
    const problem = err?.problem;
    if (problem === "not-found")
        return h("section", { class: "card empty" },
            h("h2", null, "Sentry-v2 isn't running"),
            h("p", null, `Nothing is listening on its control socket, ${SOCKET}. Start the service and this page picks it up within a few seconds.`),
            h("p", null, h("code", null, "systemctl start sentry-v2")),
            h("p", { class: "muted" }, "If it stopped by itself, check why with journalctl -u sentry-v2."));
    if (problem === "access-denied" || problem === "not-authorized")
        return h("section", { class: "card empty" },
            h("h2", null, "You don't have access to Sentry-v2"),
            h("p", null, "Reading its status needs administrative access, or membership of the sentry-v2 group. Turn on administrative access from the top bar, or log in as a user who has it."));
    return h("section", { class: "card empty" },
        h("h2", null, "Couldn't reach Sentry-v2"),
        h("p", null, `The connection to ${SOCKET} failed: ${err?.message || err}.`),
        h("p", null, "Check that the service is running with systemctl status sentry-v2. This page keeps trying in the meantime."));
}

/** Message for a failed mutation (rollback, pause, reload): what went wrong and what to do. */
function mutationError(verb, err) {
    const text = String(err?.message || err).trim().replace(/\.+$/, "");
    const hint = text.toLowerCase().startsWith("permission denied") || err?.problem === "access-denied"
        ? " Changing Sentry-v2 needs administrative access or the sentry-v2-admin group."
        : "";
    return `Couldn't ${verb}: ${text}.${hint}`;
}

// ---------------------------------------------------------------------------
// Views. Each returns {node, refresh, poll?, live?}. A refresh only replaces
// sections whose data changed, so keyboard focus survives the poll.

let errorSlot = null;
let shownError = null;

function showError(text) {
    // Skip re-rendering (and re-announcing) an identical error; clearing always works.
    if (!errorSlot || (text && text === shownError)) return;
    shownError = text;
    errorSlot.replaceChildren(text ? h("div", { class: "alert danger", role: "alert" },
        h("div", null, h("h2", null, "That didn't work"), h("p", null, text)),
        h("button", { class: "link", type: "button", onclick: () => showError(null) }, "Dismiss")) : "");
}

function slot() {
    const el = h("div");
    let last = null;
    return {
        el,
        set(data, render) {
            const key = JSON.stringify(data);
            if (key === last) return;
            last = key;
            el.replaceChildren(render(data));
        },
        reset() { last = null; },
    };
}

/** Focus the first match, or the main region if the control went away. */
function focusOr(root, selector) {
    (root.querySelector(selector) || main).focus();
}

// Overview -------------------------------------------------------------------

/** Records whose rollback failed: the latest record per id, active ones last so they win. */
function rollbackFailures(actions) {
    const byId = new Map();
    const recent = [...(actions?.recent || [])].sort((a, b) => (a.ts ?? 0) - (b.ts ?? 0));
    for (const rec of [...recent, ...(actions?.active || [])]) if (rec?.id) byId.set(rec.id, rec);
    return [...byId.values()].filter(rec => rec.status === "rollback_failed");
}

function overviewView() {
    const banners = slot();
    const summary = slot();
    const attention = slot();
    const held = slot();
    const actions = slot();
    const pressure = slot();
    let confirming = null; // {section, id} of a rollback awaiting confirmation
    let latest = { active: [], failed: [] };

    async function refresh() {
        const [status, psi, recorded] = await Promise.all([
            client.call("status"), client.call("psi"), client.call("actions")]);
        latest = {
            active: (status.active_actions || []).filter(rec => rec.status !== "rollback_failed"),
            failed: rollbackFailures(recorded),
        };
        banners.set({ mode: status.mode, paused: status.paused, breaker: status.breaker, err: status.last_reload_error }, renderBanners);
        summary.set(status, renderSummary);
        held.set(status.held || [], renderHeld);
        if (confirming === null) renderRecords();
        pressure.set(psi?.cgroups, renderPressure);
    }

    function renderRecords() {
        attention.set(latest.failed, renderAttention);
        actions.set(latest.active, renderActions);
    }

    async function mutate(cmd, verb, done) {
        shownError = null; // a repeated manual failure should be announced again
        try {
            await client.call(cmd);
            showError(null);
            announce(done);
            await refresh();
        } catch (e) {
            showError(mutationError(verb, e));
        }
        // Pause and Resume replace each other; keep focus on whichever is there now.
        focusOr(banners.el, '[data-key="pause"]');
    }

    const pauseButton = () => h("button", { type: "button", "data-key": "pause",
        onclick: () => mutate("pause", "pause remediation", "Remediation paused.") }, "Pause remediation");

    function renderBanners({ mode, paused, breaker, err }) {
        const out = [];
        if (paused)
            out.push(alertBox("warning", "Remediation is paused",
                "Sentry-v2 is still watching and recording incidents, but won't apply any actions until you resume it.",
                h("button", { class: "primary", type: "button", "data-key": "pause",
                    onclick: () => mutate("resume", "resume remediation", "Remediation resumed.") }, "Resume")));
        if (breaker?.open)
            out.push(alertBox("danger", "Too many actions failed, so Sentry-v2 switched to dry run",
                `${capitalise(plural(breaker.failures ?? 0, "recent failure"))} opened the breaker. It closes ${isNum(breaker.until) ? relative(breaker.until) : "after the cooldown"}, and every action until then is recorded but not applied.`));
        if (err)
            out.push(h("div", { class: "alert danger" },
                h("div", null, h("h2", null, "The last configuration reload failed"),
                    h("p", null, "Sentry-v2 is still running the configuration it had before. Fix the error, then reload on the Policies page."),
                    h("pre", null, err))));
        if (!paused && !breaker?.open && mode === "dry-run")
            out.push(alertBox("info", "Dry run",
                "Sentry-v2 records what it would do and changes nothing on this system."));
        if (!paused && !breaker?.open && mode !== "dry-run")
            out.push(alertBox("warning", "Enforcing",
                "Policies set to enforce act on this system when they trigger. Throttles and freezes undo themselves when their time runs out.",
                pauseButton()));
        return h("div", { class: "stack" }, out);
    }

    function renderSummary(s) {
        const failures = s.breaker?.failures ?? 0;
        const breaker = s.breaker?.open
            ? h("span", { class: "label danger" }, `Open, ${plural(failures, "failure")}`)
            : h("span", { class: "label ok" }, failures ? `Closed, ${plural(failures, "recent failure")}` : "Closed");
        const delivery = Object.entries(s.sinks?.failures || {}).filter(([, n]) => n)
            .map(([sink, n]) => `${sink}: ${n} failed${s.sinks?.dropped?.[sink] ? `, ${s.sinks.dropped[sink]} dropped` : ""}`);
        const dropped = Object.entries(s.events_dropped || {}).filter(([, n]) => n).map(([c, n]) => `${c}: ${n}`);
        const daemon = card("Daemon", facts([
            ["Mode", modeLabel(s.mode) + (s.paused ? ", paused" : "")],
            ["Breaker", breaker],
            ["Version", s.version],
            ["Running for", duration(s.uptime_s)],
            ["Delivery problems", delivery.join("; ") || "None"],
            ["Events dropped", dropped.join("; ") || "None"],
        ]));
        const rows = Object.entries(s.collectors || {}).map(([name, raw]) => {
            const health = raw && typeof raw === "object" ? raw : { state: raw };
            const { state, error, hint, ...rest } = health;
            const shown = error ? "error" : state ? String(state) : rest.source === null ? "no source" : "ok";
            const cls = shown === "ok" || shown === "running" ? "ok" : shown === "disabled" || shown === "no source" ? "warning" : "danger";
            const details = [error, hint, ...Object.entries(rest).map(([k, v]) => `${k.replace(/_/g, " ")}: ${dash(v)}`)].filter(Boolean);
            return h("tr", null,
                h("th", { scope: "row" }, COLLECTOR_LABELS[name] || capitalise(name)),
                h("td", null, h("span", { class: `label ${cls}` }, shown === "ok" ? "OK" : capitalise(shown))),
                h("td", { class: "muted" }, details.join(", ")));
        });
        const collectors = card("Collectors", rows.length
            ? table("Collector health", [["Collector"], ["State"], ["Details"]], rows)
            : h("p", { class: "muted" }, "No collectors reported."));
        return h("div", { class: "grid" }, daemon, collectors);
    }

    /** The Roll back / Retry control for one record, with its inline confirmation. */
    function rollbackCell(rec, section, label, question) {
        const key = `${section}:${rec.id}`;
        if (confirming?.section === section && confirming.id === rec.id)
            return h("td", { class: "fit" },
                h("div", { class: "actions-inline", role: "group", "aria-label": question,
                    onkeydown: ev => { if (ev.key === "Escape") { ev.preventDefault(); setConfirming(null, key); } } },
                h("span", null, question),
                h("button", { class: "danger", type: "button", "data-focus": "confirm", onclick: () => rollback(rec) }, label),
                h("button", { class: "link", type: "button", onclick: () => setConfirming(null, key) }, "Cancel")));
        return h("td", { class: "fit" },
            h("button", { type: "button", "data-row": key, "aria-label": `${label}: ${describe(rec)}`,
                onclick: () => setConfirming({ section, id: rec.id }) }, label));
    }

    const isConfirming = (section, rec) => confirming?.section === section && confirming.id === rec.id;

    function renderAttention(list) {
        if (!list.length) return "";
        const rows = list.map(rec => h("tr", { class: isConfirming("attention", rec) ? "confirming" : null },
            h("th", { scope: "row" }, dash(rec.target)),
            h("td", null, dash(rec.action), h("div", { class: "muted" }, rec.policy)),
            h("td", null, dash(rec.error)),
            h("td", null, when(rec.ts)),
            rollbackCell(rec, "attention", "Retry", `Retry rolling back ${describe(rec)}?`)));
        const section = card("Needs attention", [
            h("p", { class: "lead" }, "Sentry-v2 couldn't undo these actions. Each unit is left as it is, still throttled or frozen, until someone retries the rollback."),
            table("Rollbacks that failed", [["Target"], ["Action"], ["Error"], ["Failed"], ["", "fit"]], rows),
        ], null, "attention");
        section.classList.add("attention");
        return section;
    }

    function renderHeld(list) {
        if (!list.length) return "";
        const rows = list.map(u => h("tr", null,
            h("th", { scope: "row" }, dash(u.unit)),
            h("td", null, when(u.since)),
            h("td", { class: "fit" }, h("button", { type: "button", "data-unit": u.unit,
                "aria-label": `Allow actions on ${u.unit} again`, onclick: () => ack(u.unit) }, "Allow actions again"))));
        const section = card("Held for acting too often", [
            h("p", { class: "lead" }, "Sentry-v2 kept acting on these units, so it stopped. Whatever it last did still expires on schedule, but nothing new touches them until you allow it. Look at why they keep coming back first."),
            table("Held units", [["Unit"], ["Held"], ["", "fit"]], rows),
        ], null, "held");
        section.classList.add("attention");
        return section;
    }

    async function ack(unit) {
        shownError = null;
        try {
            await client.call("ack", { unit });
            showError(null);
            announce(`Actions on ${unit} are allowed again.`);
        } catch (e) {
            showError(mutationError(`allow actions on ${unit}`, e));
        }
        held.reset();
        await refresh().catch(() => {});
        focusOr(node, '[data-heading="actions"]');
    }

    function renderActions(list) {
        if (!list.length)
            return card("Active actions", h("p", { class: "muted" }, "Nothing is throttled or frozen right now."), null, "actions");
        const rows = list.map(rec => h("tr", { class: isConfirming("active", rec) ? "confirming" : null },
            h("th", { scope: "row" }, dash(rec.target)),
            h("td", null, dash(rec.action), h("div", { class: "muted" }, rec.policy)),
            h("td", null, statusLabel(rec.status), h("div", { class: "muted" }, modeLabel(rec.mode))),
            h("td", null, when(rec.applied_at)),
            h("td", null, relative(rec.expires_at)),
            ROLLBACK_STATUSES.has(rec.status)
                ? rollbackCell(rec, "active", "Roll back", `Roll back ${describe(rec)}?`)
                : h("td", { class: "fit" })));
        return card("Active actions", table("Active actions",
            [["Target"], ["Action"], ["Status"], ["Applied"], ["Rolls back"], ["", "fit"]], rows), null, "actions");
    }

    /** Open (target set) or close (returnTo = the row key to refocus) the inline confirmation. */
    function setConfirming(target, returnTo) {
        confirming = target;
        attention.reset();
        actions.reset();
        renderRecords();
        if (target) focusOr(node, '[data-focus="confirm"]');
        else focusOr(node, `[data-row="${CSS.escape(returnTo)}"]`);
    }

    async function rollback(rec) {
        confirming = null;
        shownError = null;
        try {
            const res = await client.call("rollback", { id: rec.id });
            showError(null);
            announce(res?.rolled_back?.length ? `Rolled back ${describe(rec)}.` : "Nothing needed rolling back.");
        } catch (e) {
            showError(mutationError(`roll back ${describe(rec)}`, e));
        }
        attention.reset();
        actions.reset();
        await refresh().catch(() => renderRecords());
        focusOr(node, '[data-heading="actions"]');
    }

    function renderPressure(cgroups) {
        if (!cgroups?.length)
            return card("Pressure", h("p", { class: "muted" }, "No cgroups are being watched. Add a PSI policy to watch one."));
        const sorted = [...cgroups].sort((a, b) => (isNum(b.avg10) ? b.avg10 : -1) - (isNum(a.avg10) ? a.avg10 : -1));
        const rows = sorted.map(c => {
            const clamp = v => (isNum(v) ? Math.max(0, Math.min(100, v)) : 0);
            const level = !isNum(c.avg10) ? "" : c.avg10 >= 40 ? "high" : c.avg10 >= 10 ? "mid" : "";
            const gauge = h("div", { class: `gauge ${level}`, "aria-hidden": "true" },
                isNum(c.avg10) && h("div", { class: "fill" }),
                isNum(c.avg300) && h("div", { class: "tick t300" }),
                isNum(c.avg60) && h("div", { class: "tick t60" }));
            gauge.style.setProperty("--v10", clamp(c.avg10));
            gauge.style.setProperty("--v60", clamp(c.avg60));
            gauge.style.setProperty("--v300", clamp(c.avg300));
            let trend = "No data";
            if (isNum(c.avg10) && isNum(c.avg300)) {
                const delta = c.avg10 - c.avg300;
                trend = Math.abs(delta) < 1 ? "Steady" : delta > 0 ? "Rising" : "Easing";
            }
            return h("tr", null,
                h("th", { scope: "row", class: "mono" }, dash(c.cgroup)),
                h("td", null, [c.resource, c.kind].filter(Boolean).join(" ") || "–"),
                h("td", null, gauge, h("span", { class: "sr-only" },
                    isNum(c.avg10) ? `${fixed(c.avg10)}% stalled in the last 10 seconds` : "No data")),
                h("td", { class: "num" }, fixed(c.avg10)),
                h("td", { class: "num" }, fixed(c.avg60)),
                h("td", { class: "num" }, fixed(c.avg300)),
                h("td", null, h("span", { class: `trend ${trend === "Rising" ? "rising" : ""}` }, trend)));
        });
        return card("Pressure",
            [table("Pressure stall information for watched cgroups",
                [["Cgroup"], ["Resource"], ["Share of time stalled, 0–100%"], ["10 s", "num"], ["1 min", "num"], ["5 min", "num"], ["Trend"]], rows),
            h("p", { class: "gauge-key", "aria-hidden": "true" },
                h("span", null, h("span", { class: "swatch" }), "Last 10 s"),
                h("span", null, h("span", { class: "tick" }), "Last minute"),
                h("span", null, h("span", { class: "tick t300" }), "Last 5 minutes"))],
            h("p", { class: "muted" }, "Updates every 5 seconds"));
    }

    const node = h("div", { class: "stack" }, banners.el, summary.el, attention.el, held.el, actions.el, pressure.el);
    return { node, refresh, poll: true };
}

// Incidents ------------------------------------------------------------------

function incidentsView() {
    const opts = cockpit.location.options;
    const list = slot();
    const unit = h("input", { type: "search", name: "unit", value: opts.unit || "", placeholder: "e.g. nginx.service" });
    const severity = h("select", { name: "severity" },
        [["", "Any"], ["critical", "Critical"], ["warning", "Warning"], ["info", "Info"]].map(([v, l]) =>
            h("option", { value: v, selected: v === (opts.severity || "") }, l)));
    const form = h("form", { class: "filters", role: "search", "aria-label": "Filter incidents", onsubmit: ev => {
        ev.preventDefault();
        const next = {};
        if (unit.value.trim()) next.unit = unit.value.trim();
        if (severity.value) next.severity = severity.value;
        cockpit.location.go(["incidents"], next);
    } },
    h("label", null, "Unit", unit),
    h("label", null, "Severity", severity),
    h("button", { type: "submit" }, "Filter"));

    async function refresh() {
        const args = { limit: 200 };
        if (opts.unit) args.unit = opts.unit;
        const res = await client.call("incidents", args);
        const shown = (res?.incidents || []).filter(i => !opts.severity || i.severity === opts.severity);
        list.set(shown, render);
    }

    function render(items) {
        if (!items.length)
            return h("p", { class: "muted" }, opts.unit || opts.severity
                ? "No incidents match these filters."
                : "No incidents yet. When a unit fails, a cgroup comes under pressure or SELinux denies something, it shows up here.");
        const rows = items.map(i => h("tr", null,
            h("td", null, when(i.ts)),
            h("td", null, severityLabel(i.severity)),
            h("td", null, kindLabel(i.kind)),
            h("th", { scope: "row" }, i.id
                ? h("a", { href: `#/incidents/${encodeURIComponent(i.id)}` }, i.target || "(no target)")
                : i.target || "(no target)"),
            h("td", null, i.policy || h("span", { class: "muted" }, "None"))));
        return table("Incidents, newest first", [["Time"], ["Severity"], ["Kind"], ["Target"], ["Policy"]], rows);
    }

    const node = card("Incidents", [form, list.el], h("p", { class: "muted" }, "Newest first"));
    return { node, refresh, live: true };
}

function bundleView(id) {
    const body = slot();

    async function refresh() {
        const res = await client.call("show", { id });
        body.set(res?.bundle || {}, render);
    }

    function avcSummary(avc) {
        const who = avc.comm || avc.exe || "a process";
        const perms = (avc.perms || []).join(", ") || "access";
        return [
            h("div", null, `${avc.permissive ? "Would deny" : "Denied"} ${perms} on ${avc.tclass || "an object"} for ${who}${avc.pid ? ` (pid ${avc.pid})` : ""}`),
            h("div", { class: "muted mono" }, `${dash(avc.scontext)} → ${dash(avc.tcontext)}`),
        ];
    }

    /** A root command that explains the bundle's denials, from the audit log itself. */
    function reviewCommand(inc, corr) {
        const avcs = [inc.trigger, ...(inc.related || []), ...corr.map(c => c.avc)]
            .filter(e => e?.source === "audit" && Number.isInteger(e.serial) && e.serial > 0);
        const ids = [...new Set(avcs.map(e => e.serial))].sort((a, b) => a - b);
        if (!ids.length) return "";
        return h("div", { class: "review" },
            h("h3", null, "Review the denials yourself"),
            h("p", null, "Run this as root to see why SELinux said no:"),
            h("pre", { class: "mono" }, `for id in ${ids.join(" ")}; do ausearch --input-logs -a "$id" --raw; done | audit2allow -w`),
            h("p", { class: "muted" }, "Drop -w to see the rules audit2allow would write. Read them before loading anything: a denial is often a file with the wrong label (restorecon fixes it) or a boolean that's off, not missing policy. Records rotated out of audit.log won't be found."));
    }

    function render(b) {
        const inc = b.incident || {};
        const { ts_us: tsUs, source: _source, ...triggerRest } = inc.trigger || {};
        const trigger = Object.entries(triggerRest)
            .filter(([, v]) => v !== null && v !== undefined)
            .map(([k, v]) => [capitalise(k.replace(/_/g, " ")), typeof v === "object" ? JSON.stringify(v) : String(v)]);

        const corr = b.correlations || [];
        const correlations = card("Likely related SELinux denials", [corr.length
            ? table("Correlated denials", [["Confidence", "num"], ["Denial"], ["Why they're linked"]],
                corr.map(c => h("tr", null,
                    h("td", { class: "num confidence" }, isNum(c.confidence) ? `${Math.round(c.confidence * 100)}%` : "–"),
                    h("td", null, avcSummary(c.avc || {})),
                    h("td", null, h("ul", { class: "reasons" }, (c.reasons || []).map(r => h("li", null, capitalise(r))))))))
            : h("p", { class: "muted" }, "No SELinux denials were linked to this incident."),
            reviewCommand(inc, corr)]);

        const d = b.decision || {};
        const decided = d.actions?.length
            ? table("Actions taken", [["Action"], ["Target"], ["Status"], ["Mode"], ["Error"]],
                d.actions.map(a => h("tr", null,
                    h("th", { scope: "row" }, dash(a.action)),
                    h("td", null, dash(a.target)),
                    h("td", null, statusLabel(a.status)),
                    h("td", null, modeLabel(a.mode)),
                    h("td", null, dash(a.error)))))
            : h("p", { class: "muted" }, "No actions were planned.");
        const decision = card("Decision", [
            facts([["Policy", d.policy || "None matched"], ["Mode", d.mode ? modeLabel(d.mode) : null]]),
            decided,
        ]);

        const journal = (b.context?.journal || []).map(e => e?.MESSAGE).filter(Boolean);
        const context = journal.length > 0 && card("Journal around the incident",
            h("pre", { class: "journal mono" }, journal.join("\n")));

        const time = isNum(tsUs) && tsUs > 0 ? when(tsUs / 1e6) : null;
        return h("div", { class: "stack" },
            h("nav", { class: "crumbs", "aria-label": "Breadcrumb" }, h("a", { href: "#/incidents" }, "All incidents")),
            h("div", { class: "bundle-title" },
                h("h2", null, `${kindLabel(inc.kind)}: ${inc.target || "no target"}`),
                severityLabel(b.severity),
                h("span", { class: "muted" }, `${when(b.ts)} on ${b.host?.hostname || "this host"}`)),
            card("What happened", trigger.length || time
                ? facts([["Time", time], ...trigger])
                : h("p", { class: "muted" }, inc.alert || "No trigger details recorded.")),
            correlations,
            decision,
            context,
            card("Raw bundle", h("details", null,
                h("summary", null, "Show the bundle as JSON"),
                h("pre", null, JSON.stringify(b, null, 2))),
            b.id && h("span", { class: "muted mono" }, b.id)));
    }

    return { node: body.el, refresh };
}

// Policies -------------------------------------------------------------------

function policiesView() {
    const body = slot();

    async function refresh() {
        body.set(await client.call("policies") || {}, render);
    }

    async function reload(button) {
        shownError = null;
        button.disabled = true;
        try {
            await client.call("reload");
            showError(null);
            announce("Configuration reloaded.");
        } catch (e) {
            showError(mutationError("reload the configuration", e));
        }
        button.disabled = false;
        body.reset();
        await refresh().catch(() => {});
        focusOr(body.el, '[data-key="reload"]');
    }

    function render(res) {
        const err = res.last_reload_error && h("div", { class: "alert danger", role: "alert" },
            h("div", null, h("h2", null, "The last reload failed, so these are the policies from before it"),
                h("p", null, "Fix the problem below, then reload."),
                h("pre", null, res.last_reload_error)));
        const reloadButton = h("button", { type: "button", "data-key": "reload", onclick: ev => reload(ev.currentTarget) }, "Reload configuration");
        const list = res.policies || [];
        const rows = list.map(p => h("tr", null,
            h("th", { scope: "row" }, dash(p.name), p.source && h("div", { class: "muted mono" }, p.source)),
            h("td", null, dash(p.signal)),
            h("td", null, (p.actions || []).join(", ") || h("span", { class: "muted" }, "Record only")),
            h("td", null, modeLabel(p.mode)),
            h("td", null, p.effective_mode === p.mode
                ? modeLabel(p.effective_mode)
                : h("span", { class: "label warning" }, `${modeLabel(p.effective_mode)} (overridden)`))));
        return h("div", { class: "stack" }, err,
            card("Policies", list.length
                ? table("Policies", [["Name"], ["Signal"], ["Actions"], ["Configured mode"], ["Effective mode"]], rows)
                : h("p", { class: "muted" }, "No policies are loaded. Add one under /etc/sentry-v2/policies.d/, then reload."),
            reloadButton));
    }

    return { node: body.el, refresh, live: true };
}

// ---------------------------------------------------------------------------
// Routing and refresh loop

let current = null;
let pollTimer = null;

function route() {
    const [page, id] = cockpit.location.path;
    for (const a of document.querySelectorAll(".tabs a")) {
        if (a.dataset.tab === (page || "")) a.setAttribute("aria-current", "page");
        else a.removeAttribute("aria-current");
    }

    const first = current === null;
    if (page === "incidents" && id) current = bundleView(id);
    else if (page === "incidents") current = incidentsView();
    else if (page === "policies") current = policiesView();
    else current = overviewView();

    errorSlot = h("div");
    shownError = null;
    main.replaceChildren(errorSlot, current.node);
    // After in-page navigation, start keyboard and screen reader users at the new content.
    if (!first) main.focus();
    run(current);
}

async function run(view) {
    clearTimeout(pollTimer);
    let down = false;
    try {
        await view.refresh();
        // Recovering from a failure screen: put the view back.
        if (view === current && !main.contains(view.node)) main.replaceChildren(errorSlot, view.node);
    } catch (err) {
        if (view !== current) return;
        down = Boolean(err.problem);
        if (err.problem && main.firstElementChild?.dataset.problem !== err.problem) {
            const failure = explainFailure(err);
            failure.dataset.problem = err.problem;
            main.replaceChildren(failure);
            announce(failure.querySelector("h2").textContent);
        } else if (!err.problem) {
            showError(err.message);
        }
    }
    // Overview polls; every view retries while the daemon is unreachable, so it comes back by itself.
    if (view === current && (view.poll || down) && !cockpit.hidden)
        pollTimer = setTimeout(() => run(view), POLL_MS);
}

let eventTimer = null;
subscribe(event => {
    if (event.kind && event.target) announce(`New incident: ${kindLabel(event.kind)} on ${event.target}.`);
    // Coalesce bursts of events into one refresh.
    clearTimeout(eventTimer);
    eventTimer = setTimeout(() => { if (current?.live || current?.poll) run(current); }, 300);
}, () => { if (current) run(current); });

cockpit.addEventListener("locationchanged", route);
cockpit.addEventListener("visibilitychange", () => { if (!cockpit.hidden && current) run(current); });
route();
