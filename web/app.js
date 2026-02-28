const API_BASE = "/api";

const ENDPOINT_CATALOG = [
  ["GET", "/health", "Service and scheduler status"],
  ["POST", "/runs/bbradar", "Run BBRadar sync manually"],
  ["POST", "/runs/github", "Run GitHub watch scan manually"],
  ["POST", "/runs/digest", "Run digest immediately"],
  ["POST", "/runs/backup", "Run backup/export immediately"],
  ["POST", "/runs/sla-reminders", "Run SLA reminder scan"],
  ["POST", "/maintenance/cleanup-invalid-watches", "Deactivate repeated 404 GitHub watches"],
  ["GET", "/jobs", "List queued/running/completed jobs"],
  ["GET", "/jobs/{id}", "Get one job status/result"],
  ["GET", "/programs", "List tracked programs"],
  ["GET", "/programs/{external_id}", "Program detail with watches/events/submissions"],
  ["GET", "/programs/{external_id}/timeline", "Program diff timeline"],
  ["GET", "/hotlist", "Priority hotlist (manual tags + score)"],
  ["POST", "/program-tags", "Tag program + manual boost (admin key)"],
  ["GET", "/events", "List audit events and change history"],
  ["GET", "/github-watches", "List active GitHub watches"],
  ["POST", "/github-watches", "Create a GitHub watch"],
  ["DELETE", "/github-watches/{watch_id}", "Deactivate one watch"],
  ["GET", "/submissions", "List bug submissions"],
  ["GET", "/submissions/kanban", "Submission kanban columns"],
  ["POST", "/submissions/duplicate-check", "Duplicate submission guard"],
  ["POST", "/submissions/{id}/deadline", "Set SLA/deadline"],
  ["GET", "/submissions/deadlines", "List SLA deadlines"],
  ["GET", "/submissions/{id}/workflow", "Workflow details"],
  ["POST", "/submissions/{id}/assign", "Assign owner"],
  ["POST", "/submissions/{id}/transition", "Workflow transition"],
  ["POST", "/submissions/{id}/notes", "Add internal note"],
  ["GET", "/submissions/{id}/notes", "List internal notes"],
  ["POST", "/submissions/{id}/evidence", "Add evidence file/link"],
  ["GET", "/submissions/{id}/evidence", "List evidence"],
  ["DELETE", "/submissions/evidence/{id}", "Delete evidence"],
  ["POST", "/submissions", "Add submission"],
  ["PATCH", "/submissions/{id}", "Update submission status/notes"],
  ["POST", "/submissions/upload", "Upload submission + PDF"],
  ["GET", "/analytics/watch-health", "GitHub watch health and stale coverage"],
  ["GET", "/analytics/rejections", "Top rejection reasons and keywords"],
  ["GET", "/analytics/source-coverage", "Program source/platform coverage"],
  ["GET", "/analytics/submission-intelligence", "Submission trend + rejection categories"],
  ["GET", "/templates", "Per-platform report templates"],
  ["POST", "/templates/validate", "Validate report draft against template"],
  ["POST", "/pre-audit/heuristics", "Run Solidity heuristic pre-audit scan"],
  ["GET", "/pre-audit/findings", "List pre-audit findings (admin key)"],
  ["POST", "/pre-audit/findings", "Create pre-audit finding (admin key)"],
  ["POST", "/pre-audit/findings/{id}/validate", "Validate pre-audit finding (admin key)"],
  ["POST", "/pre-audit/findings/{id}/draft-report", "Generate submission-ready report (admin key)"],
  ["GET", "/alert-rules", "List alert rules"],
  ["POST", "/alert-rules", "Create alert rule (admin key)"],
  ["GET", "/team/users", "List team users (admin key)"],
  ["POST", "/team/users", "Create team user + API key (admin key)"],
  ["GET", "/auth/github/login", "Start GitHub OAuth login"],
];

const PLATFORM_ORDER = ["HackenProof", "Sherlock", "Immunefi", "Code4rena"];

const $ = (id) => document.getElementById(id);

const els = {
  toast: $("toast"),
  metricPrograms: $("metric-programs"),
  metricWatches: $("metric-watches"),
  metricEvents: $("metric-events"),
  metricSubmissions: $("metric-submissions"),
  metricStaleWatches: $("metric-stale-watches"),
  metricUnhealthyWatches: $("metric-unhealthy-watches"),
  metricRejectedReports: $("metric-rejected-reports"),
  metricSourceCount: $("metric-source-count"),
  jobsList: $("jobs-list"),
  statusGrid: $("status-grid"),
  runSummaryList: $("run-summary-list"),
  programsSummary: $("programs-summary"),
  programsBody: $("programs-body"),
  platformLists: $("platform-lists"),
  hotlistBody: $("hotlist-body"),
  timelineList: $("timeline-list"),
  eventsList: $("events-list"),
  watchesBody: $("watches-body"),
  submissionsBody: $("submissions-body"),
  watchHealthSummary: $("watch-health-summary"),
  watchHealthList: $("watch-health-list"),
  rejectionSummary: $("rejection-summary"),
  rejectionReasons: $("rejection-reasons"),
  duplicateResults: $("duplicate-results"),
  templateValidationResult: $("template-validation-result"),
  workflowSummary: $("workflow-summary"),
  workflowNotesList: $("workflow-notes-list"),
  evidenceList: $("evidence-list"),
  alertRulesBody: $("alert-rules-body"),
  teamUsersBody: $("team-users-body"),
  apiEndpointsBody: $("api-endpoints-body"),
};

function watchToGithubUrl(watch) {
  if (watch.github_url) return String(watch.github_url);
  const owner = String(watch.repo_owner || "").trim();
  const repo = String(watch.repo_name || "").trim();
  const branch = String(watch.branch || "main").trim() || "main";
  const path = String(watch.file_path || "").trim().replace(/^\/+/, "");
  if (!owner || !repo) return "";
  const base = `https://github.com/${owner}/${repo}`;
  if (!path) return `${base}/tree/${branch}`;
  return `${base}/tree/${branch}/${path}`;
}

function buildProgramWatchMap(watches) {
  const map = new Map();
  for (const watch of watches || []) {
    const key = watch.program_external_id;
    if (!key) continue;
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(watch);
  }
  return map;
}

function renderProgramWatchLinks(program, watchMap, maxLinks = 3) {
  const links = watchMap.get(program.external_id) || [];
  if (!links.length) return "-";

  const selected = links.slice(0, Math.max(1, maxLinks));
  const html = selected
    .map((watch) => {
      const url = watchToGithubUrl(watch);
      const label = `${watch.repo_owner}/${watch.repo_name}${watch.file_path ? `:${watch.file_path}` : ""}`;
      return `<a href="${escapeHtml(url)}" target="_blank" rel="noopener">${escapeHtml(label)}</a>`;
    })
    .join("<br />");
  const suffix = links.length > selected.length ? `<br /><span class="more-links">+${links.length - selected.length} more</span>` : "";
  return `${html}${suffix}`;
}

function toApiUrl(path) {
  if (/^https?:\/\//i.test(path)) return path;
  if (path.startsWith(API_BASE)) return path;
  return `${API_BASE}${path}`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatDate(value) {
  if (!value) return "-";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return String(value);
  return dt.toLocaleString();
}

function formatReward(min, max) {
  const toCurrency = (val) => {
    const num = Number(val);
    if (!Number.isFinite(num)) return null;
    return `$${num.toLocaleString()}`;
  };

  const lo = toCurrency(min);
  const hi = toCurrency(max);
  if (!lo && !hi) return "N/A";
  if (lo && hi) return lo === hi ? lo : `${lo} - ${hi}`;
  return lo || hi || "N/A";
}

function shortSha(sha) {
  const value = String(sha || "").trim();
  return value ? value.slice(0, 12) : "-";
}

function parseCsvList(raw) {
  return String(raw || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function adminApiKey() {
  return $("admin-api-key")?.value?.trim() || "";
}

function adminHeaders() {
  const apiKey = adminApiKey();
  if (!apiKey) {
    throw new Error("Admin API key is required");
  }
  return { "X-API-Key": apiKey };
}

function toast(message, isError = false) {
  if (!els.toast) return;
  els.toast.textContent = message;
  els.toast.style.borderColor = isError ? "rgba(255, 151, 140, 0.7)" : "rgba(169, 220, 240, 0.5)";
  els.toast.style.background = isError ? "rgba(84, 25, 18, 0.95)" : "rgba(9, 42, 58, 0.95)";
  els.toast.classList.add("show");
  setTimeout(() => els.toast.classList.remove("show"), 3000);
}

async function request(path, options = {}) {
  const response = await fetch(toApiUrl(path), options);
  if (!response.ok) {
    let detail = "";
    try {
      const payload = await response.json();
      detail = payload.detail ? `: ${payload.detail}` : "";
    } catch {
      detail = "";
    }
    throw new Error(`HTTP ${response.status}${detail}`);
  }

  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) return response.json();
  return response.text();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function pollJob(jobId, label, maxPolls = 120, pollMs = 1500) {
  for (let i = 0; i < maxPolls; i += 1) {
    const job = await request(`/jobs/${jobId}`);
    const status = String(job.status || "").toLowerCase();
    if (status === "done") {
      toast(`${label}: completed`);
      return job.result || job;
    }
    if (status === "error") {
      throw new Error(`${label} failed: ${job.error || "unknown error"}`);
    }
    await sleep(pollMs);
  }
  throw new Error(`${label} timed out in queue`);
}

function renderApiEndpointTable() {
  if (!els.apiEndpointsBody) return;

  els.apiEndpointsBody.innerHTML = ENDPOINT_CATALOG.map(
    ([method, path, purpose]) => `
      <tr>
        <td><code>${method}</code></td>
        <td><code>/api${escapeHtml(path)}</code></td>
        <td>${escapeHtml(purpose)}</td>
      </tr>
    `,
  ).join("");
}

function renderHealth(health) {
  const rows = [
    ["Telegram", health.telegram_enabled ? "enabled" : "disabled"],
    ["GitHub Token", health.github_token_configured ? "configured" : "missing"],
    ["GitHub OAuth", health.github_oauth_configured ? "configured" : "missing"],
    ["Tracked Platforms", (health.tracked_platforms || []).join(", ") || "-"],
    ["BBRadar Interval", `${health.scheduler?.bbradar_interval_minutes || "-"} min`],
    ["GitHub Interval", `${health.scheduler?.github_interval_minutes || "-"} min`],
    ["Digest Interval", health.scheduler?.digest_enabled ? `${health.scheduler?.digest_interval_hours || "-"} hr` : "disabled"],
    ["Backup Interval", health.scheduler?.backup_enabled ? `${health.scheduler?.backup_interval_hours || "-"} hr` : "disabled"],
    ["GitHub Rate Limit", health.last_github_run?.rate_limited ? "hit" : "ok"],
    ["Queue Running", String(health.queue?.running ?? 0)],
    ["Queue Errors", String(health.queue?.error ?? 0)],
    ["Last BBRadar", formatDate(health.last_bbradar_run?.started_at)],
    ["Last GitHub", formatDate(health.last_github_run?.started_at)],
    ["Last Digest", formatDate(health.last_digest_run?.started_at)],
    ["Last Backup", formatDate(health.last_backup_run?.started_at)],
  ];

  els.statusGrid.innerHTML = rows
    .map(
      ([k, v]) => `<dl class="status-item"><dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v || "-")}</dd></dl>`,
    )
    .join("");

  const runSummary = [
    ["BBRadar", health.last_bbradar_run],
    ["GitHub", health.last_github_run],
    ["Digest", health.last_digest_run],
    ["Backup", health.last_backup_run],
    ["SLA", health.last_sla_run],
  ];

  els.runSummaryList.innerHTML = runSummary
    .map(([label, value]) => {
      if (!value) {
        return `<li><strong>${label}</strong>: no run yet</li>`;
      }
      const status = value.status || "unknown";
      const time = formatDate(value.started_at);
      let detail = "";
      if (label === "GitHub") {
        detail = `changed=${value.changed ?? 0}, errors=${value.errors ?? 0}, notifications=${value.notifications ?? 0}`;
      } else if (label === "BBRadar") {
        detail = `created=${value.created ?? 0}, updated=${value.updated ?? 0}, notifications=${value.notifications ?? 0}`;
      } else if (label === "Digest") {
        detail = `events=${value.events_in_digest ?? 0}, sent=${value.sent ? "yes" : "no"}`;
      } else if (label === "Backup") {
        detail = `program_rows=${value.program_rows ?? 0}, submission_rows=${value.submission_rows ?? 0}`;
      } else if (label === "SLA") {
        detail = `due_soon=${value.due_soon ?? 0}, overdue=${value.overdue ?? 0}, notifications=${value.notifications ?? 0}`;
      } else {
        detail = `status=${status}`;
      }
      return `<li><strong>${label}</strong>: ${escapeHtml(status)} at ${escapeHtml(time)} (${escapeHtml(detail)})</li>`;
    })
    .join("");
}

async function loadHealth() {
  const health = await request("/health");
  renderHealth(health);
}

async function loadJobs() {
  if (!els.jobsList) return;
  const jobs = await request("/jobs?limit=25");
  if (!Array.isArray(jobs) || !jobs.length) {
    els.jobsList.innerHTML = `<li class="event-item"><h4>No jobs yet</h4></li>`;
    return;
  }
  els.jobsList.innerHTML = jobs
    .map((job) => {
      const result = job.result || {};
      const detail =
        typeof result === "object" && result
          ? `status=${result.status || "-"} changed=${result.changed ?? 0} created=${result.created ?? 0}`
          : "-";
      return `
        <li class="event-item">
          <h4>#${escapeHtml(job.id)} ${escapeHtml(job.job_type || "-")} • ${escapeHtml(job.status || "-")}</h4>
          <p class="event-meta">${escapeHtml(formatDate(job.created_at))}</p>
          <p class="event-detail">${escapeHtml(detail)}</p>
        </li>
      `;
    })
    .join("");
}

async function loadPrograms() {
  const limit = Math.max(1, Number($("program-limit")?.value || 120));
  const platform = $("program-platform")?.value || "";
  const focus = $("program-focus")?.value || "smart_contract";
  const programSearch = $("program-search")?.value?.trim() || "";
  const updatedOnly = Boolean($("program-updated-only")?.checked);

  const params = new URLSearchParams({ limit: String(limit) });
  if (platform) params.set("platform", platform);
  if (updatedOnly) params.set("updated_only", "true");
  params.set("focus", focus);
  if (programSearch) params.set("q", programSearch);

  const [programs, allWatches] = await Promise.all([
    request(`/programs?${params.toString()}`),
    request("/github-watches?active_only=true"),
  ]);
  const watchMap = buildProgramWatchMap(allWatches);
  els.metricPrograms.textContent = String(programs.length);

  const updatedCount = programs.filter(
    (item) => item.first_seen_at && item.last_changed_at && item.first_seen_at !== item.last_changed_at,
  ).length;

  const focusLabel = focus === "smart_contract" ? "Smart Contract + Blockchain" : "All Programs";
  const searchLabel = programSearch ? ` • search: ${programSearch}` : "";
  els.programsSummary.textContent = `Loaded ${programs.length} programs • updated ${updatedCount} • focus: ${focusLabel}${searchLabel}`;

  if (!programs.length) {
    els.programsBody.innerHTML = `<tr><td colspan="8">No programs for current filters.</td></tr>`;
    if (els.platformLists) {
      els.platformLists.innerHTML = `<div class="platform-empty">No platform groups for current filters.</div>`;
    }
    return;
  }

  els.programsBody.innerHTML = programs
    .map(
      (program) => `
      <tr>
        <td>${escapeHtml(program.name)}</td>
        <td>${escapeHtml(program.platform)}</td>
        <td>${escapeHtml(program.date_launched || "-")}</td>
        <td>
          ${escapeHtml(formatDate(program.last_changed_at))}
          ${
            program.first_seen_at && program.last_changed_at && program.first_seen_at !== program.last_changed_at
              ? '<span class="badge updated">updated</span>'
              : ""
          }
        </td>
        <td>${escapeHtml(program.scope_type || "-")}</td>
        <td>${escapeHtml(formatReward(program.bounty_min, program.bounty_max))}</td>
        <td>${renderProgramWatchLinks(program, watchMap, 3)}</td>
        <td>
          ${
            program.link
              ? `<a href="${escapeHtml(program.link)}" target="_blank" rel="noopener">Open</a>`
              : "-"
          }
        </td>
      </tr>
    `,
    )
    .join("");

  renderPlatformLists(programs, watchMap);
}

function renderPlatformLists(programs, watchMap) {
  if (!els.platformLists) return;
  if (!Array.isArray(programs) || !programs.length) {
    els.platformLists.innerHTML = `<div class="platform-empty">No grouped data available.</div>`;
    return;
  }

  const grouped = new Map();
  for (const item of programs) {
    const key = item.platform || "Unknown";
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(item);
  }

  const orderedPlatforms = Array.from(grouped.keys()).sort((a, b) => {
    const idxA = PLATFORM_ORDER.indexOf(a);
    const idxB = PLATFORM_ORDER.indexOf(b);
    const rankA = idxA === -1 ? Number.MAX_SAFE_INTEGER : idxA;
    const rankB = idxB === -1 ? Number.MAX_SAFE_INTEGER : idxB;
    if (rankA !== rankB) return rankA - rankB;
    return a.localeCompare(b);
  });

  els.platformLists.innerHTML = orderedPlatforms
    .map((platform) => {
      const items = grouped.get(platform) || [];
      const rows = items
        .map((program) => {
          const updated =
            program.first_seen_at &&
            program.last_changed_at &&
            program.first_seen_at !== program.last_changed_at
              ? '<span class="badge updated">updated</span>'
              : "";
          return `
            <tr>
              <td>${escapeHtml(program.name)}</td>
              <td>${escapeHtml(program.scope_type || "-")}</td>
              <td>${escapeHtml(formatDate(program.last_changed_at))} ${updated}</td>
              <td>${escapeHtml(formatReward(program.bounty_min, program.bounty_max))}</td>
              <td>${renderProgramWatchLinks(program, watchMap, 2)}</td>
              <td>${program.link ? `<a href="${escapeHtml(program.link)}" target="_blank" rel="noopener">Open</a>` : "-"}</td>
            </tr>
          `;
        })
        .join("");

      return `
        <article class="platform-card">
          <div class="platform-head">
            <h3>${escapeHtml(platform)}</h3>
            <span>${items.length} program(s)</span>
          </div>
          <div class="table-wrap platform-table">
            <table>
              <thead>
                <tr>
                  <th>Program</th>
                  <th>Scope</th>
                  <th>Last Change</th>
                  <th>Reward</th>
                  <th>GitHub Links</th>
                  <th>Link</th>
                </tr>
              </thead>
              <tbody>${rows || '<tr><td colspan="6">No programs</td></tr>'}</tbody>
            </table>
          </div>
        </article>
      `;
    })
    .join("");
}

async function loadHotlist() {
  if (!els.hotlistBody) return;
  const hotlist = await request("/hotlist?limit=100&focus=smart_contract");
  if (!Array.isArray(hotlist) || !hotlist.length) {
    els.hotlistBody.innerHTML = `<tr><td colspan="4">No tagged hotlist programs yet</td></tr>`;
    return;
  }
  els.hotlistBody.innerHTML = hotlist
    .map(
      (item) => `
        <tr>
          <td><code>${escapeHtml(item.external_id)}</code></td>
          <td>${escapeHtml(item.name)}</td>
          <td>${escapeHtml(item.hotlist_score || item.priority_score || "-")}</td>
          <td>${escapeHtml((item.hotlist_tags || []).map((tag) => tag.tag).join(", ") || "-")}</td>
        </tr>
      `,
    )
    .join("");
}

async function addProgramTag(event) {
  event.preventDefault();
  const payload = {
    program_external_id: $("tag-program-id")?.value?.trim() || "",
    tag: $("tag-name")?.value?.trim() || "hotlist",
    manual_boost: Number($("tag-boost")?.value || 0),
    note: $("tag-note")?.value?.trim() || "",
  };
  await request("/program-tags", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...adminHeaders(),
    },
    body: JSON.stringify(payload),
  });
  toast("Program tag saved");
  $("program-tag-form")?.reset();
  await loadHotlist();
}

async function loadProgramTimeline(event) {
  if (event) event.preventDefault();
  if (!els.timelineList) return;
  const externalId = $("timeline-program-id")?.value?.trim() || "";
  if (!externalId) {
    toast("Program external_id required", true);
    return;
  }
  const rows = await request(`/programs/${encodeURIComponent(externalId)}/timeline?limit=80`);
  if (!Array.isArray(rows) || !rows.length) {
    els.timelineList.innerHTML = `<li class="event-item"><h4>No timeline events</h4></li>`;
    return;
  }
  els.timelineList.innerHTML = rows
    .map((row) => {
      const changed = Array.isArray(row.changed_fields) ? row.changed_fields.join(", ") : "";
      const files = Array.isArray(row.changed_files)
        ? row.changed_files.slice(0, 4).map((f) => f.filename || "").filter(Boolean).join(", ")
        : "";
      const detail = [changed ? `Fields: ${changed}` : "", files ? `Files: ${files}` : ""]
        .filter(Boolean)
        .join(" • ");
      return `
        <li class="event-item">
          <h4>${escapeHtml(row.title || row.event_type || "timeline event")}</h4>
          <p class="event-meta">${escapeHtml(formatDate(row.created_at))}</p>
          <p class="event-detail">${escapeHtml(detail || "-")}</p>
        </li>
      `;
    })
    .join("");
}

function renderEventDetail(event) {
  const details = event.details || {};

  if (event.event_type === "github_updated") {
    const files = Array.isArray(details.changed_files) ? details.changed_files : [];
    const branch = details.branch ? `branch ${details.branch}` : "";
    if (!files.length) return `GitHub target changed ${branch}`.trim();

    const preview = files
      .slice(0, 8)
      .map((item) => `${item.filename || "unknown"} (${item.status || "modified"})`)
      .join(", ");

    return `GitHub update ${branch}: ${preview}${files.length > 8 ? " ..." : ""}`.trim();
  }

  if (event.event_type === "program_updated") {
    const changedFields = Array.isArray(details.changed_fields)
      ? details.changed_fields.join(", ")
      : "program fields";
    return `Changed: ${changedFields}`;
  }

  if (event.event_type === "new_program") {
    return details.link ? `Program URL: ${details.link}` : "New program detected";
  }

  if (event.event_type === "maintenance_cleanup") {
    const list = Array.isArray(details.deactivated_watch_ids) ? details.deactivated_watch_ids : [];
    return `Cleanup deactivated ${list.length} watch(es)`;
  }

  if (event.event_type === "run_error") {
    return details.error ? `Error: ${details.error}` : "Runtime error";
  }

  return "";
}

async function loadEvents() {
  const eventType = $("event-type")?.value || "";
  const params = new URLSearchParams({ limit: "120" });
  if (eventType) params.set("event_type", eventType);

  const events = await request(`/events?${params.toString()}`);
  els.metricEvents.textContent = String(events.length);

  if (!events.length) {
    els.eventsList.innerHTML = `<li class="event-item"><h4>No events found</h4></li>`;
    return;
  }

  els.eventsList.innerHTML = events
    .map(
      (event) => `
      <li class="event-item">
        <h4>${escapeHtml(event.title)}</h4>
        <p class="event-meta">${escapeHtml(event.event_type)} • ${escapeHtml(formatDate(event.created_at))}${
          event.notified ? " • notified" : ""
        }</p>
        <p class="event-detail">${escapeHtml(renderEventDetail(event))}</p>
      </li>
    `,
    )
    .join("");
}

function watchRow(watch) {
  const repo = `${watch.repo_owner}/${watch.repo_name}`;
  const path = watch.file_path ? watch.file_path : "<repo root>";
  const program = watch.program_name || watch.program_external_id || "-";
  const githubUrl = watchToGithubUrl(watch);

  return `
    <tr>
      <td>${watch.id}</td>
      <td>${escapeHtml(program)}</td>
      <td>${escapeHtml(repo)}</td>
      <td>${escapeHtml(path)}</td>
      <td>${escapeHtml(watch.branch)}</td>
      <td><code>${escapeHtml(shortSha(watch.last_sha))}</code></td>
      <td>${githubUrl ? `<a href="${escapeHtml(githubUrl)}" target="_blank" rel="noopener">Open</a>` : "-"}</td>
      <td><button class="btn danger" data-watch-id="${watch.id}">Deactivate</button></td>
    </tr>
  `;
}

async function loadWatches() {
  const q = $("watch-search")?.value?.trim() || "";
  const programName = $("watch-program-search")?.value?.trim() || "";
  const params = new URLSearchParams({ active_only: "true" });
  if (q) params.set("q", q);
  if (programName) params.set("program_name", programName);

  const watches = await request(`/github-watches?${params.toString()}`);
  els.metricWatches.textContent = String(watches.length);

  if (!watches.length) {
    els.watchesBody.innerHTML = `<tr><td colspan="8">No active watches for current search</td></tr>`;
    return;
  }

  els.watchesBody.innerHTML = watches.map((watch) => watchRow(watch)).join("");
}

async function loadSubmissions() {
  const submissions = await request("/submissions?limit=120");
  els.metricSubmissions.textContent = String(submissions.length);

  if (!submissions.length) {
    els.submissionsBody.innerHTML = `<tr><td colspan="7">No submissions tracked yet</td></tr>`;
    return;
  }

  els.submissionsBody.innerHTML = submissions
    .map(
      (item) => `
      <tr>
        <td>${item.id}</td>
        <td>${escapeHtml(item.platform)}</td>
        <td>${escapeHtml(item.program_name)}</td>
        <td>${escapeHtml(item.bug_title)}</td>
        <td>${escapeHtml(item.severity)}</td>
        <td>${escapeHtml(item.status)}</td>
        <td>${escapeHtml(formatDate(item.updated_at))}</td>
      </tr>
    `,
    )
    .join("");
}

async function loadInsights() {
  const [watchHealth, rejections, coverage, intelligence] = await Promise.all([
    request("/analytics/watch-health?lookback_hours=168&stale_hours=48"),
    request("/analytics/rejections?top_n=12"),
    request("/analytics/source-coverage"),
    request("/analytics/submission-intelligence?months=6"),
  ]);

  if (els.metricStaleWatches) {
    els.metricStaleWatches.textContent = String(watchHealth.stale_active_watches ?? 0);
  }
  if (els.metricUnhealthyWatches) {
    const unhealthyCount = Array.isArray(watchHealth.unhealthy_samples) ? watchHealth.unhealthy_samples.length : 0;
    els.metricUnhealthyWatches.textContent = String(unhealthyCount);
  }
  if (els.metricRejectedReports) {
    els.metricRejectedReports.textContent = String(rejections.rejected_total ?? 0);
  }
  if (els.metricSourceCount) {
    const sourceCount = coverage.by_source ? Object.keys(coverage.by_source).length : 0;
    els.metricSourceCount.textContent = String(sourceCount);
  }

  if (els.watchHealthSummary) {
    els.watchHealthSummary.textContent = `Total: ${watchHealth.total_watches ?? 0} • Active: ${watchHealth.active_watches ?? 0} • Stale: ${watchHealth.stale_active_watches ?? 0}`;
  }

  if (els.watchHealthList) {
    const staleSamples = Array.isArray(watchHealth.stale_samples) ? watchHealth.stale_samples.slice(0, 6) : [];
    const unhealthySamples = Array.isArray(watchHealth.unhealthy_samples)
      ? watchHealth.unhealthy_samples.slice(0, 6)
      : [];
    const entries = [];
    for (const item of staleSamples) {
      entries.push(
        `<li class="event-item"><h4>Stale watch #${escapeHtml(item.id)}</h4><p class="event-detail">${escapeHtml(
          `${item.repo_owner}/${item.repo_name} ${item.file_path || "<repo root>"}`,
        )}</p></li>`,
      );
    }
    for (const item of unhealthySamples) {
      entries.push(
        `<li class="event-item"><h4>Errors: watch #${escapeHtml(item.watch_id)}</h4><p class="event-detail">${escapeHtml(
          `${item.repo} (${item.error_count} errors)`,
        )}</p></li>`,
      );
    }
    els.watchHealthList.innerHTML =
      entries.join("") || `<li class="event-item"><h4>No stale/unhealthy watches</h4></li>`;
  }

  if (els.rejectionSummary) {
    const cat = Array.isArray(intelligence.categories) ? intelligence.categories.slice(0, 2).map((x) => `${x.category}:${x.count}`).join(", ") : "-";
    els.rejectionSummary.textContent = `Rejected reports: ${rejections.rejected_total ?? 0} • top categories: ${cat}`;
  }
  if (els.rejectionReasons) {
    const rows = Array.isArray(rejections.top_reasons) ? rejections.top_reasons : [];
    const riskRows = Array.isArray(intelligence.duplicate_risk_samples) ? intelligence.duplicate_risk_samples.slice(0, 3) : [];
    const reasonsHtml =
      rows
        .map(
          (item) =>
            `<li class="event-item"><h4>${escapeHtml(item.reason || "unspecified")}</h4><p class="event-detail">Count: ${escapeHtml(item.count)}</p></li>`,
        )
        .join("");
    const riskHtml = riskRows
      .map(
        (item) => `
        <li class="event-item">
          <h4>Duplicate risk: #${escapeHtml(item.submission_id)}</h4>
          <p class="event-detail">${escapeHtml(item.program_name || "-")} • ${escapeHtml(item.bug_title || "-")}</p>
        </li>
      `,
      )
      .join("");
    els.rejectionReasons.innerHTML = reasonsHtml + riskHtml || `<li class="event-item"><h4>No rejection data yet</h4></li>`;
  }
}

function alertRuleRow(rule) {
  const minBounty = rule.min_bounty == null ? "-" : formatReward(rule.min_bounty, rule.min_bounty);
  const eventTypes = Array.isArray(rule.event_types) ? rule.event_types.join(", ") : "-";
  return `
    <tr>
      <td>${escapeHtml(rule.id)}</td>
      <td>${escapeHtml(rule.name)}</td>
      <td>${escapeHtml(minBounty)}</td>
      <td>${escapeHtml(eventTypes || "-")}</td>
      <td>${rule.digest_only ? "yes" : "no"}</td>
      <td><button class="btn danger" data-rule-id="${rule.id}">Delete</button></td>
    </tr>
  `;
}

async function loadAlertRules() {
  const rules = await request("/alert-rules?enabled_only=false");
  if (!els.alertRulesBody) return;
  if (!Array.isArray(rules) || !rules.length) {
    els.alertRulesBody.innerHTML = `<tr><td colspan="6">No alert rules</td></tr>`;
    return;
  }
  els.alertRulesBody.innerHTML = rules.map((rule) => alertRuleRow(rule)).join("");
}

async function createAlertRule(event) {
  event.preventDefault();
  const payload = {
    name: $("rule-name")?.value?.trim() || "",
    enabled: true,
    min_bounty: null,
    platforms: parseCsvList($("rule-platforms")?.value || ""),
    keywords: parseCsvList($("rule-keywords")?.value || ""),
    event_types: parseCsvList($("rule-event-types")?.value || ""),
    digest_only: Boolean($("rule-digest-only")?.checked),
  };
  const minBountyRaw = $("rule-min-bounty")?.value?.trim() || "";
  if (minBountyRaw) payload.min_bounty = Number(minBountyRaw);

  await request("/alert-rules", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...adminHeaders(),
    },
    body: JSON.stringify(payload),
  });
  toast("Alert rule created");
  $("alert-rule-form")?.reset();
  await loadAlertRules();
}

async function deleteAlertRule(ruleId) {
  await request(`/alert-rules/${ruleId}`, {
    method: "DELETE",
    headers: adminHeaders(),
  });
  toast(`Alert rule ${ruleId} deleted`);
  await loadAlertRules();
}

function teamUserRow(user) {
  return `
    <tr>
      <td>${escapeHtml(user.id)}</td>
      <td>${escapeHtml(user.username)}</td>
      <td>${escapeHtml(user.role)}</td>
      <td>${user.active ? "yes" : "no"}</td>
      <td>
        <button class="btn soft" data-team-rotate-id="${user.id}">Rotate Key</button>
        <button class="btn danger" data-team-delete-id="${user.id}">Delete</button>
      </td>
    </tr>
  `;
}

async function loadTeamUsers() {
  const users = await request("/team/users?active_only=false", {
    headers: adminHeaders(),
  });
  if (!els.teamUsersBody) return;
  if (!Array.isArray(users) || !users.length) {
    els.teamUsersBody.innerHTML = `<tr><td colspan="5">No team users</td></tr>`;
    return;
  }
  els.teamUsersBody.innerHTML = users.map((user) => teamUserRow(user)).join("");
}

async function createTeamUser(event) {
  event.preventDefault();
  const payload = {
    username: $("team-username")?.value?.trim() || "",
    role: $("team-role")?.value || "viewer",
    active: Boolean($("team-active")?.checked),
  };
  const result = await request("/team/users", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...adminHeaders(),
    },
    body: JSON.stringify(payload),
  });
  const key = String(result?.api_key || "");
  toast(key ? `Team user created. API key: ${key}` : "Team user created");
  $("team-user-form")?.reset();
  await loadTeamUsers();
}

async function rotateTeamUserKey(userId) {
  const result = await request(`/team/users/${userId}/rotate-key`, {
    method: "POST",
    headers: adminHeaders(),
  });
  const key = String(result?.api_key || "");
  toast(key ? `New API key for user ${userId}: ${key}` : `User ${userId} key rotated`);
  await loadTeamUsers();
}

async function deleteTeamUser(userId) {
  await request(`/team/users/${userId}`, {
    method: "DELETE",
    headers: adminHeaders(),
  });
  toast(`Team user ${userId} deleted`);
  await loadTeamUsers();
}

async function loadAdminData() {
  await Promise.all([loadAlertRules(), loadTeamUsers(), loadHotlist(), loadJobs()]);
}

async function loadAll() {
  const results = await Promise.allSettled([
    loadHealth(),
    loadJobs(),
    loadPrograms(),
    loadHotlist(),
    loadEvents(),
    loadWatches(),
    loadSubmissions(),
    loadInsights(),
  ]);

  const failed = results.find((result) => result.status === "rejected");
  if (failed && failed.reason) {
    throw failed.reason;
  }
}

async function runScan(path, label) {
  const result = await request(path, { method: "POST" });
  if (result && result.queued && result.job_id) {
    toast(`${label}: queued as job #${result.job_id}`);
    await loadJobs();
    await pollJob(result.job_id, label);
  } else if (result.status === "skipped") {
    toast(`${label}: ${result.reason || "skipped"}`);
  } else {
    toast(`${label}: ${result.status}`);
  }
  await loadJobs();
  await loadAll();
}

async function cleanupInvalidWatches(dryRun) {
  const params = new URLSearchParams({
    min_errors: "2",
    lookback_hours: String(24 * 14),
    dry_run: dryRun ? "true" : "false",
  });

  if (!dryRun) {
    const confirmed = window.confirm("Deactivate repeated 404 GitHub watches now?");
    if (!confirmed) return;
  }

  const result = await request(`/maintenance/cleanup-invalid-watches?${params.toString()}`, { method: "POST" });

  if (dryRun) {
    toast(`Dry run complete: ${result.candidate_count || 0} candidate watch(es)`);
  } else {
    toast(`Cleanup complete: deactivated ${result.deactivated_count || 0} watch(es)`);
  }

  await Promise.all([loadWatches(), loadEvents(), loadHealth()]);
}

async function addWatch(event) {
  event.preventDefault();

  const githubUrl = $("watch-github-url")?.value?.trim() || "";
  const programId = $("watch-program-id")?.value?.trim() || "";

  if (!githubUrl) {
    toast("GitHub URL is required", true);
    return;
  }

  const payload = { github_url: githubUrl };
  if (programId) payload.program_external_id = programId;

  await request("/github-watches", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  toast("Watch added");
  $("watch-form")?.reset();
  await loadWatches();
}

async function deactivateWatch(watchId) {
  await request(`/github-watches/${watchId}`, { method: "DELETE" });
  toast(`Watch ${watchId} deactivated`);
  await loadWatches();
}

async function addSubmission(event) {
  event.preventDefault();

  const payload = {
    platform: $("sub-platform")?.value?.trim() || "",
    program_name: $("sub-program")?.value?.trim() || "",
    bug_title: $("sub-title")?.value?.trim() || "",
    severity: $("sub-severity")?.value || "unknown",
    status: $("sub-status")?.value || "submitted",
  };

  await request("/submissions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  toast("Submission added");
  $("submission-form")?.reset();
  await loadSubmissions();
}

async function runDuplicateCheck(event) {
  event.preventDefault();
  const payload = {
    platform: $("dup-platform")?.value?.trim() || "",
    program_name: $("dup-program")?.value?.trim() || "",
    bug_title: $("dup-title")?.value?.trim() || "",
    triage_notes: $("dup-notes")?.value?.trim() || "",
  };
  const result = await request("/submissions/duplicate-check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const matches = Array.isArray(result.matches) ? result.matches : [];
  if (!els.duplicateResults) return;
  if (!matches.length) {
    els.duplicateResults.innerHTML = `<li class="event-item"><h4>No close duplicates found</h4></li>`;
    return;
  }
  els.duplicateResults.innerHTML = matches
    .map(
      (item) => `
      <li class="event-item">
        <h4>#${escapeHtml(item.submission_id)} ${escapeHtml(item.bug_title || "")}</h4>
        <p class="event-meta">${escapeHtml(item.program_name || "-")} • similarity ${escapeHtml(item.similarity)}</p>
        <p class="event-detail">Status: ${escapeHtml(item.status || "-")}</p>
      </li>
    `,
    )
    .join("");
}

async function loadTemplate() {
  const platform = $("template-platform")?.value || "HackenProof";
  const template = await request(`/templates/${encodeURIComponent(platform)}`);
  const sections = Array.isArray(template.sections) ? template.sections : [];
  const checklist = Array.isArray(template.checklist) ? template.checklist : [];
  const text = [
    ...sections.map((section) => `${section}\n`),
    "",
    "Checklist",
    ...checklist.map((item) => `- ${item}`),
  ].join("\n");
  if ($("template-report-text")) {
    $("template-report-text").value = text;
  }
  toast(`Template loaded for ${platform}`);
}

async function validateTemplate() {
  const platform = $("template-platform")?.value || "HackenProof";
  const reportText = $("template-report-text")?.value || "";
  const result = await request("/templates/validate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ platform, report_text: reportText }),
  });
  if (!els.templateValidationResult) return;
  const missing = Array.isArray(result.missing_sections) ? result.missing_sections.join(", ") : "-";
  els.templateValidationResult.textContent = `Score: ${result.score}% • valid: ${result.valid ? "yes" : "no"} • missing: ${missing || "-"}`;
}

function currentWorkflowSubmissionId() {
  const raw = $("workflow-submission-id")?.value || "";
  const id = Number(raw);
  return Number.isFinite(id) && id > 0 ? id : null;
}

async function loadWorkflow(event) {
  if (event) event.preventDefault();
  const submissionId = currentWorkflowSubmissionId();
  if (!submissionId) {
    toast("Submission ID required", true);
    return;
  }
  const result = await request(`/submissions/${submissionId}/workflow`);
  const workflow = result.workflow || {};
  if (els.workflowSummary) {
    els.workflowSummary.textContent = `Stage: ${workflow.stage || "-"} • review: ${workflow.review_state || "-"} • assignee: ${workflow.assigned_user_id || "-"}`;
  }
  const notes = Array.isArray(result.notes) ? result.notes : [];
  if (els.workflowNotesList) {
    els.workflowNotesList.innerHTML =
      notes
        .map(
          (note) => `
          <li class="event-item">
            <h4>Note #${escapeHtml(note.id)}</h4>
            <p class="event-meta">${escapeHtml(formatDate(note.created_at))} • ${escapeHtml(note.visibility || "internal")}</p>
            <p class="event-detail">${escapeHtml(note.note || "")}</p>
          </li>
        `,
        )
        .join("") || `<li class="event-item"><h4>No notes</h4></li>`;
  }
  await loadEvidence();
}

async function assignWorkflow(event) {
  event.preventDefault();
  const submissionId = currentWorkflowSubmissionId();
  if (!submissionId) {
    toast("Submission ID required", true);
    return;
  }
  const rawUserId = $("workflow-assign-user-id")?.value?.trim() || "";
  const payload = { user_id: rawUserId ? Number(rawUserId) : null };
  await request(`/submissions/${submissionId}/assign`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...adminHeaders(),
    },
    body: JSON.stringify(payload),
  });
  toast("Assignment updated");
  await loadWorkflow();
}

async function transitionWorkflow(event) {
  event.preventDefault();
  const submissionId = currentWorkflowSubmissionId();
  if (!submissionId) {
    toast("Submission ID required", true);
    return;
  }
  const stage = $("workflow-stage")?.value || "";
  await request(`/submissions/${submissionId}/transition`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...adminHeaders(),
    },
    body: JSON.stringify({ stage }),
  });
  toast(`Transitioned to ${stage}`);
  await Promise.all([loadWorkflow(), loadSubmissions()]);
}

async function addWorkflowNote(event) {
  event.preventDefault();
  const submissionId = currentWorkflowSubmissionId();
  if (!submissionId) {
    toast("Submission ID required", true);
    return;
  }
  const note = $("workflow-note-text")?.value?.trim() || "";
  if (!note) {
    toast("Note cannot be empty", true);
    return;
  }
  await request(`/submissions/${submissionId}/notes`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...adminHeaders(),
    },
    body: JSON.stringify({ note, visibility: "internal" }),
  });
  toast("Workflow note added");
  $("workflow-note-form")?.reset();
  await loadWorkflow();
}

function evidenceRow(item) {
  const link = item.external_url
    ? `<a href="${escapeHtml(item.external_url)}" target="_blank" rel="noopener">link</a>`
    : item.file_path
      ? `<a href="${escapeHtml(item.file_path)}" target="_blank" rel="noopener">file</a>`
      : "-";
  return `
    <li class="event-item">
      <h4>#${escapeHtml(item.id)} ${escapeHtml(item.title || "")}</h4>
      <p class="event-meta">${escapeHtml(formatDate(item.created_at))}</p>
      <p class="event-detail">tx: ${escapeHtml(item.tx_hash || "-")} • ${link}</p>
      <button class="btn danger" data-evidence-id="${item.id}">Delete</button>
    </li>
  `;
}

async function loadEvidence() {
  const submissionId = currentWorkflowSubmissionId();
  if (!submissionId || !els.evidenceList) return;
  const evidence = await request(`/submissions/${submissionId}/evidence?limit=50`);
  if (!Array.isArray(evidence) || !evidence.length) {
    els.evidenceList.innerHTML = `<li class="event-item"><h4>No evidence yet</h4></li>`;
    return;
  }
  els.evidenceList.innerHTML = evidence.map((item) => evidenceRow(item)).join("");
}

async function addEvidence(event) {
  event.preventDefault();
  const submissionId = currentWorkflowSubmissionId();
  if (!submissionId) {
    toast("Submission ID required for evidence", true);
    return;
  }
  const title = $("evidence-title")?.value?.trim() || "";
  if (!title) {
    toast("Evidence title required", true);
    return;
  }
  const fd = new FormData();
  fd.set("title", title);
  const txHash = $("evidence-tx-hash")?.value?.trim() || "";
  const evidenceUrl = $("evidence-url")?.value?.trim() || "";
  if (txHash) fd.set("tx_hash", txHash);
  if (evidenceUrl) fd.set("external_url", evidenceUrl);
  const fileInput = $("evidence-file");
  if (fileInput instanceof HTMLInputElement && fileInput.files && fileInput.files.length > 0) {
    fd.set("evidence_file", fileInput.files[0]);
  }
  await request(`/submissions/${submissionId}/evidence`, {
    method: "POST",
    headers: adminHeaders(),
    body: fd,
  });
  toast("Evidence added");
  $("evidence-form")?.reset();
  await loadEvidence();
}

async function deleteEvidence(evidenceId) {
  await request(`/submissions/evidence/${evidenceId}`, {
    method: "DELETE",
    headers: adminHeaders(),
  });
  toast(`Evidence ${evidenceId} deleted`);
  await loadEvidence();
}

function setupOAuthLink() {
  const loginBtn = $("github-login-btn");
  if (!loginBtn) return;

  const returnTo = `${window.location.origin}/app`;
  loginBtn.href = `${API_BASE}/auth/github/login?return_to=${encodeURIComponent(returnTo)}`;

  const params = new URLSearchParams(window.location.search);
  const githubLogin = params.get("github_login");
  if (githubLogin) {
    toast(`GitHub login successful: ${githubLogin}`);
    const cleanUrl = `${window.location.origin}${window.location.pathname}`;
    window.history.replaceState({}, "", cleanUrl);
  }
}

function bindEvents() {
  const runWatchSearch = () => loadWatches().catch(handleError);
  const runProgramSearch = () => loadPrograms().catch(handleError);

  $("refresh-all")?.addEventListener("click", () => loadAll().catch(handleError));
  $("load-jobs")?.addEventListener("click", () => loadJobs().catch(handleError));
  $("run-bbradar")?.addEventListener("click", () => runScan("/runs/bbradar", "BBRadar").catch(handleError));
  $("run-github")?.addEventListener("click", () => runScan("/runs/github", "GitHub").catch(handleError));
  $("run-digest")?.addEventListener("click", () => runScan("/runs/digest", "Digest").catch(handleError));
  $("run-backup")?.addEventListener("click", () => runScan("/runs/backup", "Backup").catch(handleError));
  $("refresh-insights")?.addEventListener("click", () => loadInsights().catch(handleError));
  $("load-admin-data")?.addEventListener("click", () => loadAdminData().catch(handleError));
  $("cleanup-dry")?.addEventListener("click", () => cleanupInvalidWatches(true).catch(handleError));
  $("cleanup-apply")?.addEventListener("click", () => cleanupInvalidWatches(false).catch(handleError));

  $("load-programs")?.addEventListener("click", runProgramSearch);
  $("load-hotlist")?.addEventListener("click", () => loadHotlist().catch(handleError));
  $("program-platform")?.addEventListener("change", runProgramSearch);
  $("program-focus")?.addEventListener("change", runProgramSearch);
  $("program-updated-only")?.addEventListener("change", runProgramSearch);
  $("program-search")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") runProgramSearch();
  });

  $("load-events")?.addEventListener("click", () => loadEvents().catch(handleError));
  $("event-type")?.addEventListener("change", () => loadEvents().catch(handleError));
  $("load-watches")?.addEventListener("click", runWatchSearch);
  $("watch-search-btn")?.addEventListener("click", runWatchSearch);
  $("watch-clear-btn")?.addEventListener("click", () => {
    if ($("watch-search")) $("watch-search").value = "";
    if ($("watch-program-search")) $("watch-program-search").value = "";
    runWatchSearch();
  });
  $("watch-search")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") runWatchSearch();
  });
  $("watch-program-search")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") runWatchSearch();
  });

  $("load-submissions")?.addEventListener("click", () => loadSubmissions().catch(handleError));

  $("watch-form")?.addEventListener("submit", (event) => addWatch(event).catch(handleError));
  $("submission-form")?.addEventListener("submit", (event) => addSubmission(event).catch(handleError));
  $("program-tag-form")?.addEventListener("submit", (event) => addProgramTag(event).catch(handleError));
  $("timeline-form")?.addEventListener("submit", (event) => loadProgramTimeline(event).catch(handleError));
  $("duplicate-check-form")?.addEventListener("submit", (event) => runDuplicateCheck(event).catch(handleError));
  $("load-template")?.addEventListener("click", () => loadTemplate().catch(handleError));
  $("validate-template")?.addEventListener("click", () => validateTemplate().catch(handleError));
  $("workflow-load-form")?.addEventListener("submit", (event) => loadWorkflow(event).catch(handleError));
  $("workflow-assign-form")?.addEventListener("submit", (event) => assignWorkflow(event).catch(handleError));
  $("workflow-transition-form")?.addEventListener("submit", (event) => transitionWorkflow(event).catch(handleError));
  $("workflow-note-form")?.addEventListener("submit", (event) => addWorkflowNote(event).catch(handleError));
  $("evidence-form")?.addEventListener("submit", (event) => addEvidence(event).catch(handleError));
  $("alert-rule-form")?.addEventListener("submit", (event) => createAlertRule(event).catch(handleError));
  $("team-user-form")?.addEventListener("submit", (event) => createTeamUser(event).catch(handleError));

  els.watchesBody?.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const button = target.closest("button[data-watch-id]");
    if (!button) return;
    const watchId = Number(button.getAttribute("data-watch-id"));
    if (!Number.isFinite(watchId)) return;
    deactivateWatch(watchId).catch(handleError);
  });

  els.alertRulesBody?.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const button = target.closest("button[data-rule-id]");
    if (!button) return;
    const ruleId = Number(button.getAttribute("data-rule-id"));
    if (!Number.isFinite(ruleId)) return;
    deleteAlertRule(ruleId).catch(handleError);
  });

  els.teamUsersBody?.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const rotateButton = target.closest("button[data-team-rotate-id]");
    if (rotateButton) {
      const userId = Number(rotateButton.getAttribute("data-team-rotate-id"));
      if (Number.isFinite(userId)) {
        rotateTeamUserKey(userId).catch(handleError);
      }
      return;
    }
    const deleteButton = target.closest("button[data-team-delete-id]");
    if (!deleteButton) return;
    const userId = Number(deleteButton.getAttribute("data-team-delete-id"));
    if (!Number.isFinite(userId)) return;
    deleteTeamUser(userId).catch(handleError);
  });

  els.evidenceList?.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const button = target.closest("button[data-evidence-id]");
    if (!button) return;
    const evidenceId = Number(button.getAttribute("data-evidence-id"));
    if (!Number.isFinite(evidenceId)) return;
    deleteEvidence(evidenceId).catch(handleError);
  });
}

function handleError(error) {
  const message = error?.message || "Request failed";
  toast(message, true);
}

async function init() {
  setupOAuthLink();
  renderApiEndpointTable();
  bindEvents();
  await loadAll();
}

init().catch(handleError);
