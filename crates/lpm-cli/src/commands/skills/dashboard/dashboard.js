(() => {
  "use strict";

  const SESSION_KEY = "lpm_skills_dashboard_token";
  const state = { inventory: null, filtered: [], selected: null, plan: null };
  const elements = {};

  document.addEventListener("DOMContentLoaded", init);

  function init() {
    captureElements();
    captureSessionToken();
    bindEvents();
    loadInventory();
  }

  function captureElements() {
    for (const id of [
      "project-path", "mode-badge", "refresh-button", "notice", "summary",
      "agent-context", "inventory-count", "search", "kind-filter", "scope-filter",
      "agent-filter", "status-filter", "skill-rows", "empty-state", "detail-dialog",
      "detail-kind", "detail-title", "detail-content", "plan-dialog", "plan-title",
      "plan-content", "apply-button"
    ]) elements[id] = document.getElementById(id);
  }

  function captureSessionToken() {
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const token = fragment.get("token");
    if (token) {
      sessionStorage.setItem(SESSION_KEY, token);
      history.replaceState({}, "", window.location.pathname + window.location.search);
    }
  }

  function bindEvents() {
    elements["refresh-button"].addEventListener("click", loadInventory);
    for (const id of ["search", "kind-filter", "scope-filter", "agent-filter", "status-filter"])
      elements[id].addEventListener(id === "search" ? "input" : "change", renderInventory);
    document.querySelectorAll("[data-close]").forEach((button) => {
      button.addEventListener("click", () => document.getElementById(button.dataset.close).close());
    });
    elements["apply-button"].addEventListener("click", applyPlan);
  }

  async function api(path, options = {}) {
    const token = sessionStorage.getItem(SESSION_KEY);
    if (!token) throw new Error("Dashboard session is missing. Restart `lpm skills dashboard`.");
    const headers = new Headers(options.headers || {});
    headers.set("Authorization", `Bearer ${token}`);
    if (options.body) headers.set("Content-Type", "application/json");
    const response = await fetch(path, { ...options, headers });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Dashboard request failed (${response.status})`);
    return body;
  }

  async function loadInventory() {
    setLoading(true);
    hideNotice();
    try {
      state.inventory = await api("/api/v1/inventory");
      elements["project-path"].textContent = state.inventory.project;
      elements["mode-badge"].textContent = state.inventory.read_only ? "Read-only session" : "Local authenticated session";
      elements["mode-badge"].className = `badge ${state.inventory.read_only ? "neutral" : "good"}`;
      if (!state.inventory.includes_global)
        showNotice("Showing the current project only. Restart with `lpm skills dashboard --global` to include global skills.");
      renderSummary();
      renderContext();
      renderInventory();
      if (state.selected) {
        state.selected = state.inventory.skills.find((skill) => skill.id === state.selected.id) || null;
        if (state.selected && elements["detail-dialog"].open) renderDetail(state.selected);
        else if (!state.selected && elements["detail-dialog"].open) elements["detail-dialog"].close();
      }
      return true;
    } catch (error) {
      showNotice(error.message, true);
      return false;
    } finally {
      setLoading(false);
    }
  }

  function setLoading(loading) {
    elements["refresh-button"].disabled = loading;
    elements["refresh-button"].textContent = loading ? "Refreshing…" : "Refresh";
  }

  function showNotice(message, error = false) {
    elements.notice.textContent = message;
    elements.notice.classList.remove("hidden");
    elements.notice.style.borderColor = error ? "var(--red)" : "";
    elements.notice.style.color = error ? "var(--red)" : "";
  }

  function hideNotice() {
    elements.notice.classList.add("hidden");
    elements.notice.removeAttribute("style");
  }

  function renderSummary() {
    const c = state.inventory.counts;
    const cards = [
      ["Total skills", c.total, ""], ["Managed", c.managed, ""], ["External", c.external, ""],
      ["Package", c.package, ""], ["Needs attention", c.needs_attention, "attention"],
      ["Blocking findings", c.security_blocks, c.security_blocks ? "block" : ""]
    ];
    elements.summary.replaceChildren(...cards.map(([label, value, cls]) => {
      const card = node("article", `summary-card ${cls}`.trim());
      card.append(node("span", "", label), node("strong", "", String(value)));
      return card;
    }));
  }

  function renderContext() {
    const summaries = state.inventory.context_by_agent;
    if (!summaries.length) {
      elements["agent-context"].replaceChildren(node("span", "muted", "No agent-targeted skills enabled"));
      return;
    }
    elements["agent-context"].replaceChildren(...summaries.map((summary) => {
      const card = node("div", "agent-context-card");
      card.append(
        node("span", "", summary.label),
        node("strong", "", formatTokens(summary.estimated_context_tokens)),
        node("span", "", `${summary.enabled_skills} enabled ${plural(summary.enabled_skills, "skill")}`)
      );
      return card;
    }));
  }

  function renderInventory() {
    if (!state.inventory) return;
    const query = elements.search.value.trim().toLowerCase();
    const kind = elements["kind-filter"].value;
    const scope = elements["scope-filter"].value;
    const agent = elements["agent-filter"].value;
    const status = elements["status-filter"].value;
    state.filtered = state.inventory.skills.filter((skill) => {
      const haystack = [skill.name, skill.description, skill.source, skill.package, skill.path].filter(Boolean).join(" ").toLowerCase();
      if (query && !haystack.includes(query)) return false;
      if (kind !== "all" && skill.kind !== kind) return false;
      if (scope !== "all" && skill.scope !== scope) return false;
      if (agent !== "all" && !skill.targets.some((target) => target.agent === agent)) return false;
      const attention = needsAttention(skill);
      const disabled = skill.kind === "managed" && skill.targets.length > 0 && skill.targets.every((target) => !target.enabled);
      if (status === "attention" && !attention) return false;
      if (status === "disabled" && !disabled) return false;
      if (status === "healthy" && (attention || disabled)) return false;
      return true;
    });
    elements["inventory-count"].textContent = `${state.filtered.length} of ${state.inventory.counts.total} ${plural(state.filtered.length, "skill")}`;
    elements["skill-rows"].replaceChildren(...state.filtered.map(skillRow));
    elements["empty-state"].classList.toggle("hidden", state.filtered.length !== 0);
  }

  function skillRow(skill) {
    const row = document.createElement("tr");
    row.tabIndex = 0;
    row.addEventListener("click", () => openDetail(skill));
    row.addEventListener("keydown", (event) => { if (event.key === "Enter") openDetail(skill); });

    const nameCell = document.createElement("td");
    nameCell.append(node("span", "skill-name", skill.name), node("span", "skill-description", skill.description || skill.source));
    const ownershipCell = document.createElement("td");
    const ownership = node("div", "ownership");
    ownership.append(badge(skill.kind, kindBadgeClass(skill.kind)));
    if (skill.integrity) ownership.append(badge(skill.integrity, skill.integrity === "verified" ? "good" : skill.integrity === "modified" ? "bad" : "neutral"));
    ownershipCell.append(ownership);
    const scopeCell = document.createElement("td"); scopeCell.append(badge(skill.scope, "neutral"));
    const agentsCell = document.createElement("td");
    const agents = node("div", "agent-list");
    const enabledTargets = skill.targets.filter((target) => target.enabled);
    if (enabledTargets.length) enabledTargets.forEach((target) => agents.append(badge(target.label, target.healthy ? "info" : "bad")));
    else agents.append(node("span", "muted", skill.kind === "package" ? "Package-owned" : "None"));
    agentsCell.append(agents);
    const contextCell = document.createElement("td"); contextCell.append(node("span", "token-value", skill.context_tokens == null ? "—" : formatTokens(skill.context_tokens)));
    const securityCell = document.createElement("td");
    const security = node("div", "security-cell");
    if (skill.security.status !== "scanned") security.append(badge("Not scanned", "warn"));
    else if (skill.security.block_count) security.append(badge(`${skill.security.block_count} block`, "bad"));
    else if (skill.security.warning_count) security.append(badge(`${skill.security.warning_count} warning`, "warn"));
    else security.append(badge("No findings", "good"));
    securityCell.append(security);
    const statusCell = document.createElement("td"); statusCell.append(statusBadge(skill));
    const actionsCell = document.createElement("td");
    const actions = node("div", "row-actions");
    if (skill.actions.length) {
      const button = node("button", "button secondary small", "Manage"); button.type = "button";
      button.addEventListener("click", (event) => { event.stopPropagation(); openDetail(skill); });
      actions.append(button);
    }
    actionsCell.append(actions);
    row.append(nameCell, ownershipCell, scopeCell, agentsCell, contextCell, securityCell, statusCell, actionsCell);
    return row;
  }

  function openDetail(skill) {
    state.selected = skill;
    renderDetail(skill);
    elements["detail-dialog"].showModal();
  }

  function renderDetail(skill) {
    elements["detail-kind"].textContent = `${skill.kind} · ${skill.scope}`;
    elements["detail-title"].textContent = skill.name;
    const content = elements["detail-content"];
    const grid = node("div", "detail-grid");
    grid.append(
      detailField("Source", skill.source),
      detailField("Estimated context", skill.context_tokens == null ? "Unavailable" : formatTokens(skill.context_tokens)),
      detailField("Path", skill.path || "Package-managed", true),
      detailField("Health", skill.healthy ? "Healthy" : "Needs attention")
    );
    if (skill.package) grid.append(detailField("Owning package", `${skill.package}${skill.version ? `@${skill.version}` : ""}`, true));
    if (skill.description) grid.append(detailField("Description", skill.description, true));

    const targets = section("Agent targets", `${skill.targets.length} ${plural(skill.targets.length, "target")}`);
    if (!skill.targets.length) targets.append(node("p", "muted", "Package-published skills are owned by their package and are not materialized into an agent target by LPM."));
    for (const target of skill.targets) {
      const card = node("div", "target-card");
      const top = node("div", "target-top");
      top.append(node("strong", "", target.label), badge(target.status.replaceAll("-", " "), target.healthy ? (target.enabled ? "good" : "neutral") : "bad"));
      card.append(top, node("code", "", `${target.materialization} · ${target.path}`));
      targets.append(card);
    }

    const security = section("Security scan", securitySummary(skill.security));
    if (skill.security.message) security.append(node("p", "muted", skill.security.message));
    if (!skill.security.findings.length && skill.security.status === "scanned") security.append(node("p", "muted", "No deterministic or heuristic findings detected. This is not a guarantee that the skill is safe."));
    for (const finding of skill.security.findings) {
      const card = node("div", "finding-card");
      const top = node("div", "finding-top");
      top.append(node("strong", "", finding.rule_id), badge(finding.severity, finding.severity === "block" ? "bad" : "warn"));
      card.append(top, node("code", "", `${finding.category} · ${finding.path}:${finding.line}`));
      security.append(card);
    }

    const command = section("CLI equivalent", "Copyable fallback");
    const commandBox = node("div", "detail-field wide command-box");
    commandBox.append(node("code", "", skill.command));
    const copy = node("button", "button secondary small", "Copy"); copy.type = "button";
    copy.addEventListener("click", async () => { await navigator.clipboard.writeText(skill.command); copy.textContent = "Copied"; });
    commandBox.append(copy); command.append(commandBox);

    const actions = node("div", "action-strip");
    for (const action of skill.actions) {
      const button = node("button", `button action-${action}`, actionLabel(action)); button.type = "button";
      button.addEventListener("click", () => previewAction(skill, action));
      actions.append(button);
    }
    content.replaceChildren(grid, targets, security, command, actions);
  }

  async function previewAction(skill, action) {
    setActionButtonsDisabled(true);
    try {
      const plan = await api("/api/v1/actions/preview", {
        method: "POST",
        body: JSON.stringify({ skill_id: skill.id, action, agents: [] })
      });
      state.plan = plan;
      renderPlan(plan);
      elements["detail-dialog"].close();
      elements["plan-dialog"].showModal();
    } catch (error) {
      elements["detail-dialog"].close();
      showNotice(error.message, true);
    } finally {
      setActionButtonsDisabled(false);
    }
  }

  function renderPlan(plan) {
    elements["plan-title"].textContent = `${actionLabel(plan.action)} ${plan.skill}`;
    const content = elements["plan-content"];
    const parts = [];
    if (plan.security_warning_count)
      parts.push(node("div", "plan-warning", `${plan.security_warning_count} security ${plural(plan.security_warning_count, "warning")} detected in the candidate update. Review the findings and diff before applying.`));
    const changes = section("Filesystem plan", `${plan.changes.length} ${plural(plan.changes.length, "change")}`);
    if (!plan.changes.length) changes.append(node("p", "muted", "No filesystem changes are needed."));
    for (const change of plan.changes) {
      const card = node("div", "change-card");
      card.append(node("strong", "", change.action), node("code", "", change.path));
      changes.append(card);
    }
    parts.push(changes);
    for (const update of plan.updates) {
      const updateSection = section(`Update preview · ${update.name}`, `${update.security_findings_before} → ${update.security_findings_after} findings`);
      for (const finding of update.new_security_findings) {
        const card = node("div", "finding-card");
        const top = node("div", "finding-top");
        top.append(node("strong", "", finding.rule_id), badge(finding.severity, finding.severity === "block" ? "bad" : "warn"));
        card.append(top, node("code", "", `${finding.path}:${finding.line}`));
        updateSection.append(card);
      }
      const diff = node("pre", "diff", update.diff || "No content changes");
      updateSection.append(diff); parts.push(updateSection);
    }
    content.replaceChildren(...parts);
    elements["apply-button"].className = `button ${plan.action === "remove" ? "danger" : "primary"}`;
    elements["apply-button"].textContent = `${actionLabel(plan.action)} skill`;
  }

  async function applyPlan() {
    if (!state.plan) return;
    elements["apply-button"].disabled = true;
    elements["apply-button"].textContent = "Applying…";
    try {
      const result = await api("/api/v1/actions/apply", {
        method: "POST",
        body: JSON.stringify({ plan_id: state.plan.plan_id })
      });
      elements["plan-dialog"].close();
      state.plan = null;
      if (await loadInventory()) showNotice(`${actionLabel(result.action)} applied to ${result.skill}.`);
    } catch (error) {
      elements["plan-dialog"].close();
      state.plan = null;
      showNotice(error.message, true);
    } finally {
      elements["apply-button"].disabled = false;
    }
  }

  function setActionButtonsDisabled(disabled) {
    elements["detail-content"].querySelectorAll(".action-strip button").forEach((button) => { button.disabled = disabled; });
  }

  function detailField(label, value, wide = false) {
    const field = node("div", `detail-field${wide ? " wide" : ""}`);
    field.append(node("span", "", label), node("strong", "", value));
    return field;
  }

  function section(title, meta) {
    const block = node("section", "section-block");
    const heading = node("div", "section-heading");
    heading.append(node("h3", "", title), node("span", "muted", meta));
    block.append(heading);
    return block;
  }

  function badge(text, className) { return node("span", `badge ${className}`, titleCase(text)); }
  function kindBadgeClass(kind) { return kind === "managed" ? "good" : kind === "external" ? "info" : "neutral"; }
  function securitySummary(security) {
    if (security.status !== "scanned") return "Scan unavailable";
    if (security.block_count) return `${security.block_count} blocking ${plural(security.block_count, "finding")}`;
    if (security.warning_count) return `${security.warning_count} ${plural(security.warning_count, "warning")}`;
    return "No findings detected";
  }
  function needsAttention(skill) { return !skill.healthy || skill.security.status !== "scanned" || skill.security.warning_count > 0 || skill.security.block_count > 0; }
  function statusBadge(skill) {
    if (!skill.healthy) return badge("Needs attention", "bad");
    if (skill.security.block_count) return badge("Blocked", "bad");
    if (skill.security.warning_count || skill.security.status !== "scanned") return badge("Review", "warn");
    if (skill.kind === "managed" && skill.targets.length && skill.targets.every((target) => !target.enabled)) return badge("Disabled", "neutral");
    return badge("Healthy", "good");
  }
  function actionLabel(action) { return ({ enable: "Enable", disable: "Disable", update: "Update", remove: "Remove" })[action] || titleCase(action); }
  function formatTokens(value) { return `~${new Intl.NumberFormat().format(value)} tokens`; }
  function plural(count, word) { return count === 1 ? word : `${word}s`; }
  function titleCase(value) { return String(value).replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
  function node(tag, className = "", text = null) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text != null) element.textContent = text;
    return element;
  }
})();
