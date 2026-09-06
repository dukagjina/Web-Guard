"use strict";

const threatDefinitions = [
  { id: "malware", title: "Malware & ransomware", description: "Malicious downloads, command servers and ransomware infrastructure.", icon: '<path d="M12 3 20 6v6c0 4.7-2.8 8-8 10-5.2-2-8-5.3-8-10V6l8-3Z"/><path d="M12 8v5m0 3h.01"/>' },
  { id: "phishing", title: "Phishing", description: "Impersonation pages built to steal passwords or payment details.", icon: '<circle cx="7" cy="5" r="3"/><path d="M7 8v7a5 5 0 0 0 10 0v-5M14 10l3-3 3 3"/>' },
  { id: "scams", title: "Scams & fraud", description: "Known fake offers, financial fraud and deceptive schemes.", icon: '<path d="M12 3 3 20h18L12 3Z"/><path d="M12 9v5m0 3h.01"/>' },
  { id: "abuse", title: "Deceptive & abusive sites", description: "Domains repeatedly associated with online abuse or deception.", icon: '<circle cx="12" cy="12" r="9"/><path d="M8 8l8 8m0-8-8 8"/>' },
  { id: "redirects", title: "Redirect threats", description: "Unsafe redirect and proxy domains used to disguise destinations.", icon: '<path d="M10 5H6a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-4"/><path d="M14 4h6v6M20 4l-9 9"/>' },
  { id: "crypto", title: "Cryptojacking & crypto scams", description: "Malicious mining scripts and cryptocurrency scam domains.", icon: '<path d="M9 5h5a3 3 0 0 1 0 6H9m0 0h6a3 3 0 0 1 0 6H9M11 3v16m4-16v2m0 12v2"/>' },
];

const state = {
  ready: false,
  busy: false,
  version: "",
  metadata: {},
  service: null,
  settings: {
    protection_enabled: false,
    dns_provider: "cloudflare",
    browser_dns_protection: false,
    categories: Object.fromEntries(threatDefinitions.map(item => [item.id, true])),
    allowlist: [], custom_blocklist: [],
  },
  toastTimer: null,
};

let initializationPromise = null;
let statusPromise = null;
let statusTimer = null;

const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const formatNumber = value => Number(value || 0).toLocaleString();

function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.className = `toast show${error ? " error" : ""}`;
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => element.className = "toast", 3000);
}

function setServiceStatus(status) {
  state.service = status || {};
  if (status?.settings) state.settings = status.settings;
  const running = Boolean(status?.filter_running && state.settings.protection_enabled);
  const connecting = status?.service === "starting";
  const serviceAvailable = status?.service === "running" || status?.service === "starting";
  const vpnBrowsers = status?.browser_dns?.vpn_browsers || [];
  const compatibility = status?.compatibility || {};
  const vpnNames = compatibility.vpn_names || [];
  const vpnDetected = vpnBrowsers.length > 0 || compatibility.vpn_active;
  const vpnWarning = $("#vpnWarning");
  vpnWarning.hidden = !vpnDetected;
  if (vpnBrowsers.length) {
    $("#vpnWarningText").textContent = `${vpnBrowsers.join(", ")} sends browsing and DNS through its own encrypted tunnel. Web Guard cannot block websites inside that VPN; turn it off to restore filtering in that browser.`;
  } else if (compatibility.vpn_active) {
    const label = vpnNames.length ? ` (${vpnNames.join(", ")})` : "";
    $("#vpnWarningText").textContent = `A VPN is active${label}. It may take control of DNS, so Web Guard cannot guarantee that websites are blocked until the VPN is turned off.`;
  }
  const supportedBrowsers = (status?.browser_dns?.browsers || []).filter(item => item.supported);
  const browserCoverageMissing = running && supportedBrowsers.length > 0 && !state.settings.browser_dns_protection;
  const limited = running && Boolean(
    vpnBrowsers.length || compatibility.vpn_active || compatibility.dns_bypass || browserCoverageMissing
  );
  $("#powerButton").classList.toggle("on", running);
  $("#powerButton").classList.toggle("limited", limited);
  $("#powerButton").setAttribute("aria-label", running ? "Turn protection off" : "Turn protection on");
  $("#protectionTitle").textContent = running
    ? (limited ? "Protection is limited" : "This PC is protected") : connecting ? "Checking protection…" : "Protection is off";
  $("#protectionSubtitle").textContent = running
    ? (vpnBrowsers.length ? `${vpnBrowsers.join(", ")} VPN traffic bypasses local filtering.` : limited ? "A network or browser setting can bypass local filtering." : "Known dangerous domains are blocked locally.")
    : connecting ? "Connecting to the local protection service."
    : serviceAvailable ? "Press the button to protect this PC." : (status?.error || "The protection service is unavailable.");
  $("#serviceStatus").textContent = connecting
    ? "Connecting…" : serviceAvailable ? (running ? (limited ? "Active with limits" : "Active") : "Ready") : "Unavailable";
  $("#blockedCount").textContent = formatNumber(status?.stats?.blocked);
  renderConnectionStatus(status, running);
  renderThreats();
  renderExceptions();
}

function renderConnectionStatus(status, running) {
  const compatibility = status?.compatibility || {};
  const upstream = status?.upstream || {};
  const browserDns = status?.browser_dns || {};
  const provider = state.settings.dns_provider || "cloudflare";
  const providerSelect = $("#dnsProvider");
  providerSelect.value = provider;
  providerSelect.disabled = running || state.busy;
  $("#dnsProviderStatus").textContent = provider === "cloudflare"
    ? (running && upstream.encrypted ? "Allowed requests use encrypted DNS over HTTPS." : "Certificate-verified encrypted DNS is used when protection starts.")
    : "Allowed requests use the DNS resolver Windows was already using.";

  const browserToggle = $("#browserDnsToggle");
  browserToggle.checked = Boolean(state.settings.browser_dns_protection);
  browserToggle.disabled = (!running && !state.settings.browser_dns_protection) || state.busy;
  const unsupported = browserDns.unsupported || [];
  const vpnBrowsers = browserDns.vpn_browsers || [];
  const detected = browserDns.browsers || [];
  const supported = detected.filter(item => item.supported);
  const unsecured = supported.filter(item => !item.secured);
  let browserText = state.settings.browser_dns_protection
    ? "Secure DNS is controlled for Chrome, Edge, Brave and Firefox. Restart open browsers after changing it."
    : "Turn this on to prevent Chrome, Edge, Brave and Firefox from bypassing local DNS.";
  if (state.settings.browser_dns_protection && unsecured.length) {
    browserText = `Policy is not active for ${unsecured.map(item => item.label).join(", ")}. Turn this control off and retry.`;
  }
  if (supported.length) browserText += ` Detected: ${supported.map(item => item.label).join(", ")}.`;
  if (unsupported.length) browserText += ` Check Secure DNS manually in ${unsupported.join(", ")}.`;
  if (vpnBrowsers.length) browserText = `${vpnBrowsers.join(", ")} VPN is enabled. Its tunneled browsing bypasses Web Guard; Web Guard does not disable it.`;
  const browserStatus = $("#browserDnsStatus");
  browserStatus.textContent = browserText;
  browserStatus.classList.toggle("warning", vpnBrowsers.length > 0 || (state.settings.browser_dns_protection && unsecured.length > 0));

  const badge = $("#connectionBadge");
  badge.className = "connection-badge";
  const network = $("#networkStatus");
  network.className = "network-note";
  if (compatibility.scanning) {
    badge.textContent = "Checking…";
    network.textContent = "Checking VPN and Windows DNS routes…";
  } else if (running && upstream.last_error) {
    badge.textContent = "DNS unavailable";
    badge.classList.add("warning");
    network.classList.add("warning");
    network.textContent = `The selected DNS upstream is not answering: ${upstream.last_error}`;
  } else if (vpnBrowsers.length) {
    badge.textContent = "Browser VPN bypass";
    badge.classList.add("warning");
    network.classList.add("warning");
    network.textContent = `${vpnBrowsers.join(", ")} sends browsing and DNS through its own tunnel. Turn that VPN off if you want Web Guard to filter that browser.`;
  } else if (running && supported.length && !state.settings.browser_dns_protection) {
    badge.textContent = "Browser check needed";
    badge.classList.add("warning");
    network.classList.add("notice");
    network.textContent = "Turn on Browser DNS protection to prevent supported browsers from using a separate DNS resolver.";
  } else if (state.settings.browser_dns_protection && unsecured.length) {
    badge.textContent = "Browser attention";
    badge.classList.add("warning");
    network.classList.add("warning");
    network.textContent = "One or more installed browsers are not reporting the required Secure DNS policy.";
  } else if (running && compatibility.dns_bypass) {
    badge.textContent = "Attention needed";
    badge.classList.add("warning");
    network.classList.add("warning");
    const details = [];
    if (compatibility.bypass_adapters?.length) details.push(`DNS bypass on ${compatibility.bypass_adapters.join(", ")}`);
    if (compatibility.nrpt_rules) details.push(`${compatibility.nrpt_rules} Windows DNS policy rule${compatibility.nrpt_rules === 1 ? "" : "s"}`);
    network.textContent = `${details.join("; ")}. Some requests may avoid Web Guard.`;
  } else if (compatibility.scan_error) {
    badge.textContent = running ? "Protection active" : "Protection off";
    network.textContent = "Windows network compatibility could not be checked yet.";
  } else if (compatibility.vpn_active) {
    badge.textContent = "VPN detected";
    network.classList.add("notice");
    network.textContent = `VPN active: ${compatibility.vpn_names.join(", ")}. Its DNS may take priority; Web Guard will report a confirmed bypass.`;
  } else if (running) {
    badge.textContent = upstream.encrypted ? "Encrypted" : "Protected";
    badge.classList.add("safe");
    network.textContent = "No VPN, alternate adapter DNS, or Windows DNS policy bypass was detected.";
  } else {
    badge.textContent = "Protection off";
    network.textContent = "VPN and DNS-route coverage is verified when protection is on.";
  }
}

function renderThreats() {
  const counts = state.metadata?.category_counts || {};
  const categories = state.settings.categories || {};
  $("#threatGrid").innerHTML = threatDefinitions.map(item => `
    <article class="threat-card">
      <div class="threat-icon"><svg viewBox="0 0 24 24">${item.icon}</svg></div>
      <div class="threat-copy"><h2>${item.title}</h2><p>${item.description}</p><span class="threat-count">${formatNumber(counts[item.id])} domains</span></div>
      <label class="switch" aria-label="Toggle ${item.title}"><input type="checkbox" data-category="${item.id}" ${categories[item.id] !== false ? "checked" : ""}><span></span></label>
    </article>`).join("");
  $$('[data-category]').forEach(input => input.addEventListener("change", updateCategories));
}

function renderExceptions() {
  for (const key of ["allowlist", "custom_blocklist"]) {
    const list = state.settings[key] || [];
    const container = $(`#${key}`);
    container.classList.toggle("is-empty", list.length === 0);
    container.innerHTML = list.length ? list.map(domain => `
      <div class="domain-row"><span>${escapeHtml(domain)}</span><button data-remove="${key}" data-domain="${escapeHtml(domain)}" aria-label="Remove ${escapeHtml(domain)}">×</button></div>
    `).join("") : `<div class="empty-list">${key === "allowlist" ? "No allowed domains." : "No custom blocked domains."}</div>`;
  }
  $$('[data-remove]').forEach(button => button.addEventListener("click", removeDomain));
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"})[char]);
}

async function updateCategories(event) {
  const previous = {...state.settings.categories};
  const next = {...previous, [event.target.dataset.category]: event.target.checked};
  if (!Object.values(next).some(Boolean)) {
    event.target.checked = true;
    toast("Keep at least one protection category enabled.", true);
    return;
  }
  let result;
  try {
    result = await window.pywebview.api.set_categories(next);
  } catch (error) {
    state.settings.categories = previous;
    renderThreats();
    toast(error?.message || "Could not contact the protection service.", true);
    return;
  }
  if (!result?.ok) {
    state.settings.categories = previous;
    renderThreats();
    toast(result?.error || "Could not update protection categories.", true);
    return;
  }
  setServiceStatus(result);
  toast("Protection categories updated.");
}

async function toggleProtection() {
  if (state.busy) return;
  state.busy = true;
  const button = $("#powerButton");
  button.classList.add("busy");
  button.disabled = true;
  try {
    const desired = !Boolean(state.service?.filter_running && state.settings.protection_enabled);
    const result = await window.pywebview.api.set_protection(desired);
    setServiceStatus(result);
    if (!result?.ok) toast(result?.error || "Protection could not be changed.", true);
    else if (result?.warning) toast(`Protection is on, but ${result.warning}`, true);
    else toast(desired ? "Web Guard is protecting this PC and supported browser DNS." : "Protection is off and DNS and browser settings were restored.");
  } catch (error) {
    toast(error?.message || "Could not contact the protection service.", true);
  } finally {
    state.busy = false;
    button.classList.remove("busy");
    button.disabled = false;
  }
}

async function changeDnsProvider(event) {
  if (state.busy) return;
  const previous = state.settings.dns_provider || "cloudflare";
  state.busy = true;
  event.currentTarget.disabled = true;
  try {
    const result = await window.pywebview.api.set_dns_provider(event.currentTarget.value);
    setServiceStatus(result);
    if (!result?.ok) toast(result?.error || "The DNS upstream could not be changed.", true);
    else toast(result.settings.dns_provider === "cloudflare" ? "Encrypted DNS selected." : "Original system DNS selected.");
  } catch (error) {
    state.settings.dns_provider = previous;
    toast(error?.message || "The DNS upstream could not be changed.", true);
  } finally {
    state.busy = false;
    renderConnectionStatus(state.service, Boolean(state.service?.filter_running && state.settings.protection_enabled));
  }
}

async function changeBrowserDns(event) {
  if (state.busy) return;
  const desired = event.currentTarget.checked;
  state.busy = true;
  event.currentTarget.disabled = true;
  try {
    const result = await window.pywebview.api.set_browser_dns_protection(desired);
    setServiceStatus(result);
    if (!result?.ok) toast(result?.error || "Browser Secure DNS control could not be changed.", true);
    else toast(desired ? "Supported browser Secure DNS settings are now controlled." : "Original browser policies were restored.");
  } catch (error) {
    toast(error?.message || "Browser Secure DNS control could not be changed.", true);
  } finally {
    state.busy = false;
    renderConnectionStatus(state.service, Boolean(state.service?.filter_running && state.settings.protection_enabled));
  }
}

async function saveExceptions(nextSettings, successMessage) {
  let result;
  try {
    result = await window.pywebview.api.set_exceptions(nextSettings.allowlist, nextSettings.custom_blocklist);
  } catch (error) {
    toast(error?.message || "Could not contact the protection service.", true);
    return false;
  }
  if (!result?.ok) {
    toast(result?.error || "Could not save this rule.", true);
    return false;
  }
  setServiceStatus(result);
  toast(successMessage);
  return true;
}

async function addDomain(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const key = form.dataset.list;
  const input = form.querySelector("input");
  const value = input.value.trim().toLowerCase();
  if (!value) return;
  const next = {
    ...state.settings,
    allowlist: [...(state.settings.allowlist || [])],
    custom_blocklist: [...(state.settings.custom_blocklist || [])],
  };
  if (next[key].includes(value)) {
    toast("That domain is already in this list.", true);
    return;
  }
  next[key].push(value);
  const message = state.service?.filter_running
    ? "Domain rule added. Reload the site; restart an already-connected browser if needed."
    : "Domain rule saved. Turn protection on before testing it.";
  if (await saveExceptions(next, message)) input.value = "";
}

async function removeDomain(event) {
  const {remove: key, domain} = event.currentTarget.dataset;
  const next = {
    ...state.settings,
    allowlist: [...(state.settings.allowlist || [])],
    custom_blocklist: [...(state.settings.custom_blocklist || [])],
  };
  next[key] = next[key].filter(item => item !== domain);
  await saveExceptions(next, "Domain rule removed.");
}

async function checkDomain(event) {
  event.preventDefault();
  const output = $("#domainCheckResult");
  const value = $("#domainCheck").value;
  output.className = "";
  output.textContent = "Checking the local database…";
  let result;
  try {
    result = await window.pywebview.api.check_domain(value, state.settings);
  } catch (error) {
    output.className = "blocked";
    output.textContent = error?.message || "The local database could not be reached.";
    return;
  }
  if (!result?.ok) {
    output.className = "blocked";
    output.textContent = result?.error || "This domain could not be checked.";
  } else if (result.blocked) {
    output.className = "blocked";
    output.textContent = `${result.domain} is blocked by ${categoryLabel(result.category)}.`;
  } else {
    output.className = "clear";
    output.textContent = `${result.domain} is not in the current local lists. This is not a guarantee that it is safe.`;
  }
}

function categoryLabel(id) {
  return threatDefinitions.find(item => item.id === id)?.title || "your custom rules";
}

function navigate(page) {
  $$(".nav-item").forEach(item => item.classList.toggle("active", item.dataset.page === page));
  $$(".page").forEach(item => item.classList.toggle("active", item.id === `page-${page}`));
}

function attachWindowDrag() {
  const header = $("#dragRegion");
  let drag = null;
  header.addEventListener("pointerdown", event => {
    if (event.button !== 0 || event.target.closest("button")) return;
    drag = {
      pointerId: event.pointerId,
      offsetX: event.clientX,
      offsetY: event.clientY,
      point: null,
      frame: 0,
    };
    header.setPointerCapture(event.pointerId);
    event.preventDefault();
  });
  header.addEventListener("pointermove", event => {
    const current = drag;
    if (!current || current.pointerId !== event.pointerId) return;
    current.point = {
      x: event.screenX - current.offsetX,
      y: event.screenY - current.offsetY,
    };
    if (current.frame) return;
    current.frame = requestAnimationFrame(() => {
      if (drag !== current) return;
      current.frame = 0;
      const point = current.point;
      current.point = null;
      if (point) window.pywebview.api.window_move(point.x, point.y);
    });
  });
  const endDrag = event => {
    if (!drag || drag.pointerId !== event.pointerId) return;
    if (drag.frame) cancelAnimationFrame(drag.frame);
    if (header.hasPointerCapture(event.pointerId)) header.releasePointerCapture(event.pointerId);
    drag = null;
  };
  header.addEventListener("pointerup", endDrag);
  header.addEventListener("pointercancel", endDrag);
}

async function initialize() {
  if (state.ready) return true;
  if (typeof window.pywebview?.api?.bootstrap !== "function") return false;
  if (initializationPromise) return initializationPromise;
  initializationPromise = (async () => {
    try {
      const bootstrap = await Promise.race([
        window.pywebview.api.bootstrap(),
        new Promise((_, reject) => setTimeout(
          () => reject(new Error("The Web Guard interface did not finish starting in time.")),
          4000,
        )),
      ]);
      state.version = bootstrap.version;
      state.metadata = bootstrap.metadata || {};
      $("#versionBadge").textContent = `v${state.version}`;
      $("#databaseCount").textContent = formatNumber(state.metadata.unique_domains);
      const dates = Object.values(state.metadata.sources || {}).map(item => item.last_modified).filter(Boolean).sort();
      if (dates.length) $("#listDate").textContent = `Threat-list snapshot ${dates.at(-1).slice(0, 10)} from The Block List Project. Domain endings use the bundled IANA root-zone list. Allow rules apply to subdomains and override downloaded lists.`;
      setServiceStatus(bootstrap.status);
      state.ready = true;
      void refreshServiceStatus();
      if (!statusTimer) statusTimer = setInterval(() => {
        if (state.busy || !$("#page-protection").classList.contains("active")) return;
        void refreshServiceStatus();
      }, 2500);
      return true;
    } catch (error) {
      setServiceStatus({ok: false, service: "unavailable", filter_running: false, error: error?.message || "Web Guard could not start."});
      toast(error?.message || "Web Guard could not finish starting.", true);
      return false;
    } finally {
      initializationPromise = null;
    }
  })();
  return initializationPromise;
}

async function refreshServiceStatus() {
  if (!state.ready || !window.pywebview?.api) return;
  if (statusPromise) return statusPromise;
  statusPromise = (async () => {
    try {
      const status = await Promise.race([
        window.pywebview.api.status(),
        new Promise((_, reject) => setTimeout(
          () => reject(new Error("The protection service did not answer in time.")),
          3000,
        )),
      ]);
      setServiceStatus(status);
    } catch (error) {
      setServiceStatus({
        ok: false,
        service: "unavailable",
        filter_running: false,
        error: error?.message || "The protection service is unavailable.",
      });
    } finally {
      statusPromise = null;
    }
  })();
  return statusPromise;
}

function startInitialization() {
  if (state.ready) return;
  // pywebview creates the `api` object before it populates the callable
  // methods. Do not mistake that intermediate object for a ready bridge.
  if (typeof window.pywebview?.api?.bootstrap === "function") {
    void initialize().then(started => {
      if (!started) setTimeout(startInitialization, 1000);
    });
  } else {
    setTimeout(startInitialization, 100);
  }
}

// Register immediately. pywebviewready can precede DOMContentLoaded on a fast
// WebView2 launch, so the polling fallback also handles an already-fired event.
window.addEventListener("pywebviewready", startInitialization);

document.addEventListener("DOMContentLoaded", () => {
  $$(".nav-item").forEach(item => item.addEventListener("click", () => navigate(item.dataset.page)));
  $("#powerButton").addEventListener("click", toggleProtection);
  $("#domainCheckForm").addEventListener("submit", checkDomain);
  $("#dnsProvider").addEventListener("change", changeDnsProvider);
  $("#browserDnsToggle").addEventListener("change", changeBrowserDns);
  $$(".add-domain").forEach(form => form.addEventListener("submit", addDomain));
  $("#minimizeButton").addEventListener("click", () => window.pywebview.api.window_minimize());
  $("#closeButton").addEventListener("click", () => window.pywebview.api.window_close());
  attachWindowDrag();
  startInitialization();
});
