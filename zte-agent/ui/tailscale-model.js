'use strict';
((globalThis) => {
  const ADMIN_CONSOLE_URL = 'https://login.tailscale.com/admin/machines';
  const PACKAGES_URL = 'https://pkgs.tailscale.com/stable/#static';
  const HOSTNAME_RE = /^[A-Za-z0-9-]+$/;
  const VERSION_RE = /^\d+(?:\.\d+)*$/;
  const HEX64_RE = /^[0-9a-fA-F]{64}$/;
  const OCTET_RE = /^\d{1,3}$/;
  const PREFIX_RE = /^\d{1,2}$/;

  function cleanDnsName(raw) {
    return String(raw || '').trim().replace(/\.+$/, '');
  }

  function safeLoginUrl(raw) {
    const text = String(raw || '').trim();
    if (!text) return '';
    let url;
    try { url = new URL(text); } catch { return ''; }
    if (url.protocol !== 'https:' || !url.hostname) return '';
    return url.href;
  }

  function validVersion(raw) {
    const text = String(raw || '').trim();
    return text.length > 0 && VERSION_RE.test(text);
  }

  function packageUrl(version) {
    const text = String(version || '').trim();
    return validVersion(text) ? `https://pkgs.tailscale.com/stable/tailscale_${text}_arm64.tgz` : '';
  }

  function validCidr(raw) {
    const text = String(raw || '').trim();
    const slash = text.indexOf('/');
    if (slash < 1 || text.indexOf('/', slash + 1) !== -1) return false;
    const addr = text.slice(0, slash), prefix = text.slice(slash + 1);
    if (!PREFIX_RE.test(prefix) || Number(prefix) > 32) return false;
    const octets = addr.split('.');
    return octets.length === 4 && octets.every(part => OCTET_RE.test(part) && Number(part) <= 255);
  }

  function parseRoutes(raw) {
    const seen = new Set(), routes = [];
    for (const part of String(raw || '').split(/[\s,]+/)) {
      const route = part.trim();
      if (!route || seen.has(route)) continue;
      seen.add(route);
      routes.push(route);
    }
    return routes;
  }

  function hostnameProblem(raw) {
    const value = String(raw || '').trim();
    if (!value || value.length > 63 || !HOSTNAME_RE.test(value)) {
      return 'Hostname must be 1–63 ASCII letters, digits or hyphens.';
    }
    return '';
  }

  function routesProblem(raw) {
    for (const route of parseRoutes(raw)) {
      if (!validCidr(route)) {
        return `Invalid IPv4 CIDR route: ${route} (use format like 192.168.0.0/24).`;
      }
    }
    return '';
  }

  function configProblem({hostname, routesText}) {
    return hostnameProblem(hostname) || routesProblem(routesText);
  }

  function configBaseline(status) {
    const data = status || {};
    return {
      hostname: typeof data.hostname === 'string' && data.hostname.trim() ? data.hostname.trim() : 'u60-pro',
      advertise_routes: Array.isArray(data.advertise_routes) ? data.advertise_routes.map(item => String(item).trim()).filter(Boolean) : [],
      tailscale_ssh: data.tailscale_ssh === true,
      hold_wakelock: data.hold_wakelock !== false
    };
  }

  function sameList(left, right) {
    return left.length === right.length && left.every((item, index) => item === right[index]);
  }

  function configDiff(baseline, draft) {
    const patch = {};
    const hostname = String(draft.hostname || '').trim();
    const routes = parseRoutes(draft.routesText);
    const ssh = draft.tailscale_ssh === true;
    const wakelock = draft.hold_wakelock === true;
    if (hostname !== baseline.hostname) patch.hostname = hostname;
    if (!sameList(routes, baseline.advertise_routes)) patch.advertise_routes = routes;
    if (ssh !== baseline.tailscale_ssh) patch.tailscale_ssh = ssh;
    if (wakelock !== baseline.hold_wakelock) patch.hold_wakelock = wakelock;
    return patch;
  }

  function authKeyProblem(raw) {
    const value = String(raw || '').trim();
    if (!value) return 'Enter a Tailscale auth key (for example tskey-auth-…).';
    if (/\s/.test(value)) return 'Auth keys cannot contain spaces or line breaks.';
    return '';
  }

  function versionProblem(raw) {
    const value = String(raw || '').trim();
    if (!value) return 'Enter a Tailscale version number (for example 1.86.2).';
    if (/^[vV]\d/.test(value)) return 'Enter the version without a leading “v” (for example 1.86.2).';
    if (!VERSION_RE.test(value)) return 'Version may contain only digits and dots (for example 1.86.2).';
    return '';
  }

  function sha256Problem(raw) {
    const value = String(raw || '').trim();
    if (!value) return 'Enter the 64-character SHA-256 checksum for the arm64 .tgz archive.';
    if (!HEX64_RE.test(value)) return 'SHA-256 checksum must be exactly 64 hexadecimal characters.';
    return '';
  }

  function updateProblem({version, sha256}) {
    return versionProblem(version) || sha256Problem(sha256);
  }

  function updateRequest({version, sha256}) {
    return {
      version: String(version || '').trim(),
      sha256: String(sha256 || '').trim().toLowerCase()
    };
  }

  function formatExpiry(raw, expired, nowMs = Date.now()) {
    if (expired === true) return 'Expired';
    const text = String(raw || '').trim();
    if (!text) return '—';
    if (text.startsWith('0001-')) return 'Never expires';
    const parsed = Date.parse(text);
    if (!Number.isFinite(parsed)) return text;
    if (parsed <= nowMs) return 'Expired';
    return new Date(parsed).toISOString().slice(0, 10);
  }

  function ageLabel(unixSeconds, nowSeconds = Date.now() / 1000) {
    const at = Number(unixSeconds);
    if (!Number.isFinite(at) || at <= 0 || at > 253402300800) return '';
    const age = Math.max(0, nowSeconds - at);
    if (age < 60) return 'just now';
    if (age < 3600) return `${Math.floor(age / 60)} min ago`;
    if (age < 86400) return `${Math.floor(age / 3600)} h ago`;
    return `${Math.floor(age / 86400)} d ago`;
  }

  function lastUpdateSummary(lastUpdate, nowSeconds = Date.now() / 1000) {
    if (!lastUpdate || typeof lastUpdate !== 'object') return null;
    const version = String(lastUpdate.version || '').trim() || 'unknown';
    const when = ageLabel(lastUpdate.finished_at, nowSeconds);
    const suffix = when ? ` · ${when}` : '';
    if (lastUpdate.ok === true) {
      return {ok: true, text: `Installed v${version}${suffix}.`};
    }
    const error = String(lastUpdate.error || 'update failed').trim();
    return {ok: false, text: `Update to v${version} failed${suffix}: ${error}`};
  }

  function view(status) {
    if (!status || typeof status !== 'object') {
      return {
        state: 'unknown', tone: 'off', chip: 'WAITING',
        title: 'Checking Tailscale',
        detail: 'Connect and unlock the console to read Tailscale status.',
        installed: false, enabled: false, enrolled: false, updating: false, running: false,
        loginUrl: '', canEnable: false, canDisable: false, canLogout: false,
        canLoginUrl: false, canAuthKey: false, canConfig: false, canUpdate: false,
        authReason: 'Waiting for Tailscale status.'
      };
    }
    const installed = status.installed === true;
    const enabled = status.enabled === true;
    const enrolled = status.enrolled === true;
    const daemonRunning = status.daemon_running === true;
    const updating = status.updating === true || status.state === 'updating';
    const running = status.backend_state === 'Running';
    const state = String(status.state || 'unknown');
    const dnsName = cleanDnsName(status.dns_name);
    const loginUrl = safeLoginUrl(status.login_url);
    const meta = {
      not_installed: ['off', 'NOT INSTALLED', 'Tailscale is not installed', 'Install the official ARM64 Tailscale binaries below to enable encrypted remote access.'],
      updating: ['busy', 'UPDATING', 'Installing or upgrading Tailscale', 'Downloading, verifying SHA-256 and swapping binaries in the background. On cellular this can take several minutes.'],
      disabled: enrolled
        ? ['off', 'DISABLED', 'Tailscale is off', 'Your node identity is saved. Enable Tailscale to reconnect to your tailnet.']
        : ['off', 'NOT ENROLLED', 'Tailscale is ready to set up', 'Use a browser login link or an auth key below to enroll this router into your tailnet.'],
      respawning: ['busy', 'STARTING', 'Starting Tailscale daemon', 'Waiting for the supervised tailscaled process to come up.'],
      starting: ['busy', 'STARTING', 'Waiting for Tailscale daemon', 'tailscaled is starting up and opening its local control socket.'],
      connecting: ['busy', 'CONNECTING', 'Connecting to Tailscale', 'Negotiating with the Tailscale control plane and relay network.'],
      awaiting_setup: ['warn', 'AWAITING SETUP', 'Sign in to join your tailnet', 'Open a browser login link or submit a pre-authenticated auth key below.'],
      needs_login: ['warn', 'NEEDS LOGIN', 'Re-authentication required', 'This enrolled node needs to sign in again. Its node key may have expired or been revoked.'],
      pending_approval: ['warn', 'PENDING APPROVAL', 'Waiting for admin approval', 'Approve this machine in the Tailscale admin console to bring it online.'],
      paused: ['off', 'PAUSED', 'Tailscale backend is stopped', 'Enable Tailscale or wait for the supervisor to bring the backend up.'],
      healthy: ['active', 'CONNECTED', dnsName || status.hostname || 'Tailscale connected', 'Connected to your tailnet in userspace mode. Console and API traffic over Tailscale are accepted.'],
      degraded: ['warn', 'OFFLINE', 'Tailscale is offline', 'The daemon is running, but this node is currently offline on the tailnet. Check your internet uplink.']
    }[state] || ['off', 'UNKNOWN', 'Tailscale status unknown', 'The router reported an unrecognized Tailscale state.'];

    const [tone, chip, title, detail] = meta;
    const canEnable = installed && !updating && !enabled;
    const canDisable = installed && !updating && (enabled || daemonRunning);
    const canLogout = installed && !updating && (
      enrolled || daemonRunning || ['healthy', 'degraded', 'needs_login', 'pending_approval', 'paused', 'awaiting_setup'].includes(state)
    );
    const canLoginUrl = installed && !updating && !running && !(enrolled && !enabled);
    const canAuthKey = installed && !updating && !running;
    let authReason = '';
    if (!installed) authReason = 'Install Tailscale below before enrolling this router.';
    else if (updating) authReason = 'Wait for the current install or upgrade to finish.';
    else if (running) authReason = 'Already enrolled and connected. Log out first to switch accounts or re-enroll with a new key.';
    else if (enrolled && !enabled) authReason = 'Enable Tailscale above before requesting a browser login link, or re-enroll with an auth key.';

    return {
      state, tone, chip, title, detail,
      installed, enabled, enrolled, updating, running, loginUrl,
      canEnable, canDisable, canLogout, canLoginUrl, canAuthKey,
      canConfig: !updating, canUpdate: !updating, authReason
    };
  }

  function connectionLabel(status) {
    if (!status || status.backend_state !== 'Running') return '—';
    const relay = String(status.relay || '').trim();
    if (status.direct === true) return relay ? `Direct · DERP ${relay}` : 'Direct';
    return relay ? `Relayed · DERP ${relay}` : 'Relayed';
  }

  function facts(status, nowMs = Date.now()) {
    const data = status || {};
    const ips = Array.isArray(data.tailscale_ips) ? data.tailscale_ips.filter(Boolean) : [];
    const dnsName = cleanDnsName(data.dns_name);
    const routes = Array.isArray(data.advertise_routes) ? data.advertise_routes.filter(Boolean) : [];
    const version = data.client_version
      ? String(data.client_version)
      : data.pinned_version
        ? `${data.pinned_version} (pinned)`
        : data.installed === true
          ? 'Installed'
          : 'Not installed';
    const wakelock = data.wakelock_held === true
      ? 'Held'
      : data.hold_wakelock === false
        ? 'Disabled'
        : 'Standby';
    return [
      ['Tailscale IP', ips.length ? ips.join(' · ') : '—', true],
      ['MagicDNS', dnsName || '—', true],
      ['Connection', connectionLabel(data), false],
      ['Version', version, true],
      ['Key expiry', formatExpiry(data.key_expiry, data.expired, nowMs), false],
      ['Wakelock', wakelock, false],
      ['Advertised routes', routes.length ? routes.join(', ') : 'None', true],
      ['Tailscale SSH', data.tailscale_ssh === true ? 'Enabled' : 'Disabled', false]
    ];
  }

  function alerts(status) {
    if (!status || typeof status !== 'object') return [];
    const list = [], push = text => {
      const clean = String(text || '').trim();
      if (clean && !list.includes(clean)) list.push(clean);
    };
    if (status.error) push(status.error);
    if (status.expired === true) {
      push('Node key has expired. Re-authenticate below or disable key expiry in the Tailscale admin console.');
    }
    if (status.state === 'pending_approval') {
      push('Approve this machine in the Tailscale admin console to bring it online.');
    }
    if (Array.isArray(status.health)) {
      for (const item of status.health) push(item);
    }
    return list;
  }

  function configConfirmation(patch, enabled) {
    const lines = [];
    if (Object.hasOwn(patch, 'hostname')) {
      lines.push(`Hostname becomes “${patch.hostname}”.${enabled ? ' If you open this console by MagicDNS name, you may need the new name afterward.' : ''}`);
    }
    if (Object.hasOwn(patch, 'advertise_routes')) {
      lines.push(patch.advertise_routes.length
        ? `Advertised subnet routes become ${patch.advertise_routes.join(', ')} (approve them in the Tailscale admin console).`
        : 'All advertised subnet routes will be cleared.');
    }
    if (Object.hasOwn(patch, 'tailscale_ssh')) {
      lines.push(patch.tailscale_ssh
        ? 'Tailscale SSH will be enabled for tailnet peers allowed by your ACLs.'
        : 'Tailscale SSH will be disabled.');
    }
    if (Object.hasOwn(patch, 'hold_wakelock')) {
      lines.push(patch.hold_wakelock
        ? 'The router will hold a wakelock while Tailscale is enabled.'
        : 'The wakelock will be released; the router may sleep and interrupt remote reachability.');
    }
    return lines.join(' ');
  }

  const api = {
    ADMIN_CONSOLE_URL,
    PACKAGES_URL,
    cleanDnsName,
    safeLoginUrl,
    validVersion,
    packageUrl,
    validCidr,
    parseRoutes,
    hostnameProblem,
    routesProblem,
    configProblem,
    configBaseline,
    configDiff,
    authKeyProblem,
    versionProblem,
    sha256Problem,
    updateProblem,
    updateRequest,
    formatExpiry,
    ageLabel,
    lastUpdateSummary,
    view,
    facts,
    alerts,
    configConfirmation
  };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else globalThis.OpenU60Tailscale = api;
})(globalThis);
