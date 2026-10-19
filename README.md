# Proxmox Manager

A single web dashboard for many Proxmox VE hosts and clusters. Built for an MSP
that looks after Proxmox boxes at a lot of different clients.

What it shows, per host (or whole cluster):

- Reachability, Proxmox VE version (flags clusters whose nodes are on mixed versions), cluster name and quorum
- CPU, RAM and storage utilisation — current value plus a rolling average (default: last 60 minutes)
- Nodes online, running / stopped VMs and containers, uptime
- Full node list with kernel, CPU model, load average, root filesystem
- Every VM / LXC with status, CPU, RAM, disk, uptime and tags
- Every storage with usage (shared storage counted once per cluster)
- Physical disks per node with model, serial, type, size, PVE health and SSD wear
- **SMART reads on demand** — one disk or every disk on a node, with health, temperature,
  power-on hours, reallocated / pending sectors and the full attribute table or raw `smartctl` output.
  Results are stored so the last reading is visible without re-scanning.
- A one-click **Open PVE web UI** link per host (overridable, e.g. for a VPN-side address)
- **Pending apt updates** per node (with "includes a kernel" flag) and **reboot pending**
  detection (newer kernel installed than the one running) straight from the API
- **Update node** — runs `apt-get update && apt-get dist-upgrade -y` over SSH, streams the
  output live, tells you whether a reboot is needed and why, with optional auto-reboot
- **Reboot node** — with a guest-count warning, waits for the node to come back and reports
  the new kernel
- A link that opens the node's interactive **upgrade shell** in the PVE web UI as a fallback
- **Guest actions** (admin): Start / Stop / Restart and Console on every VM and container row,
  plus *More* with a Start at boot switch, network adapters (bridge / VLAN), snapshot, backup
  and disk expansion
- Hover-able CPU / RAM / storage history charts (1 h / 6 h / 24 h)

Plus a fleet summary across everything, filtering / grouping by client, user accounts with
admin and viewer roles, and a small JSON API.

Stack: Python 3.11+, FastAPI, [proxmoxer](https://github.com/proxmoxer/proxmoxer), SQLAlchemy +
SQLite, vanilla HTML/JS. No CDN or internet dependency at runtime, so it works on isolated
management networks.

---

## 1. Install (Debian 12 / Ubuntu 22.04+ VM or LXC)

An unprivileged LXC with 1 vCPU, 512 MB RAM and 4 GB disk is plenty.

```bash
# copy this folder to the box, then:
cd proxmox-manager
chmod +x install.sh
sudo ./install.sh
```

The installer:

1. installs `python3`, `python3-venv`, `rsync`
2. copies the app to `/opt/proxmox-manager` and creates a venv there
3. creates a `proxmox-manager` system user and `/var/lib/proxmox-manager` for the SQLite DB
4. generates `/opt/proxmox-manager/.env` with a random `PM_SECRET_KEY`
5. prompts you to create the first admin user
6. installs and starts the `proxmox-manager` systemd service on port 8080

Then open `http://<server-ip>:8080/`.

Re-running `install.sh` upgrades in place and keeps `.env` and the database.

### Upgrading

Copy the new files over the folder you installed from and re-run `sudo ./install.sh`
(keeps `.env` and the database), or for a quick patch copy the changed files straight
into `/opt/proxmox-manager/` and `systemctl restart proxmox-manager`.

### Useful commands

```bash
journalctl -u proxmox-manager -f                          # logs
systemctl restart proxmox-manager                         # after editing .env
cd /opt/proxmox-manager
runuser -u proxmox-manager -- venv/bin/python manage.py list-users
runuser -u proxmox-manager -- venv/bin/python manage.py create-admin <name>
runuser -u proxmox-manager -- venv/bin/python manage.py reset-password <name>
runuser -u proxmox-manager -- venv/bin/python manage.py set-role <name> admin|viewer
```

### Running it by hand (dev / testing)

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # set PM_SECRET_KEY, and PM_DATA_DIR=./data
python manage.py create-admin admin
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

---

## 2. Give the dashboard access to each Proxmox host

Create a read-only user and an API token on each host (or once per cluster — users and
tokens are cluster-wide).

### Option A: shell (any node, as root)

```bash
pveum user add monitor@pve --comment "Proxmox Manager dashboard"
pveum acl modify / --users monitor@pve --roles PVEAuditor
pveum user token add monitor@pve dashboard --privsep 0
```

The last command prints the token secret **once** — copy it.

### Option B: web UI

1. Datacenter → Permissions → Users → **Add**: user `monitor`, realm `Proxmox VE authentication server`.
2. Datacenter → Permissions → **Add → User Permission**: path `/`, user `monitor@pve`, role `PVEAuditor`.
3. Datacenter → Permissions → API Tokens → **Add**: user `monitor@pve`, token ID `dashboard`,
   **untick Privilege Separation**. Copy the secret from the popup — it is shown only once.

### Add it in the dashboard

| Field        | Value                                                            |
|--------------|------------------------------------------------------------------|
| Auth type    | API token                                                        |
| Token ID     | `monitor@pve!dashboard` — exactly as the API Tokens page shows it |
| Token secret | the UUID Proxmox printed                                         |

`PVEAuditor` grants `Sys.Audit` (versions, node status, disks, SMART), `Datastore.Audit`
and `VM.Audit`: everything the dashboard needs and nothing that can change anything.

### Privilege Separation — the usual gotcha

A token created **with** Privilege Separation (the default in the web UI) has *no*
permissions of its own, even if the user is root. Proxmox will accept the token and then
return an empty node list; the dashboard reports this as
"Authenticated, but the token has no permissions". Either recreate the token with the
box unticked, or give the token its own ACL:

```bash
pveum acl modify / --tokens 'monitor@pve!dashboard' --roles PVEAuditor
```

(web UI: Datacenter → Permissions → Add → **API Token Permission**, path `/`, role `PVEAuditor`).

Username/password auth is also supported (e.g. `root@pam`, or `monitor@pve` with a
password set via `pveum passwd monitor@pve`). Tokens are preferred: nothing to expire,
no 2FA interaction, and you can revoke one host's access with
`pveum user token remove monitor@pve dashboard`.

### Pending-update counts need Sys.Modify

Proxmox gates "list available updates" (`GET /nodes/{node}/apt/update`) behind
`Sys.Modify`, which `PVEAuditor` does not include. With a plain auditor token the node
shows **updates: n/a**; everything else still works, and *Check updates* over SSH gives
the real answer. To get the badge without SSH, add that one privilege:

```bash
pveum role add PVEAuditorUpdates -privs "Sys.Audit,Datastore.Audit,VM.Audit,Sys.Modify"
pveum acl modify / --users monitor@pve --roles PVEAuditorUpdates
```

(`Sys.Modify` is a broad privilege; a root token has it already.)
Reboot-pending detection only needs `Sys.Audit` and works with any token.

---

## 3. Updating nodes

There are two ways to work, and you can mix them per host.

### Without SSH (default)

Nothing to set up beyond the API token. Per node you get:

- **Refresh package list**: runs Proxmox's own `apt update` task through the API
  (`POST /nodes/{node}/apt/update`), streams its log, then lists the pending updates and flags
  kernel packages. Needs `Sys.Modify`.
- **Upgrade shell ↗**: opens the node's `pveupgrade` terminal from the Proxmox web UI in a new
  tab (the same as Node → Updates → Upgrade). This is where the updates get installed. Proxmox
  only allows this console for a real `root@pam` login (API tokens are refused), so the button
  signs your browser in first:
  - hosts added with **username/password as root@pam**: one click, it uses the stored password;
  - other hosts: it asks for the root password once. Tick *Remember for this host* and it's one
    click from then on (stored encrypted like the other credentials; *Forget it* under the node
    list removes it).

  How it works: the dashboard gets a `root@pam` ticket from the host, and the new tab posts that
  ticket to the host's own login page (`/api2/html/access/ticket`). Proxmox sets its normal
  login cookie for that browser (valid 2 hours) and the tab then opens the console. The root
  password itself never goes to the browser. Accounts with two-factor login can't be signed in
  this way; log in to the Proxmox UI by hand for those.

  Self-signed certificates: the browser has to accept the host's certificate before Proxmox
  can set its login cookie (a login sent to an untrusted host just lands on the warning page,
  which is what caused "Connection failed (Error 401: No ticket)"). The button checks this
  first. If the certificate isn't accepted yet, the new tab shows the host with the warning;
  click Advanced → Proceed (Chrome) or Accept the Risk and Continue (Firefox) and the shell
  opens by itself. Once per browser.
- **Reboot node**: `POST /nodes/{node}/status command=reboot` through the API, then waits for
  the node's uptime to reset and reports the kernel it came back on. Needs `Sys.PowerMgmt`.

Typical flow: Refresh package list → Upgrade shell ↗ (run the upgrade) → the poller shows
**reboot pending** if a new kernel was installed → Reboot node.

A `root@pam` token without privilege separation has `Sys.Modify` and `Sys.PowerMgmt`. With a
`PVEAuditor`-only token the jobs fail with a message naming the missing privilege.

### With SSH (optional)



The PVE API has no "run apt" call (the web UI's own Upgrade button just opens a root
shell), so fully hands-off upgrades need SSH. Enabling SSH on a host adds **Check updates (SSH)**
and **Update node (SSH)**, and Reboot node then goes over SSH too. Leave it off if you prefer
the no-SSH flow above.

#### One-time: create the dashboard key

Hosts → **Dashboard SSH key** → *Generate key*. The dashboard keeps an ed25519 keypair
(private half encrypted in its database). The card then has three views:

- **Install command**: pick the host in *For host* and you get a ready-to-paste script with the
  key filled in. Paste it into a root shell on the node (Proxmox web UI → node → Shell). It is
  safe to run more than once, keeps existing keys, works with Proxmox's
  `/root/.ssh/authorized_keys → /etc/pve/priv/authorized_keys` symlink, and prints
  `OK: Proxmox Manager key installed on <hostname>`.
- **Install from your PC**: the same as a single `ssh root@<host> '...'` command for a Linux/macOS
  terminal; it asks for that node's root password once.
- **Public key**: just the key line.

Then click **Enable SSH & test**: the dashboard connects with its key, and only if that works
turns SSH on for the host (root, port 22). Copy works on plain http too.

Proxmox ships with `PermitRootLogin yes` in `/etc/ssh/sshd_config`, so key login as root
works out of the box. If a client hardened that to `prohibit-password`, keys still work;
only password auth is blocked.

#### Per host

Edit the host → tick **SSH access** → auth *Dashboard key* (or paste a private key, or
a password), user `root`, port `22` → *Test SSH* → Save.

Clusters: each node is reached on the IP it reports in cluster status (the corosync
address). If the dashboard can't reach that network, set **Per-node SSH address
overrides** (`pve1=10.0.0.11`, one per line).

Host keys are pinned on first use; if a node's key ever changes the job refuses to run
and says so. After a legitimate reinstall, Edit host → *Forget SSH host keys*.

#### Repository problems (enterprise repo without a subscription)

A fresh Proxmox install points at the paid **enterprise** repositories. Without a subscription key
`enterprise.proxmox.com` answers `401 Unauthorized`, so apt only sees the Debian repos and
every Proxmox package (pve-manager, kernel, ceph) is silently skipped. Check updates, Update node
and Refresh package list detect this, finish with status **warning** instead of "done", and show
ready-to-paste commands (matched to the node's Debian release and Ceph version) that disable the
enterprise repo and add the free no-subscription repos. If the client has a subscription, add the
key instead (Node → Subscription).

**Switch to no-subscription** (button on nodes flagged *enterprise repo, no subscription*): does
through the Proxmox API exactly what Node → Updates → Repositories does by hand — disables the
enabled enterprise entries (PVE and Ceph), adds the No-Subscription repo and the matching Ceph
no-subscription repo, then refreshes the package lists. No SSH needed; the token needs
`Sys.Modify` (a root@pam token without privilege separation has it). Safe to run twice.

#### What Update node (SSH) actually does

1. Checks apt/dpkg are not already locked.
2. Starts, **detached on the node** (`setsid` + `nohup`, log in `/var/log/proxmox-manager/`):
   ```
   apt-get update
   apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade
   apt-get -y autoremove
   ```
   with `DEBIAN_FRONTEND=noninteractive`, so a package prompt can never hang it and an SSH
   drop (sshd itself may be upgraded) cannot kill it. The dashboard tails the log and
   reconnects if needed.
3. Afterwards checks `/var/run/reboot-required` and compares the running kernel with the
   newest installed `proxmox-kernel-*` package, then reports **Reboot required** with the
   reason, or **No reboot required**.
4. Reboots only if you ticked *Reboot automatically afterwards* and it was required.

`dist-upgrade` is what Proxmox's own `pveupgrade` runs; plain `apt upgrade` can leave a
PVE system half-updated.

**Check updates** does `apt-get update` plus a simulated dist-upgrade and lists what
would change, flagging kernel packages. **Reboot node** issues `systemctl reboot`, waits
for SSH to go away and come back (up to 20 min), and reports the new kernel. Every guest on
that node stops (or is migrated first if it is HA-managed) — the confirm dialog shows how
many are running. Jobs are one-at-a-time per node, admin-only, require typing the node
name, and are listed under *Recent jobs* with their full output.

The **Upgrade shell ↗** button opens `https://<host>:8006/?console=upgrade&node=<node>&xtermjs=1`
after signing the browser in as `root@pam` (see above). Viewers get a plain link and need their
own Proxmox login.

Clusters: add any one node. The API returns the whole cluster — all nodes, guests
and storage are collected and aggregated. If that node goes down the host shows an
error until it is back; add a second node as a separate entry if you want redundancy.

SSL: most PVE hosts use self-signed certificates, so **Verify SSL** is off by default.
Turn it on for hosts with a proper certificate (ACME in Datacenter → ACME, or a CA
cert the dashboard server trusts).

Network: the dashboard server needs TCP 8006 to each host. Everything else is pull-only.

---

## 4. Using it

**Dashboard** — fleet tiles at the top, one card per host below. Group by client, sort by
CPU / RAM / storage / problems, and filter by any text (name, client, IP, version, node
name). Cards refresh every 30 s from the cache; the background poller hits each host
every `PM_POLL_INTERVAL` seconds (default 60). *Refresh* polls one host immediately;
*Refresh all* kicks off a full cycle. The small tick on each bar marks the rolling average.

**Host page** — version / cluster / guests / CPU / RAM / storage tiles, history charts
(hover for the exact value and time; 1 h / 6 h / 24 h), a block per node with update and
reboot-pending badges and the Check updates / Update node / Reboot node / Upgrade shell
buttons, then guests and storage tables and recent jobs. *Disks / SMART* on a node lists its
physical disks; *Scan* reads SMART for one disk, *Scan all disks* does the whole node.
*Details* opens the full attribute table (ATA) or raw `smartctl` text (NVMe / SAS).

> SMART reads go through the Proxmox API (`/nodes/{node}/disks/smart`), which runs
> `smartctl` on the node and returns the current health and attributes. Starting a
> SMART *self-test* (`smartctl -t short`) is not exposed by the API, so that still needs
> an SSH session; it would be a reasonable v2 feature with per-host SSH keys.

**Guest actions** (admin, 1.2.9) — each row in the Guests table has:

- **Start** — starts the guest straight away.
- **Stop** — asks how: *Shut down cleanly* (the guest OS gets 3 minutes, optionally powered
  off if it hasn't finished) or *Power off now* (hard stop; type the guest ID to confirm).
- **Restart** — clean reboot after one confirmation; pending config changes are applied.
- **Console ↗** — signs the browser in as root@pam exactly like the Upgrade shell (same saved
  password) and opens noVNC for VMs or xterm.js for containers in a new tab.
- **More ▾** — a dialog with:
  - **Boot and network** (live from the guest config): whether *Start at boot* is on, with a
    *Turn on* / *Turn off* button (one confirmation, nothing restarts, the change is recorded
    as a job; refused if the guest's config was changed in Proxmox at the same moment), plus
    boot order and up/down delays when set (read only), and one row per network adapter with
    bridge, VLAN tag (or *untagged*, with trunks when set), MAC, model, firewall flag and
    link state (*down* when Disconnect is ticked). Containers also show the configured
    IP / gateway (or `dhcp`). VM IPs aren't in the config, so they aren't shown.
  - **Snapshot**: name (default `pm-YYYYMMDD-HHMM`), optional description, *Include RAM* for a
    running VM. Rollback and delete stay in the Proxmox web UI.
  - **Backup**: storage (only storages on that node that take backups), mode
    (snapshot / suspend / stop), compression (hidden for Proxmox Backup Server), notes
    (`{{guestname}}` by default).
  - **Expand disk**: pick a disk (VM disks except CD-ROMs and EFI/TPM, container rootfs and
    volume mount points, never bind mounts), add N GiB, confirm. Grow only; Proxmox can't
    shrink disks. For VMs, extend the partition and filesystem inside the guest afterwards;
    for containers Proxmox grows the filesystem itself.

Templates only get *More* (backup). Each action runs as a job through the Proxmox API (no
SSH), follows the Proxmox task log live in the job dialog, and is recorded with the user who
started it. One job per guest at a time; a node reboot waits for guest jobs on that node.
Viewers get a plain console link (they log in to Proxmox themselves) and no action buttons.

Privileges the token needs on the Proxmox side: `VM.Audit` (boot and network info, which the
monitoring token already has), `VM.Config.Options` (Start at boot on/off), `VM.PowerMgmt`
(start/stop/restart),
`VM.Snapshot` (snapshot), `VM.Backup` plus `Datastore.AllocateSpace` on the backup storage
(backup), `VM.Audit` and `VM.Config.Disk` plus `Datastore.AllocateSpace` (expand disk). A
root@pam token without privilege separation has all of them; with a read-only token the job
fails with a message naming the missing privilege.

**Hosts** (admin) — add / edit / delete hosts, test a connection before saving, disable
polling for a host without deleting it. Credentials are encrypted at rest with a key
derived from `PM_SECRET_KEY`.

**Users** (admin) — add users as *admin* or *viewer*. Viewers see everything and can run
SMART reads and refreshes, but cannot change hosts or users.

---

## 5. HTTPS

`deploy/enable-https.sh` puts the dashboard behind nginx with your certificate and locks the
app to localhost. It needs an internal DNS record for the name the dashboard will be reached
by (`--name`, e.g. `proxmox.example.com`) pointing at this machine, and the certificate as a
PFX or as PEM files:

```bash
cd /opt/proxmox-manager
# no certificate yet: self-signed for this machine's IP (browsers warn once; accept it)
sudo ./deploy/enable-https.sh --self-signed
# with the real certificate (switches to https://proxmox.example.com)
sudo ./deploy/enable-https.sh --pfx /path/to/certificate.pfx --name proxmox.example.com
# or
sudo ./deploy/enable-https.sh --cert /path/to/cert.pem --chain /path/to/intermediate.pem --key /path/to/key.pem --name proxmox.example.com
```

It checks that the key matches, the certificate covers the name and hasn't expired, stores it
in `/etc/ssl/proxmox-manager/`, writes the nginx site (port 80 redirects to https, port 443
proxies to `127.0.0.1:8080`, HSTS and anti-framing headers), checks `https://<name>/healthz`
through nginx, and only then sets `PM_HOST=127.0.0.1` and `PM_SESSION_COOKIE_SECURE=true` in
`.env` (backup kept next to it) and restarts the service. `--self-signed` makes a certificate
for the machine's IP (`--ip` to choose it) and `--name` if given, keeps it across re-runs, serves any
address on 443 and leaves HSTS off so the browser warning can be clicked through; running the
script later with `--pfx` or `--cert` replaces it. `--name` is required with `--pfx` /
`--cert` (the certificate must cover it). `--no-lockdown` stops before the `.env` change. `--help` shows the undo commands.
`deploy/nginx-proxmox-manager.conf.example` is the same site for doing it by hand.

The service only trusts `X-Forwarded-*` headers from `127.0.0.1` (nginx on the same machine).

---

## 6. JSON API

Everything the UI uses is under `/api/` and works with the session cookie:

| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | `/api/dashboard` | any | fleet summary + per-host summaries and averages |
| GET | `/api/hosts/{id}` | any | full host detail incl. nodes, guests, storage, history, stored SMART |
| POST | `/api/hosts/{id}/refresh` | any | poll one host now |
| POST | `/api/refresh-all` | any | poll everything now (background) |
| GET | `/api/hosts/{id}/nodes/{node}/disks` | any | physical disks + last SMART per disk |
| POST | `/api/hosts/{id}/nodes/{node}/smart` | any | `{"devpath": "/dev/sda"}` → SMART read |
| POST | `/api/hosts/{id}/nodes/{node}/smart/all` | any | SMART read of every disk on the node |
| POST | `/api/hosts/{id}/nodes/{node}/refresh-packages` | admin | apt update via the PVE API (no SSH) → `{job_id}` |
| POST | `/api/hosts/{id}/nodes/{node}/api-reboot` | admin | `{"confirm": "<node>"}` → reboot via the PVE API (no SSH) |
| POST | `/api/hosts/{id}/nodes/{node}/check-updates` | admin | start a check-updates job over SSH → `{job_id}` |
| POST | `/api/hosts/{id}/nodes/{node}/upgrade` | admin | `{"confirm": "<node>", "auto_reboot": false}` → start upgrade job |
| POST | `/api/hosts/{id}/nodes/{node}/reboot` | admin | `{"confirm": "<node>"}` → start reboot job |
| POST | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/power` | admin | `{"action": "start\|shutdown\|reboot\|stop", "force_stop": false, "confirm": "<vmid for stop>"}` → `{job_id}` |
| POST | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/snapshot` | admin | `{"snapname": "pre-patch", "description": "", "vmstate": false}` → `{job_id}` |
| GET | `/api/hosts/{id}/nodes/{node}/backup-storages` | admin | storages on the node that take backups |
| POST | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/backup` | admin | `{"storage": "local", "mode": "snapshot", "compress": "zstd", "notes": "{{guestname}}"}` → `{job_id}` |
| GET | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/details` | admin | `{onboot, startup, nets, disks}`: start at boot, boot order, adapters with bridge / VLAN, expandable disks |
| POST | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/onboot` | admin | `{"onboot": true}` → `{job_id}`; Start at boot on/off |
| GET | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/disks` | admin | disks of the guest that can be expanded |
| POST | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/resize` | admin | `{"disk": "scsi0", "add_gb": 10}` → `{job_id}` |
| POST | `/api/hosts/{id}/console-login` | admin | `{"password": "", "remember": false}` → root@pam ticket + login URL for the Upgrade shell |
| DELETE | `/api/hosts/{id}/console-login` | admin | forget the saved root password |
| GET | `/api/jobs/{id}?since=N` | any | job status, result and output (from char N) |
| GET | `/api/hosts/{id}/jobs` | any | last 50 jobs for the host |
| GET/POST | `/api/ssh/key`, `/api/ssh/key/generate` | admin | dashboard SSH public key / regenerate |
| POST | `/api/ssh/test` | admin | test SSH credentials |
| GET/POST/PUT/DELETE | `/api/hosts[/{id}]` | admin | host CRUD |
| POST | `/api/hosts/test` | admin | test credentials without saving |
| GET/POST/PUT/DELETE | `/api/users[/{id}]` | admin | user CRUD |
| POST | `/api/me/password` | any | change own password |
| GET | `/healthz` | public | liveness check |

Scripting example:

```bash
curl -c jar -s -o /dev/null -d 'username=admin&password=...' http://dash:8080/login
curl -b jar -s http://dash:8080/api/dashboard | jq '.hosts[] | {name, version: .summary.version, cpu: .summary.cpu_pct}'
```

---

## 7. Configuration reference (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `PM_SECRET_KEY` | *(required)* | signs sessions, encrypts PVE credentials — never change after hosts are added |
| `PM_HOST` / `PM_PORT` | `0.0.0.0` / `8080` | listen address |
| `PM_DATA_DIR` | `/var/lib/proxmox-manager` | SQLite location |
| `PM_POLL_INTERVAL` | `60` | seconds between poll cycles |
| `PM_PVE_TIMEOUT` | `15` | per-request timeout to a host |
| `PM_POLL_WORKERS` | `8` | hosts polled in parallel |
| `PM_AVERAGE_WINDOW_MINUTES` | `60` | window for the "avg" figures |
| `PM_SAMPLE_RETENTION_HOURS` | `24` | how long samples are kept |
| `PM_SESSION_COOKIE_SECURE` | `false` | set `true` behind HTTPS |
| `PM_SESSION_MAX_AGE` | `43200` | login lifetime, seconds |
| `PM_INITIAL_ADMIN_USERNAME/PASSWORD` | unset | bootstrap admin on first start (remove afterwards) |
| `PM_LOG_LEVEL` | `INFO` | `DEBUG` to see every PVE call failure |

---

## 8. Layout

```
app/
  main.py        FastAPI app, middleware, startup (poller) and error handling
  config.py      settings from .env
  database.py    SQLAlchemy / SQLite
  models.py      User, ProxmoxHost, StatSample, SmartResult
  auth.py        bcrypt, sessions, admin/viewer guards
  crypto.py      Fernet encryption of stored PVE secrets
  pve.py         proxmoxer wrapper: collect summary, updates/kernel state, disks, SMART
  poller.py      background polling loop
  ssh.py         paramiko: dashboard keypair, pinned host keys, connect/run
  jobs.py        check-updates / upgrade / reboot jobs with live output
  routers/       auth pages, HTML pages, JSON API
  templates/     Jinja2 pages
  static/        app.css, app.js
deploy/          systemd unit, nginx example
manage.py        user admin CLI
install.sh       installer / upgrader
```

Ideas for later: SMART self-tests over SSH (`smartctl -t short`), backup job status,
alert thresholds with email/Teams webhooks, ZFS pool health, bulk "update all nodes in
this cluster one at a time".
