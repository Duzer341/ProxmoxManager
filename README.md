# Proxmox Manager

Proxmox Manager is a self-hosted web application for monitoring and maintaining multiple
Proxmox VE hosts and clusters from one interface. It polls each host through the Proxmox
REST API, caches the results in SQLite, and presents version, capacity, update and guest
state across the whole fleet. Administrators can also run node maintenance (package
refresh, upgrade, reboot) and basic guest operations (power, console, snapshot, backup,
disk expansion, start at boot) without opening each host's web UI.

The application has no runtime dependency on external CDNs or internet services and can
run on an isolated management network.

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Proxmox API access](#proxmox-api-access)
- [Configuration](#configuration)
- [HTTPS](#https)
- [Usage](#usage)
- [Node maintenance](#node-maintenance)
- [Guest operations](#guest-operations)
- [SSH integration (optional)](#ssh-integration-optional)
- [Security](#security)
- [API reference](#api-reference)
- [Project layout](#project-layout)
- [Roadmap](#roadmap)

## Features

**Monitoring**

- Reachability, Proxmox VE version (mixed versions within a cluster are flagged), cluster
  name and quorum state
- CPU, memory and storage utilization with current value and rolling average (default
  window 60 minutes), plus 1 h / 6 h / 24 h history charts
- Node inventory: kernel, CPU model, load average, root filesystem, uptime
- Guest inventory: every VM and LXC container with status, CPU, memory, disk, uptime and tags
- Storage inventory with usage; shared storage is counted once per cluster
- Physical disks per node (model, serial, type, size, Proxmox health, SSD wear) and on-demand
  SMART reads with stored results
- Pending apt updates per node, kernel updates flagged, and reboot-pending detection
  (installed kernel newer than the running kernel)
- Detection of enterprise repositories configured without a subscription
- Fleet summary with grouping by client, sorting and free-text filtering

**Node maintenance** (admin)

- Package list refresh and node reboot through the Proxmox API
- Node terminal (root shell, as Node → Shell) and interactive upgrade shell (`pveupgrade`) opened
  in the browser with automatic `root@pam` sign-in
- Optional SSH mode: unattended `dist-upgrade` with live output, reboot-required analysis and
  optional automatic reboot
- One-step switch from enterprise to no-subscription repositories

**Guest operations** (admin)

- Start, clean shutdown, hard stop and restart
- Browser console (noVNC for VMs, xterm.js for containers)
- Snapshot, backup (vzdump) and disk expansion
- Start-at-boot view and toggle, startup order, and network adapter details (bridge, VLAN tag,
  trunks, MAC, model, firewall, link state)

**Access control**

- Local user accounts with `admin` and `viewer` roles
- JSON API used by the UI, available to scripts with a session cookie

## Architecture

| Component | Implementation |
|---|---|
| Web application | Python 3, FastAPI, Uvicorn, Jinja2 templates, vanilla JavaScript |
| Proxmox access | `proxmoxer` (REST API, port 8006); `paramiko` for optional SSH |
| Storage | SQLite (WAL mode) via SQLAlchemy 2 in `/var/lib/proxmox-manager` |
| Service | systemd unit `proxmox-manager`, dedicated system user |
| TLS (optional) | nginx reverse proxy configured by `deploy/enable-https.sh` |

A background poller queries every enabled host at a fixed interval (`PM_POLL_INTERVAL`,
default 60 s, `PM_POLL_WORKERS` hosts in parallel) and stores a summary per host plus
utilization samples. Page loads and API reads are served from that cache. Maintenance and
guest operations run as jobs in a worker pool; each job records the requesting user, its
options, live output and result. Jobs that call the Proxmox API follow the corresponding
Proxmox task log until the task finishes.

For a cluster, one node is added as the host. The cluster API returns all nodes, guests and
storage, which are aggregated under that host.

## Requirements

- Debian 12 or Ubuntu 24.04 (VM or LXC container), Python 3.11 or later
- 1 vCPU, 512 MB RAM and 4 GB disk are sufficient for a typical fleet
- Network access from the dashboard server to TCP 8006 on every Proxmox host, and TCP 22 if
  the SSH integration is used
- Network access from administrators' browsers to TCP 8006 on the hosts for the console and
  upgrade shell, which connect directly from the browser to the host
- A Proxmox API token per host or cluster (see [Proxmox API access](#proxmox-api-access))

## Installation

```bash
cd proxmox-manager
sudo bash install.sh
```

`install.sh` performs the following steps and can be re-run to upgrade:

1. Installs `python3`, `python3-venv`, `python3-pip` and `rsync`.
2. Copies the application to `/opt/proxmox-manager` (excluding `.git`, `.env`, `venv/` and
   `data/`) and creates a virtual environment there.
3. Creates the `proxmox-manager` system user and the data directory `/var/lib/proxmox-manager`.
4. Generates `/opt/proxmox-manager/.env` with a random `PM_SECRET_KEY` if it does not exist.
   An existing `.env` is kept.
5. Prompts for the first administrator account on a new installation.
6. Installs, enables and starts the `proxmox-manager` systemd service on port 8080.

The dashboard is then available at `http://<server-ip>:8080/`. To serve it over HTTPS, see
[HTTPS](#https).

### Upgrade and rollback

Run `install.sh` from the new release. The configuration and database are preserved, and
schema additions are applied automatically at startup. To roll back, run `install.sh` from
the previous release. Confirm the running version with:

```bash
curl -s http://127.0.0.1:8080/healthz
```

### Service administration

```bash
journalctl -u proxmox-manager -f
sudo systemctl restart proxmox-manager
cd /opt/proxmox-manager
sudo runuser -u proxmox-manager -- venv/bin/python manage.py list-users
sudo runuser -u proxmox-manager -- venv/bin/python manage.py create-admin <username>
sudo runuser -u proxmox-manager -- venv/bin/python manage.py reset-password <username>
sudo runuser -u proxmox-manager -- venv/bin/python manage.py set-role <username> admin|viewer
sudo runuser -u proxmox-manager -- venv/bin/python manage.py disable-user <username>
sudo runuser -u proxmox-manager -- venv/bin/python manage.py enable-user <username>
```

Restart the service after editing `.env`.

### Development

```bash
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # set PM_SECRET_KEY and PM_DATA_DIR=./data
python manage.py create-admin admin
uvicorn app.main:app --host 127.0.0.1 --port 8080 --reload
```

## Proxmox API access

Users and tokens are cluster-wide, so a cluster needs one token.

### Read-only monitoring token

On any node, as root:

```bash
pveum user add monitor@pve --comment "Proxmox Manager"
pveum acl modify / --users monitor@pve --roles PVEAuditor
pveum user token add monitor@pve dashboard --privsep 0
```

The last command prints the token secret once. In the web UI the equivalent is Datacenter →
Permissions: add the user `monitor` (realm *Proxmox VE authentication server*), add a user
permission on `/` with role `PVEAuditor`, and add an API token `dashboard` with *Privilege
Separation* unchecked.

Add the host in the dashboard with:

| Field | Value |
|---|---|
| Auth type | API token |
| Token ID | `monitor@pve!dashboard` |
| Token secret | the UUID printed by Proxmox |

`PVEAuditor` provides `Sys.Audit`, `VM.Audit` and `Datastore.Audit`, which cover all
monitoring functions, including SMART reads and reboot-pending detection.

### Privilege separation

A token created with *Privilege Separation* enabled (the web UI default) has no permissions
of its own. Proxmox authenticates it and returns an empty node list, which the dashboard
reports as "Authenticated, but the token has no permissions". Either recreate the token
without privilege separation or grant the token its own ACL:

```bash
pveum acl modify / --tokens 'monitor@pve!dashboard' --roles PVEAuditor
```

### Privileges for management functions

Functions that change state need additional privileges. A `root@pam` token without privilege
separation has all of them. When a privilege is missing, the job fails with a message that
names the privilege and path.

| Function | Required privilege |
|---|---|
| Monitoring, SMART, reboot-pending | `Sys.Audit`, `VM.Audit`, `Datastore.Audit` |
| Pending update count, package list refresh, repository switch | `Sys.Modify` |
| Node reboot through the API | `Sys.PowerMgmt` |
| Guest start / shutdown / stop / restart | `VM.PowerMgmt` |
| Start at boot | `VM.Config.Options` |
| Snapshot | `VM.Snapshot` |
| Backup | `VM.Backup`, `Datastore.AllocateSpace` on the target storage |
| Disk expansion | `VM.Config.Disk`, `Datastore.AllocateSpace` on the disk's storage |
| Terminal, upgrade shell, guest console | `root@pam` password (Proxmox does not allow these for API tokens) |

To add only the pending-update count to a monitoring token:

```bash
pveum role add PVEAuditorUpdates -privs "Sys.Audit,Datastore.Audit,VM.Audit,Sys.Modify"
pveum acl modify / --users monitor@pve --roles PVEAuditorUpdates
```

`Sys.Modify` is a broad privilege; grant it only where required.

### Password authentication

Username and password authentication (for example `root@pam`) is also supported. Tokens are
preferred: they do not expire, are not affected by two-factor authentication, and can be
revoked per host with `pveum user token remove <user> <token>`.

### TLS verification

Proxmox hosts normally use self-signed certificates, so *Verify SSL* is disabled by default
for new hosts. Enable it for hosts with a certificate the dashboard server trusts (ACME or an
internal CA).

## Configuration

Settings are read from `/opt/proxmox-manager/.env`.

| Variable | Default | Description |
|---|---|---|
| `PM_SECRET_KEY` | required | Signs session cookies and derives the credential encryption key. Changing it invalidates all sessions and makes stored credentials unreadable. |
| `PM_HOST` | `0.0.0.0` | Listen address. Set to `127.0.0.1` when behind nginx. |
| `PM_PORT` | `8080` | Listen port |
| `PM_DATA_DIR` | `/var/lib/proxmox-manager` | SQLite database location |
| `PM_POLL_INTERVAL` | `60` | Seconds between poll cycles |
| `PM_PVE_TIMEOUT` | `15` | Per-request timeout to a host, seconds |
| `PM_POLL_WORKERS` | `8` | Hosts polled in parallel |
| `PM_AVERAGE_WINDOW_MINUTES` | `60` | Window for rolling averages |
| `PM_SAMPLE_RETENTION_HOURS` | `24` | Retention of utilization samples |
| `PM_SESSION_COOKIE_SECURE` | `false` | Set to `true` when served over HTTPS |
| `PM_SESSION_MAX_AGE` | `43200` | Session lifetime, seconds |
| `PM_INITIAL_ADMIN_USERNAME` / `PM_INITIAL_ADMIN_PASSWORD` | unset | Creates an administrator on first start. Remove after use. |
| `PM_LOG_LEVEL` | `INFO` | `DEBUG` logs every failed Proxmox call |

## HTTPS

`deploy/enable-https.sh` places the application behind nginx and restricts the application
itself to localhost.

```bash
cd /opt/proxmox-manager

# Self-signed certificate for the server's IP address (interim)
sudo ./deploy/enable-https.sh --self-signed

# Certificate as PFX / PKCS#12
sudo ./deploy/enable-https.sh --pfx /path/to/certificate.pfx --name proxmox.example.com

# Certificate as PEM
sudo ./deploy/enable-https.sh --cert /path/to/cert.pem --chain /path/to/intermediate.pem \
  --key /path/to/key.pem --name proxmox.example.com
```

The script:

1. Installs nginx if required.
2. Validates the certificate: key match, coverage of `--name`, expiry and chain. For
   `--self-signed` it generates an 825-day certificate for the server IP (`--ip` to override)
   and `--name` if given, and reuses it on later runs while it remains valid.
3. Stores the certificate and key in `/etc/ssl/proxmox-manager/` (key mode 600).
4. Writes the nginx site: HTTP redirects to HTTPS, HTTPS proxies to `127.0.0.1:<PM_PORT>`, and
   the responses carry `X-Frame-Options`, `X-Content-Type-Options` and `Referrer-Policy`
   headers. HSTS is enabled for named certificates and omitted for self-signed mode.
5. Verifies `/healthz` through nginx.
6. Sets `PM_HOST=127.0.0.1` and `PM_SESSION_COOKIE_SECURE=true` in `.env` (a timestamped
   backup is kept), restarts the service and verifies again.

`--name` is required with `--pfx` or `--cert`, and an internal DNS record for that name must
point to the server. `--no-lockdown` stops before step 6. `--help` lists all options and the
commands to revert. `deploy/nginx-proxmox-manager.conf.example` contains the equivalent
configuration for manual setup. The service trusts `X-Forwarded-*` headers only from
`127.0.0.1`.

## Usage

**Dashboard.** Fleet totals followed by one card per host. Cards can be grouped by client,
sorted by CPU, memory, storage or problems, and filtered by name, client, IP, version or node
name. The page refreshes from the cache every 30 seconds. *Refresh* polls a single host
immediately; *Refresh all* starts a full poll cycle.

**Host page.** Summary tiles, utilization history, one section per node with update and
reboot-pending status and maintenance actions, followed by the guest table, storage table and
recent jobs. *Disks / SMART* lists a node's physical disks; *Scan* reads SMART for one disk and
*Scan all disks* for the whole node. *Details* shows the ATA attribute table or the raw
`smartctl` output for NVMe and SAS devices. SMART data is read through
`/nodes/{node}/disks/smart`; SMART self-tests are not available through the API.

**Hosts** (admin). Add, edit, test, disable and delete hosts. *Web UI link override* sets the
address used for links to the Proxmox UI when it differs from the address the dashboard
polls, for example an address reachable over VPN.

**Users** (admin). Create users with the `admin` or `viewer` role. Viewers have read access and
can trigger refreshes and SMART reads; they cannot run jobs or change hosts or users.

## Node maintenance

### API mode (default)

Available with an API token only:

- **Refresh package list** runs the Proxmox `apt update` task
  (`POST /nodes/{node}/apt/update`), streams the task log, then lists pending updates with
  kernel packages flagged.
- **Open terminal** opens a root shell on the node from the Proxmox UI in a new tab (the same
  console as Node → Shell). It uses the sign-in described for the upgrade shell below.
- **Upgrade shell** opens the node's `pveupgrade` console from the Proxmox UI in a new tab. The
  button is highlighted in yellow while the node has pending updates. Proxmox only permits this console for an interactive `root@pam` session, so the dashboard
  requests a `root@pam` ticket from the host and the new tab submits it to the host's login
  endpoint (`/api2/html/access/ticket`). Proxmox then sets its standard authentication
  cookie (valid for two hours) in that browser and the console opens. The password is used
  server-side only and is never sent to the browser. For hosts added with `root@pam` password
  authentication the stored password is used; otherwise the password is requested and can be
  saved per host (encrypted). Accounts with two-factor authentication are not supported by
  this sign-in.
- **Reboot node** issues `POST /nodes/{node}/status command=reboot`, waits for the node's
  uptime to reset and reports the kernel it booted.

The browser must already trust the host's certificate before Proxmox can set the
authentication cookie. The dashboard checks this before signing in; if the certificate has
not been accepted, the new tab shows the browser's certificate warning, and the console
opens once the warning is accepted.

Typical sequence: Refresh package list, Upgrade shell (run the upgrade), wait for the next
poll to show *reboot pending* if a new kernel was installed, then Reboot node.

### Repository check

A default installation uses the enterprise repositories. Without a subscription,
`enterprise.proxmox.com` returns `401 Unauthorized` and apt silently skips all Proxmox
packages. Package refresh, update checks and upgrades detect this, finish with status
*warning*, and show the commands to switch to the no-subscription repositories for the node's
Debian release and Ceph version. **Switch to no-subscription** performs the same change
through the API (as in Node → Updates → Repositories): it disables the enterprise entries
for PVE and Ceph, adds the matching no-subscription repositories and refreshes the package
lists. Requires `Sys.Modify`. If the client has a subscription, install the key instead.

### SSH mode

The Proxmox API has no call that installs packages. Enabling SSH for a host adds **Check
updates (SSH)** and **Update node (SSH)**, and node reboots are then performed over SSH. See
[SSH integration](#ssh-integration-optional) for setup.

**Update node (SSH)**:

1. Verifies that apt and dpkg are not locked.
2. Starts the upgrade detached on the node (`setsid`, `nohup`, log in
   `/var/log/proxmox-manager/`) with `DEBIAN_FRONTEND=noninteractive`:
   ```
   apt-get update
   apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade
   apt-get -y autoremove
   ```
   The dashboard tails the log and reconnects if the SSH session drops, for example when
   `openssh-server` itself is upgraded.
3. Evaluates `/var/run/reboot-required` and compares the running kernel with the newest
   installed `proxmox-kernel-*` package, then reports whether a reboot is required and why.
4. Reboots only if *Reboot automatically afterwards* was selected and a reboot is required.

`dist-upgrade` matches what `pveupgrade` runs; `apt upgrade` can leave a Proxmox system
partially updated. **Check updates (SSH)** runs `apt-get update` and a simulated
`dist-upgrade`. **Reboot node (SSH)** runs `systemctl reboot` and waits up to 20 minutes for the
node to return.

All node jobs are restricted to administrators, require the node name to be typed for upgrades
and reboots, run one at a time per node, and are kept with full output under *Recent jobs*.
The reboot confirmation shows how many guests are running on the node.

## Guest operations

Each row in the guest table provides, for administrators:

| Action | Behavior |
|---|---|
| Start | Starts the guest. |
| Stop | *Shut down cleanly* sends a shutdown with a 180-second timeout, optionally followed by a forced stop. *Power off now* performs a hard stop and requires the VMID to be typed. |
| Restart | Clean reboot after confirmation. Pending configuration changes are applied. |
| Console | Signs the browser in as `root@pam` (same mechanism and saved password as the terminal and upgrade shell) and opens noVNC (VMs) or xterm.js (containers). Not shown for templates or stopped containers. |
| More | Opens the dialog described below. |

The **More** dialog reads the guest configuration live and contains:

- **Boot and network.** Start at boot state with a *Turn on* / *Turn off* control, startup
  order and delays (read only), and one row per network adapter with bridge, VLAN tag or
  *untagged* (with trunks), MAC address, model, firewall flag and link state. Containers also
  show the configured IP address and gateway. VM IP addresses are not part of the configuration
  and are not shown. The start-at-boot change is sent with the configuration digest, so it is
  rejected if the configuration was modified concurrently; the guest is not restarted.
- **Snapshot.** Name (default `pm-YYYYMMDD-HHMM`), description, and optional RAM state for
  running VMs. Rollback and deletion remain in the Proxmox UI.
- **Backup.** Target storage (storages on the node that accept backups), mode (snapshot,
  suspend, stop), compression (not applicable to Proxmox Backup Server) and notes template
  (default `{{guestname}}`).
- **Expand disk.** Lists VM disks (excluding CD-ROM, EFI and TPM volumes) and container root
  and volume mount points (excluding bind mounts). Disks can only be grown. For VMs, the
  partition and filesystem must be extended inside the guest afterwards; for containers
  Proxmox grows the filesystem.

Templates offer only the More dialog. Every operation runs as a job through the Proxmox API,
follows the Proxmox task log, and is recorded with the requesting user. One job per guest runs
at a time, a node reboot waits for running guest jobs on that node, and guest jobs are refused
while the node is rebooting. Viewers see a direct console link and must sign in to Proxmox
themselves.

## SSH integration (optional)

### Dashboard key

Hosts → *Dashboard SSH key* → *Generate key* creates an ed25519 key pair; the private key is
stored encrypted in the database. The card provides:

- an install script for a root shell on the node (Proxmox UI → node → Shell). It is
  idempotent, preserves existing keys and handles the
  `/root/.ssh/authorized_keys → /etc/pve/priv/authorized_keys` link;
- an equivalent single `ssh root@<host> '...'` command for a Linux or macOS terminal;
- the public key.

*Enable SSH & test* connects with the key and enables SSH for the host only if the connection
succeeds. Key authentication as root works with the Proxmox default `PermitRootLogin yes` and
with `prohibit-password`.

### Per-host settings

Edit the host, enable *SSH access*, select *Dashboard key*, a pasted private key or a
password, set user and port, then *Test SSH* and save.

In a cluster, each node is reached at the address it reports in the cluster status (the
corosync address). If that network is not reachable from the dashboard, set *Per-node SSH
address overrides*, one `node=address` entry per line (for example `pve1=10.0.0.11`).

Host keys are pinned on first connection. A changed host key stops the job with an error.
After a legitimate reinstall, use *Forget SSH host keys* on the host.

## Security

**Stored secrets.** Proxmox token secrets and passwords, SSH private keys and passwords,
saved `root@pam` console passwords and the dashboard SSH private key are encrypted with Fernet
using a key derived from `PM_SECRET_KEY`. They are never returned by the API. `.env` is mode
600 and readable only by the service account.

**User accounts.** Passwords are hashed with bcrypt and must be at least 10 characters.
Sessions use a signed cookie (`SameSite=Lax`, `Secure` when `PM_SESSION_COOKIE_SECURE=true`).
State-changing API requests with an `Origin` or `Referer` header from another host are rejected.

**Privilege model.** An administrator can act with every credential stored for a host. With a
`root@pam` token, root password or the dashboard SSH key configured, an administrator account
is equivalent to root on those hosts. Assign the admin role accordingly and use least-privilege
tokens where management functions are not needed.

**Deployment recommendations.** Serve the application over HTTPS, restrict access to the
management network, and back up `/var/lib/proxmox-manager` together with `.env`; the database
cannot be decrypted without the original `PM_SECRET_KEY`.

**Known limitations.** No multi-factor authentication, no login rate limiting or lockout,
no server-side session revocation, and no audit log beyond job history. TLS verification to
Proxmox hosts is disabled by default.

## API reference

All endpoints under `/api/` require a session cookie. Obtain one by posting to `/login`.

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/dashboard` | any | Fleet summary and per-host summaries |
| GET | `/api/hosts/{id}` | any | Host detail: nodes, guests, storage, history, SMART, active jobs |
| POST | `/api/hosts/{id}/refresh` | any | Poll one host |
| POST | `/api/refresh-all` | any | Start a full poll cycle |
| GET | `/api/hosts/{id}/nodes/{node}/disks` | any | Physical disks with last SMART result |
| POST | `/api/hosts/{id}/nodes/{node}/smart` | any | `{"devpath": "/dev/sda"}`: read SMART for one disk |
| POST | `/api/hosts/{id}/nodes/{node}/smart/all` | any | Read SMART for all disks on the node |
| POST | `/api/hosts/{id}/nodes/{node}/refresh-packages` | admin | Package list refresh through the API → `{job_id}` |
| POST | `/api/hosts/{id}/nodes/{node}/api-reboot` | admin | `{"confirm": "<node>"}`: reboot through the API → `{job_id}` |
| POST | `/api/hosts/{id}/nodes/{node}/check-updates` | admin | Update check over SSH → `{job_id}` |
| POST | `/api/hosts/{id}/nodes/{node}/upgrade` | admin | `{"confirm": "<node>", "auto_reboot": false}`: upgrade over SSH → `{job_id}` |
| POST | `/api/hosts/{id}/nodes/{node}/reboot` | admin | `{"confirm": "<node>"}`: reboot over SSH → `{job_id}` |
| POST | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/power` | admin | `{"action": "start\|shutdown\|reboot\|stop", "force_stop": false, "confirm": "<vmid>"}` → `{job_id}`; `confirm` required for `stop` |
| POST | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/snapshot` | admin | `{"snapname": "pre-patch", "description": "", "vmstate": false}` → `{job_id}` |
| GET | `/api/hosts/{id}/nodes/{node}/backup-storages` | admin | Storages on the node that accept backups |
| POST | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/backup` | admin | `{"storage": "local", "mode": "snapshot", "compress": "zstd", "notes": "{{guestname}}"}` → `{job_id}` |
| GET | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/details` | admin | `{onboot, startup, nets, disks}` from the live guest configuration |
| POST | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/onboot` | admin | `{"onboot": true}` → `{job_id}` |
| GET | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/disks` | admin | Disks that can be expanded |
| POST | `/api/hosts/{id}/nodes/{node}/guests/{vmid}/resize` | admin | `{"disk": "scsi0", "add_gb": 10}` → `{job_id}` |
| POST | `/api/hosts/{id}/console-login` | admin | `{"password": "", "remember": false}`: `root@pam` ticket and login URL for console sign-in |
| DELETE | `/api/hosts/{id}/console-login` | admin | Delete the saved `root@pam` password |
| GET | `/api/jobs/{id}?since=N` | any | Job status, result and output from character N |
| GET | `/api/hosts/{id}/jobs` | any | Last 50 jobs for the host |
| GET | `/api/ssh/key` | admin | Dashboard SSH public key |
| POST | `/api/ssh/key/generate` | admin | Generate or replace the dashboard key pair |
| POST | `/api/ssh/test` | admin | Test SSH credentials |
| GET, POST, PUT, DELETE | `/api/hosts`, `/api/hosts/{id}` | admin | Host management |
| POST | `/api/hosts/test` | admin | Test host credentials without saving |
| GET, POST, PUT, DELETE | `/api/users`, `/api/users/{id}` | admin | User management |
| POST | `/api/me/password` | any | Change own password |
| GET | `/healthz` | none | Liveness check, returns the running version |

Example:

```bash
curl -c jar -s -o /dev/null -d 'username=admin&password=...' https://proxmox.example.com/login
curl -b jar -s https://proxmox.example.com/api/dashboard \
  | jq '.hosts[] | {name, version: .summary.version, cpu: .summary.cpu_pct}'
```

## Project layout

```
app/
  main.py         FastAPI application, middleware, startup, error handling
  config.py       Settings from .env
  database.py     SQLAlchemy engine and session, schema migration
  models.py       User, ProxmoxHost, StatSample, SmartResult, SshHostKey, Job, AppSetting
  auth.py         Password hashing, session handling, role and origin checks
  crypto.py       Fernet encryption of stored credentials
  pve.py          Proxmox API client: summaries, updates, disks, SMART, guest configuration
  poller.py       Background polling
  ssh.py          SSH key pair, host key pinning, command execution
  jobs.py         Node and guest jobs with live output
  routers/        Login, HTML pages, JSON API
  templates/      Jinja2 templates
  static/         CSS and JavaScript
deploy/
  proxmox-manager.service            systemd unit
  enable-https.sh                    nginx and TLS setup
  nginx-proxmox-manager.conf.example nginx site for manual setup
install.sh        Installer and upgrader
manage.py         User administration CLI
```

## Roadmap

- Multi-factor authentication (TOTP)
- Login rate limiting and an audit log
- SMART self-tests over SSH
- Backup job status per guest
- Alerting (email, Microsoft Teams webhooks)
- ZFS pool health
- Rolling updates across the nodes of a cluster
