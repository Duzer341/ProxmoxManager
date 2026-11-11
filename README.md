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
- [Sign-in](#sign-in)
- [Roles](#roles)
- [Consoles](#consoles)
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
- Pending apt updates per node with notes from the package changelogs and a CVE check, kernel
  updates flagged, and reboot-pending detection
  (installed kernel newer than the running kernel)
- Detection of enterprise repositories configured without a subscription
- Fleet summary with grouping by client, free-form host tags with tag filters, sorting and
  free-text filtering
- When a host stops answering: when it was last up and last tried, its nodes and guests shown as
  down or unknown, and the last known network information

**Node maintenance** (admin)

- Package list refresh and node reboot through the Proxmox API
- Node terminal (root shell, as Node → Shell), relayed through the dashboard
- One-click node updates through a small update agent on the node (no root password, no SSH, no new port)
- Optional SSH mode: unattended `dist-upgrade` with live output, reboot-required analysis and
  optional automatic reboot
- One-step switch from enterprise to no-subscription repositories
- One-click switch of a root@pam host to a dedicated `pmm@pve` API token with a least-privilege role

**Guest operations** (admin)

- Start, clean shutdown, hard stop and restart
- Browser console (noVNC for VMs, xterm.js for containers), relayed through the dashboard and
  logged per session
- Snapshot, backup (vzdump) and disk expansion
- Start-at-boot view and toggle, startup order, and network adapter details (bridge, VLAN tag,
  trunks, MAC, model, firewall, link state)

**Access control**

- Three sign-in modes chosen at setup: username and password; username and password with an
  authenticator app (TOTP); Microsoft Entra ID single sign-on with app roles
- `admin`, `technician` and `viewer` roles, sign-in throttling, administrator-set passwords
  replaced at first sign-in, a fresh re-auth before consoles and console time limits
- Certificate pinning for hosts with self-signed certificates (confirmed before any credential is
  sent, as is a node's SSH host key for SSH password auth), limits on connection tests,
  Content-Security-Policy on every page, and an event log of sign-ins and changes in the service journal
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
- Browsers only need HTTPS (443) to the dashboard. Consoles are relayed by the dashboard; only
  the optional *Open PVE web UI* links need browser access to TCP 8006 on the hosts
  (`PM_SHOW_PVE_LINKS=false` hides them)
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
6. Prompts for the sign-in mode (see [Sign-in](#sign-in)) if none is configured yet, which is
   the case on a new installation and on the first upgrade to a release with this setting.
7. Installs, enables and starts the `proxmox-manager` systemd service on port 8080.

The dashboard is then available at `http://<server-ip>:8080/`. To serve it over HTTPS, see
[HTTPS](#https).

### Upgrade and rollback

Run `install.sh` from the new release. The configuration and database are preserved, and
schema additions are applied automatically at startup. To roll back, run `install.sh` from
the previous release. Confirm the running version with:

```bash
curl -s http://127.0.0.1:8080/healthz
```

### Upgrading from 1.3.0 to 1.4.0

Run `install.sh` from the new release; no configuration changes are needed. The database gets
new columns automatically (host tags, last known network information, confirmed SSH host key,
update agent nodes). Things that work differently afterwards:

- A host without a confirmed certificate is no longer pinned silently at its first poll. Hosts that
  were already pinned keep their pin. For a new host, *Test connection* shows the certificate's
  fingerprint first and the test runs once you confirm it (see [TLS verification](#tls-verification)).
- *Test SSH* with password authentication shows the node's SSH host key and sends the password only
  after you confirm it. SSH jobs with password auth to a node whose host key the dashboard hasn't seen
  before need that confirmation (Edit host → Test SSH); nodes it already knows keep working. The
  dashboard key (default) is not affected.
- The *Upgrade shell* button is replaced by **Update node** through the [update agent](#update-agent),
  installed once per node with *Set up updates*.
- The *Open PVE* button is no longer on the dashboard cards (the host page and Hosts list keep it),
  so people open *Details* instead.
- A host switched with *Switch to API token* in 1.4.0 gets the `Sys.Syslog` privilege in its PMM
  role for the update agent.

### Upgrading from 1.2.x to 1.3.0

Back up the data directory and `.env` first; a rollback to 1.2.x needs that backup:

```bash
sudo systemctl stop proxmox-manager
sudo tar czf ~/proxmox-manager-backup-$(date +%F).tar.gz /var/lib/proxmox-manager /opt/proxmox-manager/.env
```

Then run `install.sh` from the new release. What changes at the first start:

- Stored credentials are re-encrypted with the new key derivation (scrypt and a salt stored in
  the database). 1.2.x can't read them afterwards, which is why a rollback needs the backup.
- The service refuses to start if `PM_SECRET_KEY` is shorter than 32 characters or has fewer
  than 12 different characters. The installer's key passes; a hand-made one may not.
- Everyone signs in once more (new session format).
- Each host's certificate is pinned at its first poll (1.3.0; from 1.4.0 it is confirmed first, see [TLS verification](#tls-verification)).
- Consoles run through the dashboard ([Consoles](#consoles)). If the dashboard is behind nginx,
  re-run `deploy/enable-https.sh` with the options used originally so nginx passes the console
  websockets. Consoles need sign-in mode 2 or 3 (a second factor for the console re-auth).
- Existing accounts keep their roles; the new `technician` role is assigned on the Users page.
  Admins and technicians without an authenticator need an enrollment code at their next
  sign-in in modes 2 and 3 (`manage.py enroll-code <username>`, see
  [Authenticator app](#authenticator-app-modes-2-and-3)).
- Only one process may run on a data directory (`uvicorn --workers` is refused).

### Service administration

```bash
journalctl -u proxmox-manager -f
sudo systemctl restart proxmox-manager
cd /opt/proxmox-manager
sudo runuser -u proxmox-manager -- venv/bin/python manage.py list-users
sudo runuser -u proxmox-manager -- venv/bin/python manage.py create-admin <username>
sudo runuser -u proxmox-manager -- venv/bin/python manage.py reset-password <username> [--no-change-required]
sudo runuser -u proxmox-manager -- venv/bin/python manage.py set-role <username> admin|technician|viewer
sudo runuser -u proxmox-manager -- venv/bin/python manage.py disable-user <username>
sudo runuser -u proxmox-manager -- venv/bin/python manage.py enable-user <username>
sudo runuser -u proxmox-manager -- venv/bin/python manage.py reset-mfa <username>
sudo runuser -u proxmox-manager -- venv/bin/python manage.py enroll-code <username>
sudo runuser -u proxmox-manager -- venv/bin/python manage.py configure-login
sudo runuser -u proxmox-manager -- venv/bin/python manage.py show-login
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

### Limits on connection tests

*Test connection* and *Test SSH* connect from the dashboard to an address you type, with a password or token
you type, so they are limited to keep the dashboard from being used to guess passwords or scan addresses:

- An address that isn't one of your hosts (host address, cluster node IP or SSH address override) needs the
  console re-auth (authenticator code / Microsoft sign-in) first.
- Five failed sign-ins to the same address and port within 10 minutes pause tests of it for 15 minutes (429).
- Each admin can run 30 tests per 10 minutes.
- An event `outbound.alert` (outcome *denied*) is written to the service journal when an address
  reaches the failure limit and when one admin tests five or more different unmanaged addresses in 10 minutes.
- *Test SSH* with password auth shows the node's SSH host key first and sends the password only after you
  confirm it (`for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf $f; done` on the node). The confirmed
  key is saved with the host; SSH jobs with password auth refuse a node whose first key doesn't match it.
  The dashboard key (default) needs no confirmation: nothing secret is sent to the node.

### Switch to API token

On the host page of a host that signs in as root@pam with a password, or with a root@pam API
token, admins have **Switch to API token** (after the console re-auth). For a root@pam token
host the old token is removed from the host after the switch (it has full root access); untick that in the
dialog to keep it. If Proxmox doesn't let the token create users or tokens, enter the root@pam password in the
dialog (used once, not stored). Over the Proxmox API, signed in as root@pam:

1. Role `PMM` is created (or its privileges set) with: `Sys.Audit`, `Sys.Modify`, `Sys.PowerMgmt`, `Sys.Syslog`,
   `VM.Audit`, `VM.PowerMgmt`, `VM.Snapshot`, `VM.Backup`, `VM.Config.Disk`, `VM.Config.Options`, `VM.Console`,
   `Datastore.Audit`, `Datastore.AllocateSpace`. No user, permission, firewall, storage or cluster changes,
   no guest deletion or snapshot rollback, no node shell.
2. User `pmm@pve` is created (Proxmox VE realm) with a 64-character random password that is set and thrown away:
   never shown, never stored. Nobody can sign in to the web UI as pmm@pve; only its token works. An existing
   pmm@pve is reused as is.
3. `PMM` on `/` for pmm@pve, propagated.
4. API token `pmm@pve!pmm-<UTC timestamp>-<4 random hex>` with privilege separation off, stored encrypted in the dashboard only.
5. The token has to see the same nodes and guests as root@pam and hold every PMM privilege on `/`.
   Only then the host switches to the token and the stored root@pam password is removed.

If any step fails, what this run created is removed again (a changed role gets its old privileges back) and the
host entry is unchanged; the dialog lists every step. Users, roles and tokens are cluster-wide, so one run covers
a whole cluster. Running it on a second host of the same cluster reuses pmm@pve and adds a token. In the Proxmox
GUI the result is under Datacenter → Permissions (Users, API Tokens, Roles, Permissions).

Afterwards:

- Polling, guest actions, snapshots, backups, disk expansion, start at boot, Refresh package list, update notes,
  Reboot node: on the token.
- VM consoles: on the token (`VM.Console`), no root password. If Proxmox refuses the token for a console, the
  console says so and the dashboard asks for the root password for that host's consoles for the next hour.
- Container consoles and the node terminal: Proxmox only allows them for root@pam, so they ask for the
  root password when opened (typed, not stored unless you tick Remember). Updates without the root password:
  the [update agent](#update-agent), or the SSH update path where port 22 is reachable. The PMM role
  includes `Sys.Syslog` so the dashboard can read the agent's output.
- Going back: Edit host → Password, root@pam and the password. Remove the token in Proxmox if it isn't needed.

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
| Monitoring, SMART, reboot-pending, node network and DNS | `Sys.Audit`, `VM.Audit`, `Datastore.Audit` |
| Pending update count and update notes (changelogs), package list refresh, repository switch | `Sys.Modify` |
| Node reboot through the API | `Sys.PowerMgmt` |
| Guest start / shutdown / stop / restart | `VM.PowerMgmt` |
| Start at boot | `VM.Config.Options` |
| Snapshot | `VM.Snapshot` |
| Backup | `VM.Backup`, `Datastore.AllocateSpace` on the target storage |
| Disk expansion | `VM.Config.Disk`, `Datastore.AllocateSpace` on the disk's storage |
| Update agent: send a request / read its output | `Sys.Modify` (node notes) / `Sys.Syslog` (node journal) |
| Terminal, container console | `root@pam` password (Proxmox does not allow these for API tokens) |

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

*Verify SSL (CA-signed)* checks the host's certificate against the dashboard server's trusted CAs.
Enable it for hosts with an ACME or internal-CA certificate.

Proxmox hosts normally use the self-signed certificate the cluster generates. For those (Verify
SSL off) the dashboard **pins** the certificate: the SHA-256 fingerprint of the
certificate the host presents is stored on the host record. Nothing is pinned silently:
*Test connection* first shows the fingerprint (nothing else is sent yet) and runs the real test only after you
confirm it matches the node; that confirmed fingerprint is saved with the host. A host saved without a
confirmed certificate stays *pending* and the dashboard sends it nothing until *Check certificate* → *Accept*.
A new host entry at an address another host already pinned takes that pin. From then on every connection to that address (polling, jobs,
the root@pam sign-in, console start and the console relay) must present exactly that certificate;
the check runs right after the TLS handshake, before a token, password or cookie is sent. A
different certificate stops all traffic to the host and shows *TLS certificate changed* on the
host. If the certificate was replaced on purpose (reinstall, new cluster certificate), open *Edit
host*, click *Check certificate*, compare the fingerprint with the node:

```bash
openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256
```

and click *Accept new certificate*. The Hosts list shows each host as *pinned*, *CA* or *pending*.

Changing a host's address or port: if the new address presents the same pinned certificate (a
DNS name for the same node, say) the pin and the stored secrets are kept. Otherwise it is
treated as a different machine: the pin is dropped and has to be confirmed again, the token
secret or password has to be entered again (the edit is refused with a blank secret), and a
saved `root@pam` console password is cleared.

The pin is one certificate per host entry, and each Proxmox node has its own certificate. Point
a host entry at one node's address, not at a VIP, load balancer or round-robin DNS name that
can land on different nodes; the other cluster nodes are reached through that node's API.

## Configuration

Settings are read from `/opt/proxmox-manager/.env`.

| Variable | Default | Description |
|---|---|---|
| `PM_SECRET_KEY` | required, 32+ characters | Derives the session-cookie signing key and the credential encryption key (scrypt with a salt stored in the database). Changing it invalidates all sessions and makes stored credentials unreadable. The service refuses to start with a key shorter than 32 characters or with fewer than 12 different characters. |
| `PM_HOST` | `0.0.0.0` | Listen address. Set to `127.0.0.1` when behind nginx. |
| `PM_PORT` | `8080` | Listen port |
| `PM_DATA_DIR` | `/var/lib/proxmox-manager` | SQLite database location |
| `PM_POLL_INTERVAL` | `60` | Seconds between poll cycles |
| `PM_GUEST_DISK_REFRESH` | `300` | Seconds a guest's disk list (from its configuration) is cached before it is read again |
| `PM_PVE_TIMEOUT` | `15` | Per-request timeout to a host, seconds |
| `PM_POLL_WORKERS` | `8` | Hosts polled in parallel |
| `PM_AVERAGE_WINDOW_MINUTES` | `60` | Window for rolling averages |
| `PM_SAMPLE_RETENTION_HOURS` | `24` | Retention of utilization samples |
| `PM_SESSION_COOKIE_SECURE` | `true` | Session cookie only sent over HTTPS. `.env.example` sets `false` for the first HTTP-only start; `deploy/enable-https.sh` sets `true`. |
| `PM_SESSION_MAX_AGE` | `43200` | Session lifetime, seconds |
| `PM_INITIAL_ADMIN_USERNAME` / `PM_INITIAL_ADMIN_PASSWORD` | unset | Creates an administrator on first start. Remove after use. |
| `PM_LOG_LEVEL` | `INFO` | `DEBUG` logs every failed Proxmox call |
| `PM_SHOW_PVE_LINKS` | `true` | Show links to each host's Proxmox web UI (host page and hosts list; not on the dashboard cards, so people open Details). Set `false` when browsers can't reach the hosts; consoles go through the dashboard either way. |
| `PM_CONSOLE_CONNECT_SECONDS` | `120` | A requested console that has not connected within this time is discarded. |
| `PM_CONSOLE_MAX_SECONDS` | `7200` | Maximum length of one console session (2 hours). |
| `PM_CONSOLE_IDLE_MINUTES` | `15` | A console closes after this long without activity. |
| `PM_STEPUP_MINUTES` | `15` | How long a console re-auth lasts for that browser. |
| `PM_ENTRA_RECHECK_MINUTES` | `60` | A Microsoft sign-in is sent back through Microsoft after this long, so a removed or lowered Entra app role takes effect (normally seamless). |
| `PM_ENTRA_STEPUP_ACR` | empty | Conditional Access authentication context (e.g. `c1`) required at the Microsoft console re-auth. |
| `PM_CONSOLE_LOG_RETENTION_DAYS` | `365` | Console log rows (who opened which console, when, from where) are kept this long. |

## Sign-in

The sign-in mode applies to the whole dashboard. `install.sh` asks for it once; change it at
any time with:

```bash
cd /opt/proxmox-manager
sudo runuser -u proxmox-manager -- venv/bin/python manage.py configure-login
```

| Mode | Behavior |
|---|---|
| 1. Username and password | Local accounts with a password. |
| 2. Username and password with authenticator app | After the password, a 6-digit code from Google Authenticator, Microsoft Authenticator or any RFC 6238 app. Required for admins and technicians; viewers can enable it on their Account page. |
| 3. Microsoft Entra ID | *Sign in with Microsoft*. Roles come from Entra ID app roles. Local accounts remain available as break-glass through *Sign in with a local account* and follow the rules of mode 2. |

The mode, the Entra settings and the encrypted client secret are stored in the database, not
in `.env`. Sessions that no longer meet the current mode are signed out on their next request:
an admin session without a second factor after switching to mode 2 or 3, and Microsoft
sessions after switching away from mode 3.

### Passwords set by an administrator

A password an administrator chooses is temporary: when an account is created on
the Users page, or an administrator sets a new password for someone else there or with
`manage.py reset-password`, the user chooses their own password at the next sign-in. The order
at that sign-in is: the given password, then the authenticator (or, for an admin or technician
who has none yet, the enrollment code, authenticator setup and recovery codes), then *Set your
password*. There is no session until the new password is set, so the given password alone
opens nothing. The new password must be at least 10 characters, different from the given one
and not the username; setting it signs the account out of any other browser. The half-finished
sign-in expires after 15 minutes, or at once if an administrator changes the account meanwhile.

The Users page marks such accounts *new password at sign-in*, `manage.py list-users` shows
*(sets a new password at next sign-in)*. An administrator changing their own password on the
Users page or on *Account* is not asked again. To reset your own password on the server without
the extra step (break-glass), use
`manage.py reset-password <username> --no-change-required`. `manage.py create-admin` (used by
the installer) sets the password of the person running it and is not temporary.

### Authenticator app (modes 2 and 3)

- **Enrollment.** An admin or technician without an authenticator is shown a QR code (and the
  key for manual entry) after entering the password, and cannot continue until a valid code has
  been entered. Viewers enroll from *Account*.
- **Enrollment codes.** That first setup also needs a one-time enrollment code from an
  administrator, so a stolen password alone can't be used to enroll someone else's phone first.
  The code is shown once when an admin or technician is created, when their role is raised to
  one of those, or when their authenticator is reset, and printed by `manage.py create-admin`,
  `reset-mfa`, `set-role` and `configure-login`; *Enrollment code* on the Users page (or
  `manage.py enroll-code <username>`) issues a new one. Raising a viewer to technician or admin
  also removes the authenticator the viewer set up on their own, so the new role starts with an
  enrollment the administrator controls. Give it to the user another way (phone,
  Teams). It works once and expires after 7 days. Without a valid code the sign-in stops at
  *Ask an administrator for an enrollment code*.
- **Recovery codes.** Ten single-use codes (`XXXXX-XXXXX`) are shown once at enrollment. Any of
  them can be entered instead of a code. New codes can be created from *Account* with a current
  code; this invalidates the previous set.
- **Code checks.** Codes are accepted for the current 30-second step and one step either side.
  Each step can be used once per account.
- **Lost device.** An administrator can remove a user's authenticator with *Reset MFA* on the
  Users page, or on the server with `manage.py reset-mfa <username>`. The user enrolls again at
  the next sign-in. An admin cannot reset their own authenticator from the Users page.
- **Turning it off.** Viewers can turn it off from *Account* with a valid code. Admins and
  technicians cannot while mode 2 or 3 is active.

Secrets are encrypted with the same key as other stored credentials; recovery codes are stored
as SHA-256 hashes.

### Microsoft Entra ID (mode 3)

Requirements:

- The dashboard is served over HTTPS. Entra ID accepts only `https` redirect URIs (apart from
  `localhost`). A DNS name with a trusted certificate, such as `https://proxmox.example.com`,
  is recommended.
- The dashboard server can reach `https://login.microsoftonline.com` (outbound TCP 443) to read
  the tenant configuration and signing keys and to redeem sign-in codes. Entra ID itself never
  connects to the dashboard; the redirect happens in the browser.
- The server clock is accurate (NTP); ID tokens are checked with a two-minute tolerance.

App registration (Microsoft Entra admin center):

1. *App registrations → New registration.* Name `Proxmox Manager`,
   supported account types *Accounts in this organizational directory only*, redirect URI
   platform *Web* with `https://<dashboard address>/auth/entra/callback`.
2. From *Overview*, note the *Application (client) ID* and the *Directory (tenant) ID*.
3. *Certificates & secrets → Client secrets → New client secret.* Copy the secret **Value**
   (not the Secret ID). Note the expiry date; sign-in stops working when it expires, and the
   new value is entered with `configure-login`.
4. *App roles → Create app role*, three times: display name and value `Admin`, `Technician`
   and `Viewer`, allowed member types *Users/Groups*.
5. *Token configuration → Add optional claim → ID → `auth_time`.* Needed for the console
   re-auth (see [Console re-auth](#console-re-auth)).
6. *Enterprise applications → Proxmox Manager → Users and groups → Add user/group.* Assign users
   or groups to the `Admin`, `Technician` or `Viewer` role. Assigning groups requires Entra ID P1 or higher.
   Optionally set *Properties → Assignment required* to *Yes* so unassigned users are stopped
   at the Microsoft sign-in page.
7. On the dashboard server, run `manage.py configure-login`, choose 3, and enter the tenant ID,
   client ID, the dashboard address and the client secret. The command prints the exact
   redirect URI and checks that the tenant's OpenID configuration can be reached.

Sign-in flow: authorization code flow with PKCE, `state` and `nonce`, `response_mode=query`.
The ID token is verified against the tenant's published signing keys (RS256), and its issuer,
audience (client ID), tenant ID, expiry and nonce are checked. Microsoft accounts are matched by
their immutable object ID (`oid`); the username (`preferred_username`), display name and role
are updated from the token at every sign-in. A user with no `Admin`, `Technician` or `Viewer`
app role is refused. A role change takes effect at the next sign-in or console re-auth and
signs out the account's other browsers. Sign-ins are re-checked: after
`PM_ENTRA_RECHECK_MINUTES` (60) the browser is sent back through Microsoft (normally without a
prompt while the Microsoft session is valid) and the role is read again, so a removed or
lowered app role takes effect within an hour even in an open browser. Open consoles of a
Microsoft account end at the re-check too; the user opens them again after signing back in.
Disabling a Microsoft account on the Users page blocks it immediately; deleting it only removes
the local record, which is recreated at the next sign-in if the role assignment still exists. A
Microsoft account cannot sign in if a local account with the same username exists.

### Throttling and logging

After 5 failed password or code attempts within 15 minutes, that **username from that client
address** is locked for 15 minutes, and a client address after 20 failures for any usernames.
Across addresses a username is only slowed down: from 10 failures within 15 minutes each
further attempt waits 2, 4, 8 … up to 60 seconds after the last failure, so the break-glass
admin can't be locked out by someone else's attempts. The slow-down doesn't apply to a browser
that has signed in to that account before (a signed *known device* cookie, `pm_dev_…`, kept 90
days and tied to the account's session key, so a password change or MFA reset voids it). Wrong
console re-auth codes count too. Sign-ins, failures, lockouts, enrollments, recovery-code use
and MFA resets are logged to the service journal (`journalctl -u proxmox-manager`, loggers
`app.auth` and `app.events`; usernames that don't exist are masked).

## Roles

| Role | Can |
|---|---|
| `viewer` | Read everything on the dashboard and host pages, refresh hosts, run SMART scans, read job output. |
| `technician` | Everything a viewer can, plus guest start, stop, restart, snapshot, backup, expand disk and start at boot (the guest *More* dialog). No consoles, no node actions (updates, reboots, repositories), no host, credential, SSH, user or sign-in settings, no console log. |
| `admin` | Everything. |

`app/permissions.py` holds the table. The API guards, the console websocket check and the page
templates all read it, so a hidden button and a refused request cannot drift apart: a
technician calling an admin-only API directly receives HTTP 403, which is logged. Local admins
and technicians must use an authenticator app in sign-in modes 2 and 3. In Entra ID mode the
role comes from the app roles `Admin`, `Technician` and `Viewer`; with more than one, the most
powerful one applies.

Changing a user's password, authenticator, role or access (Users page or `manage.py`) signs that
user out of every browser and closes their open consoles within 20 seconds. Each account has a
random session key that is also stored in the session cookie; changing it invalidates every
existing sign-in, and a deleted user's cookie can never act as a later user with the same ID.

## Consoles

### Console relay

The node terminal, upgrade shell and guest consoles run through the dashboard, so browsers
never connect to a Proxmox host for them:

```
browser --wss:443--> dashboard /console/<id>/ws --wss:8006--> host .../vncwebsocket
```

1. An administrator clicks *Open terminal*, *Upgrade shell* or a guest's *Console*. The
   dashboard signs in to the host as `root@pam` with the host's stored password, the saved
   console password, or the one entered in the dialog, and keeps the ticket server-side.
2. A new tab opens at `/console/<id>` on the dashboard. It asks the dashboard to request a
   one-time console port from Proxmox (`vncproxy` for VMs, `termproxy` for containers, the node
   shell and `pveupgrade`).
3. The tab opens a websocket to the dashboard, which opens the matching websocket to the host
   and relays traffic in both directions until either side closes.

VMs are shown with noVNC (scaled to the window, with a *Ctrl+Alt+Del* button); containers and
node shells use xterm.js. Both are served from the dashboard (`app/static/vendor/`). When a
session ends, the tab shows how it ended and offers *Reconnect*, which opens a new session for
the same target without asking for the password again (the host sign-in is reused for up to
90 minutes, and the re-auth window below must still be open). A session ends after 15 minutes
without activity or 2 hours at the latest (see [Console time limits](#console-time-limits)).

Security properties:

- The `root@pam` password and ticket never reach the browser. For terminals the dashboard
  performs the Proxmox handshake itself. For VM consoles the browser receives the one-time VNC
  password Proxmox issues for that console port, which only the dashboard can reach and which
  expires within seconds.
- A console websocket is accepted only from the signed-in administrator who requested it, from
  the same browser sign-in, with an open re-auth window used from the same address, from the
  dashboard's own origin, within 20 seconds of the console starting, and only once.
- Consoles are for administrators only. Technicians and viewers see no console buttons and the
  API refuses them.

nginx must pass websocket upgrades for `/console/<id>/ws`. `deploy/enable-https.sh` writes that
location; on an installation set up before 1.3.0 re-run it with the options used originally.

### Paste text (VM consoles)

VNC has no shared clipboard without extra setup in
the guest, so *Paste text* in the console bar opens a box for text that is then typed into the
VM key by key, wherever its cursor is: a login screen, BIOS, an installer, a Linux console or a
Windows desktop, with no guest agent. New lines press Enter and tabs press Tab; *Hide the text*
switches to a one-line password field and *Press Enter after the text* submits it. Keys are sent
as a US keyboard would send them (QEMU extended key events, physical keys), so a guest set to
another layout types what those keys give there. Letters, digits, space and the US-keyboard
symbols are typed; curly quotes, dashes and non-breaking spaces copied from Word or Teams are
typed as their plain versions; anything else (accented letters, emoji) is left out and the
console bar says how many. Up to 5000 characters, about 60 per second, with *Stop typing*.
The event log records `console.paste` with the console and the number of characters and
lines; the text itself is never sent to the dashboard or stored. Terminals (node shell, containers)
take a normal paste (Ctrl+Shift+V or right-click) and have no *Paste text* button.

### Console re-auth

Every console (VM, container, node terminal and upgrade shell), *Reconnect* and the console
websocket need a recent re-auth on top of the normal sign-in:

- **Local accounts:** a new code from the authenticator app. Recovery (backup) codes are
  refused here, and a code that was already used, for example at sign-in, cannot be used again.
  Five wrong codes in a row sign the browser out; they also count towards the account lockout.
- **Microsoft accounts:** a forced fresh Microsoft sign-in (`prompt=login`, `max_age=0`,
  `login_hint`). The ID token must come back for the same account (`oid`), still carry a role
  that may open consoles, and contain an `auth_time` no older than the request. **Add the
  optional claim `auth_time` to the ID token** (app registration → *Token configuration* →
  *Add optional claim* → *ID* → `auth_time`); without it the re-auth fails, because the
  browser could otherwise strip `prompt=login` and be signed in silently.
  With Entra ID P1, set `PM_ENTRA_STEPUP_ACR` to a Conditional Access authentication context
  (for example `c1`) whose policy requires MFA at every sign-in; the dashboard then requests
  that context and refuses tokens without it (`acrs` claim).
- Password-only mode (1) has no second factor, so consoles are not available in it.

A re-auth opens a window of `PM_STEPUP_MINUTES` (15) for that browser sign-in, used from the
same client address. Opening more consoles does not extend it. The header shows *Console
access* with the time left and an *End* button. The window lives in the service's memory, keyed
by user and a random per-sign-in ID, so signing out, a restart or another browser never carries
it over.

### Console time limits

A console closes after `PM_CONSOLE_IDLE_MINUTES` (15) without activity, and after
`PM_CONSOLE_MAX_SECONDS` (7200, 2 hours) at the latest. For terminals, the upgrade shell and
container consoles, activity is typing or output from the host, so a running upgrade is not cut
off for lack of typing. For VM consoles it is keyboard or mouse input only; noVNC's own screen
refresh requests do not count. The console tab shows the limits, warns a minute before an idle
close (*Stay connected* resets it) and five minutes before the time limit. The console log
records why each session ended.

The console tab's title bar names the session, the node for guest consoles and the host's name
from the Hosts page, for example *Terminal on pve1 (Branch office)* or *Console VM 102 (DC1) on
pve1 (Branch office)*. The host name is left out when it is the same as the node name. With a node name set (see
*Node names*), the title reads *Terminal on pve1 (Main server) · Branch office*.

If Proxmox rejects the root@pam sign-in when a console starts (HTTP 401: the sign-in expired,
or the node joined a cluster after it was issued, which replaces its sign-in key), the dashboard
never reuses that sign-in again, signs in once more with the saved or host password and retries.
If that fails too, or no password is stored, the console page names the node and reports a clock
difference when there is one.

### Console session log

Every console request is recorded in the `console_log` table with the user, host, node, target,
client IP, request, connect and end times, how the session ended, the re-auth method and the
bytes transferred in each direction. The host page lists the
last 25 sessions under *Console sessions* (8 shown, *Show all* for the rest) for administrators.
Rows are kept for `PM_CONSOLE_LOG_RETENTION_DAYS` (365). The service journal carries the same
events:

```bash
sudo journalctl -u proxmox-manager | grep -E "app.console|console\.(connect|end|paste)"
```

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
reboot-pending status and maintenance actions, followed by the guest table, storage table,
network table and recent jobs. *Disks / SMART* lists a node's physical disks; *Scan* reads SMART for one disk and
*Scan all disks* for the whole node. *Details* shows the ATA attribute table or the raw
`smartctl` output for NVMe and SAS devices. SMART data is read through
`/nodes/{node}/disks/smart`; SMART self-tests are not available through the API.
The node header shows the node's management IP (the address Proxmox resolves the node name to,
from `/cluster/status`; click to copy). The **Network** section under Storage lists every
interface of every online node from `/nodes/{node}/network` (bridges, bonds, VLANs, physical
NICs, OVS) with IPv4 / IPv6 address, gateway, bridge ports or bond slaves and mode, VLAN ID or
VLAN-aware range, MTU, active state and comment, and above the table one line per node with the
management IP, default gateway, DNS servers and search domain from `/nodes/{node}/dns`. The
management interface is highlighted. It is read once when the page opens (its *Refresh* reads
it again; polling does not), and every role sees it.

**Offline nodes.** While a cluster node is offline, Proxmox keeps reporting its guests' last
state (often *running*, with their last CPU and RAM). The dashboard shows those guests as
*unknown* (hover for the last reported state), counts them separately from running and stopped,
offers no actions or consoles for them (the API refuses them with 409), dims the node's own
storage rows with an *offline* badge (last reported figures) and shows *Node offline* in the
Network section.

**Node names.** For a cluster, *Edit host* lists each member with an optional friendly name
(up to 64 characters). The name appears after the node name in the node header, for example
*prox (Main server)*, and in console titles, for example *Terminal on prox (Main server) · Main
Host*. The section is shown for hosts with more than one node or with names already set.

**Node clock.** Each poll reads `/nodes/{node}/time`. A node whose clock is a minute or more
off gets a *clock … ahead / behind* badge (red from four minutes, or when it differs from the
node the dashboard signs in through by that much). Proxmox accepts a root@pam sign-in issued by
another cluster node only when the clocks agree within five minutes, so a drifting node breaks
consoles while token-based polling keeps working.

**Host tags.** Each host can carry up to 20 free-form tags (up to 40 characters each, no
commas or angle brackets), set on *Edit host*: type a tag and press Enter or comma, Backspace in
the empty box removes the last one, and tags already used on other hosts are suggested (picking
one keeps its spelling). Tags are matched without regard to case. They appear as coloured chips
(the same tag always has the same colour) on the dashboard cards, in the Hosts list and in the
host page header, next to the single *Client / group* label that the dashboard groups by. Above
the dashboard cards a *Tags* bar lists every tag with the number of hosts; click tags to show
only hosts that have all of the selected ones (click again to remove, *Clear* for none). The
selection is remembered in that browser, the search box matches tags too, and a tag in a host
page header opens the dashboard filtered by it. Every role sees tags; only admins change them
(changes are in the event log as `host.update`, field `tags`).

**Hosts** (admin). Add, edit, test, disable and delete hosts. *Web UI link override* sets the
address used for links to the Proxmox UI when it differs from the address the dashboard
polls, for example an address reachable over VPN (not used with `PM_SHOW_PVE_LINKS=false`).

**Users** (admin). Create users with the `admin`, `technician` or `viewer` role (see
[Roles](#roles)). Viewers have read access and can trigger refreshes and SMART reads.
Technicians can also run guest actions. Neither can open consoles, run node jobs or change
hosts or users.

### Appearance

Each user picks **Dark**, **Light** or **Match system** under *Account → Appearance*. The choice is
stored on the account (`users.theme`, default `dark`), so it applies on every browser the user
signs in from; Match system follows the operating system's or browser's light/dark setting and
switches with it. A non-secret `pm_theme` cookie holds a copy only so the sign-in page opens in
the same theme. Console screens stay black in both themes.

Since 1.4.0 the pages use a "rack panel" look in both themes, like the front of rack equipment: a dark
top bar and node headers, host cards with a header strip and status LED, segmented usage meters,
uppercase labels and figures in a monospaced font. Host tags keep their own colours.

## Node maintenance

### API mode (default)

Available with an API token only:

- **Refresh package list** runs the Proxmox `apt update` task
  (`POST /nodes/{node}/apt/update`), streams the task log, then lists pending updates with
  kernel packages flagged.
- **Open terminal** opens a root shell on the node (the same console as Node → Shell) in a
  new dashboard tab. See [Console relay](#console-relay) for how the session is set up.
- **Update node** installs the pending updates through the [update agent](#update-agent)
  (replaces the Upgrade shell button of 1.3.0). Highlighted in yellow while the node has pending
  updates. Nodes without the agent show **Set up updates** instead.
- **Reboot node** issues `POST /nodes/{node}/status command=reboot`, waits for the node's
  uptime to reset and reports the kernel it booted.

Typical sequence: Refresh package list, Update node, then Reboot node if the job (or the next
poll) shows *reboot required*.

### Update agent

A small Perl service on each node (`pmm-agent`) installs updates when the dashboard
asks, so updating a node is one click and needs neither the root password nor SSH.

How it works:

- It opens no port and connects nowhere. Every ~10 s it reads the node's Notes through the local
  `pvesh`. To ask for something, the dashboard writes one signed line into the Notes over the Proxmox API
  (`PUT /nodes/{node}/config`, sent with the config digest):
  `<!-- pmm-agent:v1 PAYLOAD.SIGNATURE -->`. The agent removes every such line first, then checks it.
- Requests are signed with an Ed25519 key that only the dashboard holds (generated on first use, stored
  encrypted with the other secrets). The node only has the public key (`/etc/pmm-agent/dashboard.pub`).
  A request names its node, has a random single-use id and expires after 5 minutes, so having API
  access to the host (or a copy of an old request) is not enough to make the agent do anything.
- It can do exactly two things: answer a ping, and run `apt-get update` followed by a non-interactive
  `apt-get dist-upgrade -y` that keeps existing config files (needrestart, if installed, is suspended so no
  services are restarted automatically). There is no way to send it a command.
  Reboots stay a separate step (Reboot node, through the API).
- Its output goes to the journal (unit `pmm-agent`), every line tagged with the request id. The dashboard
  reads it with `GET /nodes/{node}/syslog?service=pmm-agent` and streams it into the job window. The job
  keeps waiting if the Proxmox API restarts during the upgrade.

Setting it up (once per node): **Set up updates** on the node → **Open terminal** (root password one last
time) → **Copy** → paste into the terminal → **Check agent**. The installer writes
`/usr/local/lib/pmm-agent/pmm-agent.pl`, `/etc/pmm-agent/dashboard.pub` and
`/etc/systemd/system/pmm-agent.service`, adds `Sys.Syslog` to the PMM role if there is one, and starts
the service. Remove it with:

```bash
systemctl disable --now pmm-agent
rm -rf /usr/local/lib/pmm-agent /etc/pmm-agent /var/lib/pmm-agent /etc/systemd/system/pmm-agent.service
systemctl daemon-reload
```

The token needs `Sys.Modify` and `Sys.Syslog`. If `Sys.Syslog` is missing the update is refused
before a request is sent (so nothing runs that the dashboard can't watch), with the `pveum` command to
add it. Check on a node: `systemctl status pmm-agent`, `journalctl -u pmm-agent`.

If the dashboard's key is ever lost (new database without a restore), reinstall the agent on each node
with the new installer; requests signed with the old key are refused.

### When a host can't be reached

When a poll fails:

- The error is followed by *Last up 4h ago (date)*, the last successful poll. Everything shown
  for the host (figures, versions, guests, storage) is from then.
- The card footer and the host page header show *last tried …*, the last attempt, so a host that
  is still being tried doesn't look forgotten. The tooltip has both times.
- Nodes show *unreachable* with a red dot, guests *unknown* with their last reported state, and the
  node and guest buttons are hidden until the host answers again. Live-only figures (CPU, load,
  uptime) are left out.
- The Network section shows the last network information read from each node (saved every time
  the section loads), marked *last known* with its date and a note that it may have changed since.
  It is cleared when a host is pointed at a different machine.

### Update notes and CVE check

Click the *N updates* badge in a node's header on the host page, or on a host's dashboard card
(all its nodes), to see what the pending updates change Every role can open it.

- Each package shows the installed and the new version, its repository and, once its changelog
  has been read, a *security* badge and the CVE IDs it fixes. Kernel packages are marked
  *kernel · reboot*.
- Expanding a package lists the changelog entries between the installed and the new version:
  version, date, urgency, the security suite when it came from one (for example
  `bookworm-security`), and the first line of each change. CVE IDs link to the Debian security
  tracker.
- The box at the top checks a CVE (`CVE-2025-1234`, any case) or a word: it says which pending
  update fixes it and in which version, or that it is already fixed in the installed version of
  a pending package, or that no pending update mentions it.

The changelogs are downloaded by the node from its repository through the Proxmox API
(`GET /nodes/{node}/apt/changelog`, at most four at a time, kept for 12 hours), so the node needs
the same internet access it uses for apt, and the token needs `Sys.Modify` like the update
list. Versions are compared like dpkg. Limits: only packages with a pending update are checked;
a fix that a changelog doesn't name by CVE ID isn't found; Proxmox kernel changelogs name the
Ubuntu kernel they are based on (for example `Ubuntu-6.14.0-29.29`), not individual CVEs, so
for a kernel CVE check Ubuntu's notice for that kernel.

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
| Console | Opens noVNC (VMs) or xterm.js (containers) in a new dashboard tab through the [console relay](#console-relay), using the same `root@pam` sign-in and saved password as the terminal and upgrade shell. Not shown for templates or stopped containers. |
| More | Opens the dialog described below. |

The **Disk** column is the total of every disk in the guest's configuration: VM disks on
`scsi`/`virtio`/`sata`/`ide` and passed-through physical disks, container `rootfs` and `mpN`
volumes. Proxmox's own guest list reports only the boot disk of a VM (the `rootfs` of a
container), so a VM with `sata0` 100G and `sata1` 700G shows 800 GiB here, with *2 disks*
underneath; hover for the list. EFI and TPM state disks, container bind mounts, CD-ROMs and
unused (detached) volumes are not counted. The configurations are read during polling and
cached per guest for `PM_GUEST_DISK_REFRESH` seconds (default 300), so a disk added in the
Proxmox UI appears within about five minutes. An *Expand disk* job updates the column as soon as
it finishes; opening the guest's *More* dialog updates it at the next poll. At most 60
configurations are read per poll and for at most 10 seconds (a node that stops answering is
skipped for that poll), so on hosts with several hundred guests the first totals take a few
polls. If a configuration cannot be read (`VM.Audit` missing), the column falls back to the boot
disk and is marked with an asterisk.

The **More** dialog reads the guest configuration live and contains:

- **Boot, disks and network.** Start at boot state with a *Turn on* / *Turn off* control, startup
  order and delays (read only), one row per disk (bus and number, storage, size, and notes for
  passthrough, EFI vars, TPM state, bind mounts, mount points and disks excluded from backup),
  and one row per network adapter with bridge, VLAN tag or
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
while the node is rebooting. Technicians can run every guest operation except the console.
Consoles are available to administrators only, after a [re-auth](#console-re-auth);
technicians and viewers see no console buttons.

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
saved `root@pam` console passwords, authenticator secrets, the Entra client secret and the
dashboard SSH private key are encrypted with Fernet. The key is derived from `PM_SECRET_KEY` with
scrypt (N=2^15, r=8, p=1) and a random salt stored in the database, then HKDF per use (credentials,
cookies); values written by older versions are re-encrypted at startup. Secrets are never
returned by the API. A stored token, password or SSH secret is only ever sent to the address and
account it was saved for: *Test connection* / *Test SSH* with a different address, port, user,
token name, authentication type or SSL setting, and saving a host under a different address,
require the secret to be entered again (see [TLS verification](#tls-verification)). `.env` is mode 600 and readable only by the
service account.

**Browser.** Every page is served with a Content-Security-Policy that allows only the
dashboard's own scripts and the page's inline scripts (per-request nonce), no framing, plugins
or foreign form targets; JSON responses allow nothing. Values that come from managed hosts are
escaped where they are shown, numbers are type-checked and version strings are reduced to
version characters when polled. The API description (`/openapi.json`, `/docs`) is not served.

**User accounts.** Passwords are hashed with bcrypt and must be at least 10 characters. A
password set by an administrator is replaced by the user at the next sign-in, before a session
starts ([details](#passwords-set-by-an-administrator)).
Second factors and Entra ID sign-in are described under [Sign-in](#sign-in). Sessions use a
signed cookie (`SameSite=Lax`, `Secure` when `PM_SESSION_COOKIE_SECURE=true`) that records how
the session was authenticated, a random per-sign-in ID and the user's session key. Signing out
revokes the sign-in ID server-side (a copied cookie stops working); changing a user's password,
authenticator, role or access invalidates all of their sessions. State-changing API requests
with an `Origin` or `Referer` header from another host are rejected.

**Privilege model.** An administrator can act with every credential stored for a host. With a
`root@pam` token, root password or the dashboard SSH key configured, an administrator account
is equivalent to root on those hosts. Assign the admin role accordingly and use least-privilege
tokens where management functions are not needed.

**Deployment recommendations.** Serve the application over HTTPS, restrict access to the
management network, and back up `/var/lib/proxmox-manager` together with `.env`; the database
cannot be decrypted without the original `PM_SECRET_KEY`.

**Event log.** Sign-ins, failed sign-ins, changes made through the web UI or API, job results,
console connections and refused requests are written to the service journal as one JSON line
each (logger `app.events`). Passwords, codes, tokens, tickets and keys are never written; a
failed sign-in with a username that does not exist is shown as `unknown account #tag (length
range)`. Forward the journal to a log collector for a copy outside the server. See also
[Console re-auth](#console-re-auth) and [Console time limits](#console-time-limits).

```bash
sudo journalctl -u proxmox-manager | grep app.events
```

**Single process.** Throttling counters, session revocation, console re-auth windows and open
consoles are held in memory, so the service runs as one process: a second process on the same
data directory (for example `uvicorn --workers 2`) refuses to start (lock file
`.instance.lock` in the data directory). A restart resets the
counters and ends all re-auth windows.

**Known limitations.** Root on the dashboard server can alter the service journal; forward it
to a log collector for an independent record. `/healthz` reports the version only to requests from
the server itself, and the sign-in page doesn't show it. Viewers can make the dashboard contact a host (refresh, SMART, disks,
network); that is part of their read-only role.

## API reference

All endpoints under `/api/` require a session cookie. Obtain one by posting to `/login`.

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/dashboard` | any | Fleet summary and per-host summaries |
| GET | `/api/hosts/{id}` | any | Host detail: nodes, guests, storage, history, SMART, active jobs |
| POST | `/api/hosts/{id}/refresh` | any | Poll one host |
| POST | `/api/refresh-all` | any | Start a full poll cycle |
| GET | `/api/hosts/{id}/nodes/{node}/disks` | any | Physical disks with last SMART result |
| GET | `/api/hosts/{id}/nodes/{node}/updates/notes?name=&version=` | any | Update notes for one pending package: changelog entries between installed and new, CVE IDs, CVEs already fixed in the installed version |
| POST | `/api/hosts/{id}/nodes/{node}/smart` | any | `{"devpath": "/dev/sda"}`: read SMART for one disk |
| POST | `/api/hosts/{id}/nodes/{node}/smart/all` | any | Read SMART for all disks on the node |
| POST | `/api/hosts/{id}/nodes/{node}/refresh-packages` | admin | Package list refresh through the API → `{job_id}` |
| GET | `/api/agent/installer` | admin | Update agent installer block, uninstall commands, key fingerprint |
| POST | `/api/hosts/{id}/nodes/{node}/agent/ping` | admin | Signed ping to the node's update agent (up to ~45 s) → `{ok, agent}` or `{ok: false, error}` |
| POST | `/api/hosts/{id}/nodes/{node}/agent/upgrade` | admin | `{"confirm": "<node>"}`: install updates through the update agent → `{job_id}` |
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
| POST | `/api/hosts/{id}/consoles` | admin | `{"kind": "vm\|ct\|shell\|upgrade", "node": "pve1", "vmid": 100, "password": "", "remember": false}` → `{id, url}`; 409 when a `root@pam` password is needed |
| POST | `/api/consoles/{id}/start` | admin (owner) | Ask the host for a console port; returns the one-time VNC password for VM consoles |
| POST | `/api/consoles/{id}/reconnect` | admin (owner) | New console for the same target → `{id, url}` |
| POST | `/api/consoles/{id}/paste` | admin (owner) | VM consoles: record a *Paste text* (`{chars, lines, skipped}`, never the text) before the browser types it; 409 if not connected |
| GET | `/api/hosts/{id}/consoles` | admin | Last 25 console sessions on the host |
| WebSocket | `/console/{id}/ws` | admin (owner) | Console stream, relayed to the host |
| DELETE | `/api/hosts/{id}/console-login` | admin | Delete the saved `root@pam` password |
| GET | `/api/jobs/{id}?since=N` | any | Job status, result and output from character N |
| GET | `/api/hosts/{id}/jobs` | any | Last 50 jobs for the host |
| GET | `/api/ssh/key` | admin | Dashboard SSH public key |
| POST | `/api/ssh/key/generate` | admin | Generate or replace the dashboard key pair |
| POST | `/api/ssh/test` | admin | Test SSH credentials |
| GET, POST, PUT, DELETE | `/api/hosts`, `/api/hosts/{id}` | admin | Host management (`tags`: list of strings; leave it out on PUT to keep the current tags) |
| POST | `/api/hosts/test` | admin | Test host credentials without saving |
| GET, POST, PUT, DELETE | `/api/users`, `/api/users/{id}` | admin | User management (`must_change_password`: the user sets a new password at next sign-in; set on create and when an admin sets someone else's password) |
| GET | `/api/me` | any | Own account, sign-in mode and authenticator state |
| POST | `/api/me/password` | any | Change own password (local accounts) |
| POST | `/api/me/mfa/setup` | any | Start authenticator enrollment: secret, `otpauth://` URI and QR code (SVG) |
| POST | `/api/me/mfa/enable` | any | `{"code": "123456"}` → `{recovery_codes}` |
| POST | `/api/me/mfa/disable` | any | `{"code": "123456"}`; not allowed for admins in modes 2 and 3 |
| POST | `/api/me/mfa/recovery-codes` | any | `{"code": "123456"}` → new `{recovery_codes}` |
| DELETE | `/api/users/{id}/mfa` | admin | Remove another user's authenticator |
| GET | `/api/login-config` | admin | Current sign-in mode and Entra settings (no secret) |
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
  models.py       User (incl. MFA and Entra fields), ProxmoxHost, StatSample, SmartResult, SshHostKey, Job, AppSetting, ConsoleLog
  auth.py         Password hashing, session handling, role and origin checks
  loginconfig.py  Sign-in mode and Entra ID settings
  mfa.py          TOTP verification, enrollment, recovery codes
  entra.py        Entra ID OpenID Connect client and ID token validation
  ratelimit.py    Sign-in throttling
  crypto.py       Key derivation and encryption of stored credentials
  pve.py          Proxmox API client: summaries, updates, disks, SMART, guest configuration
  poller.py       Background polling
  ssh.py          SSH key pair, host key pinning, command execution
  jobs.py         Node and guest jobs with live output
  consoles.py     Console relay
  stepup.py       Console re-auth window
  tlspin.py       TLS certificate pinning for hosts
  auth_device.py  Known-device cookie (sign-in throttling)
  events.py       Event log (service journal)
  routers/        Sign-in (password, MFA, Entra ID), HTML pages, JSON API
  templates/      Jinja2 templates
  static/         CSS and JavaScript; vendor/ holds noVNC 1.6.0 and xterm.js 5.5.0 (MPL-2.0 / MIT)
deploy/
  proxmox-manager.service            systemd unit
  enable-https.sh                    nginx and TLS setup
  nginx-proxmox-manager.conf.example nginx site for manual setup
install.sh        Installer and upgrader
manage.py         User and sign-in administration CLI
```

## Roadmap

- SMART self-tests over SSH
- Backup job status per guest
- Alerting (email, Microsoft Teams webhooks)
- ZFS pool health
- Rolling updates across the nodes of a cluster
