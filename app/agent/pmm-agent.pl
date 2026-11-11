#!/usr/bin/perl
# pmm-agent - Proxmox Manager update agent, version 1.
#
# Installs pending updates on THIS Proxmox node when the dashboard asks for it, and does nothing else.
#
#  - It never listens on a port and never connects anywhere except the local Proxmox API (pvesh).
#  - Every ~10 s it reads this node's Notes (pvesh get /nodes/<node>/config) and looks for request lines
#      <!-- pmm-agent:v1 PAYLOAD.SIGNATURE -->
#    which the dashboard writes there over the Proxmox API.
#  - A request is used only if its Ed25519 signature verifies against the dashboard's PUBLIC key in
#    /etc/pmm-agent/dashboard.pub (the private key never leaves the dashboard), it names this node, it
#    has not expired and its id was not used before. Request lines are removed from the Notes either way.
#  - Actions: "ping" (answers, nothing else) and "upgrade" (apt-get update + non-interactive
#    apt-get dist-upgrade, keeping existing config files). No other command can be run.
#  - Output goes to the journal (unit pmm-agent), each line tagged [request id]; the dashboard reads it
#    with GET /nodes/<node>/syslog?service=pmm-agent.
#
# Uninstall:
#   systemctl disable --now pmm-agent
#   rm -rf /usr/local/lib/pmm-agent /etc/pmm-agent /var/lib/pmm-agent /etc/systemd/system/pmm-agent.service
#   systemctl daemon-reload

use strict;
use warnings;
use Fcntl qw(:flock);
use File::Temp qw(tempfile);
use JSON::PP;
use MIME::Base64 qw(decode_base64);

my $VERSION  = 1;
my $PUBKEY   = $ENV{PMM_AGENT_PUBKEY}   // '/etc/pmm-agent/dashboard.pub';
my $STATE    = $ENV{PMM_AGENT_STATE}    // '/var/lib/pmm-agent';
my $INTERVAL = $ENV{PMM_AGENT_INTERVAL} // 10;
my $PVESH    = $ENV{PMM_AGENT_PVESH}    // '/usr/bin/pvesh';
my $APT      = $ENV{PMM_AGENT_APT}      // '/usr/bin/apt-get';
my $OPENSSL  = $ENV{PMM_AGENT_OPENSSL}  // '/usr/bin/openssl';
my $ONCE     = $ENV{PMM_AGENT_ONCE}     // 0;     # tests: one pass, then exit
my $NODE     = $ENV{PMM_AGENT_NODE}     // do { my $n = `hostname`; chomp $n; $n =~ s/\..*//; $n };
my $MARK_RE  = qr/<!--\s*pmm-agent:v1\s+([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\s*-->/;
my %ACTIONS  = (ping => 1, upgrade => 1);

$| = 1;
umask 077;
mkdir $STATE unless -d $STATE;

sub out { print join('', @_), "\n" }

sub b64url { my $s = shift; $s =~ tr/-_/+\//; $s .= '=' x ((4 - length($s) % 4) % 4); return decode_base64($s) }

sub run_capture {    # list form, no shell
    my @cmd = @_;
    open(my $fh, '-|', @cmd) or return (255, '');
    local $/;
    my $txt = <$fh> // '';
    close($fh);
    return ($? >> 8, $txt);
}

sub node_config {
    my ($rc, $txt) = run_capture($PVESH, 'get', "/nodes/$NODE/config", '--output-format', 'json');
    return undef if $rc != 0;
    my $cfg = eval { decode_json($txt) };
    return ref($cfg) eq 'HASH' ? $cfg : undef;
}

sub verify_sig {
    my ($payload, $sig) = @_;
    my ($pf, $pname) = tempfile(DIR => $STATE, UNLINK => 1);
    my ($sf, $sname) = tempfile(DIR => $STATE, UNLINK => 1);
    binmode $pf; binmode $sf;
    print $pf $payload; close $pf;
    print $sf $sig; close $sf;
    my ($rc) = run_capture($OPENSSL, 'pkeyutl', '-verify', '-pubin', '-inkey', $PUBKEY, '-rawin', '-in', $pname, '-sigfile', $sname);
    unlink $pname, $sname;
    return $rc == 0;
}

sub seen_load {
    my $f = "$STATE/seen.json";
    return {} unless -f $f;
    open(my $fh, '<', $f) or return {};
    local $/;
    my $d = eval { decode_json(<$fh> // '{}') };
    return ref($d) eq 'HASH' ? $d : {};
}

sub seen_save {
    my $d = shift;
    my $now = time;
    delete $d->{$_} for grep { $d->{$_} < $now - 3600 } keys %$d;
    open(my $fh, '>', "$STATE/seen.json.tmp") or return;
    print $fh encode_json($d);
    close $fh;
    rename "$STATE/seen.json.tmp", "$STATE/seen.json";
}

# Check one request line; returns (request hashref) or (undef, reason).
sub check_request {
    my ($p64, $s64, $seen) = @_;
    my $payload = b64url($p64);
    my $sig = b64url($s64);
    return (undef, 'bad signature length') unless length($sig) == 64;
    return (undef, 'signature does not verify') unless verify_sig($payload, $sig);
    my $r = eval { decode_json($payload) };
    return (undef, 'unreadable request') unless ref($r) eq 'HASH';
    return (undef, 'unsupported version') unless ($r->{v} // 0) == 1;
    return (undef, 'bad id') unless ($r->{id} // '') =~ /^[0-9a-f]{16,32}$/;
    return (undef, "for another node") unless ($r->{node} // '') eq $NODE;
    return (undef, 'unknown action') unless $ACTIONS{$r->{action} // ''};
    my $now = time;
    my $exp = $r->{exp} // 0;
    return (undef, 'bad expiry') unless $exp =~ /^\d+$/;
    return (undef, 'expired') if $now > $exp + 60;
    return (undef, 'expiry too far ahead') if $exp - $now > 900;
    return (undef, 'already used') if exists $seen->{$r->{id}};
    return ($r);
}

sub do_upgrade {
    my $id = shift;
    open(my $lock, '>', "$STATE/upgrade.lock") or do { out("[$id] PMM-RESULT status=failed action=upgrade rc=255 reason=lock"); return };
    unless (flock($lock, LOCK_EX | LOCK_NB)) { out("[$id] PMM-RESULT status=failed action=upgrade rc=255 agent=$VERSION reason=busy"); return }
    local $ENV{DEBIAN_FRONTEND} = 'noninteractive';
    local $ENV{APT_LISTCHANGES_FRONTEND} = 'none';
    local $ENV{NEEDRESTART_SUSPEND} = '1';    # never restart services on the hypervisor behind the admin's back (or this agent mid-upgrade)
    my $rc = 0;
    my $upgraded = '';
    for my $step (['update'], ['-y', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold', 'dist-upgrade']) {
        out("[$id] \$ apt-get " . join(' ', @$step));
        open(my $fh, '-|', $APT, @$step) or do { $rc = 255; last };
        while (my $line = <$fh>) {
            chomp $line;
            $line =~ s/[\r\x00-\x08\x0b-\x1f]//g;
            $upgraded = $1 if $line =~ /^(\d+) upgraded, /;
            out("[$id] $line");
        }
        close($fh);
        $rc = $? >> 8;
        last if $rc != 0;
    }
    out("[$id] PMM-RESULT status=" . ($rc == 0 ? 'ok' : 'failed') . " action=upgrade rc=$rc agent=$VERSION" . ($upgraded ne '' ? " upgraded=$upgraded" : ''));
    flock($lock, LOCK_UN);
    close($lock);
}

sub pass {
    my $cfg = node_config() or return;
    my $desc = $cfg->{description} // '';
    return unless $desc =~ $MARK_RE;
    my @reqs;
    while ($desc =~ /$MARK_RE/g) { push @reqs, [$1, $2] }
    # remove every request line first (valid or not), so nothing is ever run twice
    (my $clean = $desc) =~ s/[ \t]*<!--\s*pmm-agent:v1\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\s*-->[ \t]*\n?//g;
    $clean =~ s/\s+\z//;
    my @set = $clean eq '' ? ('--delete', 'description') : ('--description', $clean);
    push @set, '--digest', $cfg->{digest} if $cfg->{digest};
    my ($rc) = run_capture($PVESH, 'set', "/nodes/$NODE/config", @set);
    if ($rc != 0) { out("could not update the node notes (rc=$rc); retrying"); return }
    my $seen = seen_load();
    my @todo;
    for my $q (@reqs) {
        my ($r, $why) = check_request($q->[0], $q->[1], $seen);
        if (!$r) { out("refused a request: $why"); next }
        $seen->{$r->{id}} = $r->{exp};
        push @todo, $r;
    }
    seen_save($seen);
    for my $r (@todo) {
        out("[$r->{id}] accepted action=$r->{action} agent=$VERSION node=$NODE");
        if ($r->{action} eq 'ping') { out("[$r->{id}] PMM-RESULT status=ok action=ping agent=$VERSION") }
        elsif ($r->{action} eq 'upgrade') { do_upgrade($r->{id}) }
    }
}

out("pmm-agent $VERSION started on node $NODE (checking every ${INTERVAL}s)");
die "public key $PUBKEY missing\n" unless -r $PUBKEY;
while (1) {
    eval { pass(); 1 } or out("error: $@");
    last if $ONCE;
    sleep $INTERVAL;
}
