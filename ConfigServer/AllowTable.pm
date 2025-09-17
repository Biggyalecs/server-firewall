package ConfigServer::AllowTable;
use strict;
use warnings;
use utf8;

# --- Config ---
my $ALLOW_FILE = '/etc/csf/csf.allow';     # change if you renamed it for LSF
my $CSF_BIN    = '/usr/sbin/csf';

# CSS flag (print style only once per page)
our $LS_CSS_PRINTED = 0;

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

# Escape HTML (reuse specialchars from the UI if available)
sub _e {
    no strict 'refs';
    if (defined &ConfigServer::DisplayUI::specialchars) {
        return ConfigServer::DisplayUI::specialchars($_[0]);
    }
    my $s = defined $_[0] ? $_[0] : '';
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g;
    return $s;
}

# Determine CGI URL (forms must POST here, NOT to this module)
sub _script {
    return $main::script || $ENV{'SCRIPT_NAME'} || '/cgi/linuxshield/index.cgi';
}

# Run "csf -ra" and CAPTURE stdout+stderr (last 400 lines)
sub _run_csf_reload {
    my $cmd = "$CSF_BIN -ra";
    my $out = `$cmd 2>&1`;
    my $rc  = $? >> 8;
    my @L = split /\r?\n/, ($out // '');
    if (@L > 400) { @L = @L[-400..-1] }
    $out = join "\n", @L;
    return ($rc, $out);
}

# CSS (print once)
sub _print_css_once {
    return if $LS_CSS_PRINTED;
    $LS_CSS_PRINTED = 1;
    print q{
    <style>
      .ls-card{background:#0f1a2b;border:1px solid #1f2a3c;border-radius:14px;padding:16px;margin-bottom:16px;color:#e9eef6}
      .ls-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap}
      .ls-head h3{margin:0;color:#dfe9ff;font-size:18px}
      .ls-row{display:flex;gap:8px;flex-wrap:wrap}
      .ls-input{background:#0b1320;color:#e9eef6;border:1px solid #22324a;border-radius:10px;padding:8px 10px;width:100%}
      .ls-select{background:#0b1320;color:#e9eef6;border:1px solid #22324a;border-radius:10px;padding:8px 10px}
      .ls-btn{border:none;border-radius:10px;padding:6px 10px;cursor:pointer}
      .btn-primary{background:#2f6df6;color:#fff}
      .btn-warn{background:#f0ad4e;color:#111}
      .btn-danger{background:#e55353;color:#fff}
      table{width:100%;border-collapse:collapse}
      th,td{border:1px solid #22324a;padding:8px 10px}
      thead th{background:#152238;color:#dfe9ff}
      tbody tr:nth-child(even){background:#0e192a}
      .badge-ip{background:#22324a;color:#cfe1ff;padding:3px 6px;border-radius:8px;font-family:monospace}
      .actions{display:flex;gap:8px}
      .note{color:#9fb3d9;font-size:12px;margin-top:8px}
      .pager{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
      .pager a,.pager span{padding:6px 10px;border-radius:10px;border:1px solid #22324a;text-decoration:none;color:#e4ebf7}
      .pager .active{background:#2f6df6;border-color:#2f6df6;color:#fff}
      .pager .disabled{opacity:.5;pointer-events:none}
      .summary{color:#9fb3d9;font-size:12px;margin-left:auto}
      @media (max-width:900px){.hide-sm{display:none}}
      /* log panel */
      .ls-log{border:1px solid #1f2a3c;border-radius:12px;margin-top:10px}
      .ls-log-head{padding:8px 12px;border-bottom:1px solid #1f2a3c;font-weight:600}
      .ls-log-ok{color:#8ee59b}
      .ls-log-bad{color:#ff7b7b}
      .ls-log-body{padding:8px 12px}
      .ls-pre{max-height:320px;overflow:auto;white-space:pre-wrap;margin:8px 0 0 0;padding:8px;background:#0b1320;border:1px solid #22324a;border-radius:8px;color:#dbe7ff}
    </style>
    };
}

# Render a boxed reload log (DenyTable-like style)
sub _print_csf_log {
    my ($rc, $log) = @_;
    my $title = $rc == 0 ? 'CSF reloaded OK' : "CSF reload FAILED (exit $rc)";
    my $cls   = $rc == 0 ? 'ls-log-ok' : 'ls-log-bad';
    print qq{
      <div class="ls-log">
        <div class="ls-log-head $cls">$title</div>
        <div class="ls-log-body">
          <details open>
            <summary style="cursor:pointer;user-select:none">Restart log</summary>
            <pre class="ls-pre">}
      . _e($log) .
      qq{</pre>
          </details>
          <div class="note">Only last 400 lines shown.</div>
        </div>
      </div>
    };
}

# Parse allow file -> entries & includes
sub _parse_allow_file {
    my @entries;
    my @includes;

    if (open my $fh, '<', $ALLOW_FILE) {
        while (my $line = <$fh>) {
            chomp $line;
            next if $line =~ /^\s*$/;           # empty
            if ($line =~ /^\s*#/) { next }      # comments/header
            if ($line =~ /^\s*Include\s+(.+)$/i) {
                push @includes, $1;
                next;
            }
            # split into "left" (IP/Rule) + "comment" (after #)
            my ($left, $comment) = split /\s+#\s*/, $line, 2;
            $left =~ s/^\s+|\s+$//g;
            next if $left eq '';

            push @entries, {
                ip      => $left,                           # IP/CIDR or advanced rule
                comment => (defined $comment ? $comment : ''),
                raw     => $line,
            };
        }
        close $fh;
    }

    return (\@entries, \@includes);
}

# ------------------------------------------------------------------------------
# Actions & UI
# ------------------------------------------------------------------------------

sub handle_action {
    my ($form) = @_;
    my $op  = $form->{op}  || '';
    my $ip  = $form->{ip}  || '';
    my $cmt = $form->{cmt} || '';

    _print_css_once();

    if ($op eq 'add' && $ip) {
        my $line = $ip . ($cmt ne '' ? " # $cmt" : '') . "\n";
        open my $fh, '>>', $ALLOW_FILE or die "Cannot write $ALLOW_FILE: $!";
        print $fh $line;
        close $fh;

        my ($rc,$log) = _run_csf_reload();
        print qq{<div class="ls-card" style="padding:10px"><div class="ls-head"><h3>Firewall Allow IPs</h3></div>};
        print "<div class='note'>Added: <span class='badge-ip'>" . _e($ip) . "</span></div>\n";
        _print_csf_log($rc,$log);
        print qq{</div>};
    }
    elsif ($op eq 'del' && $ip) {
        my @kept;
        if (open my $in, '<', $ALLOW_FILE) {
            while (my $line = <$in>) {
                if ($line =~ /^\s*#/ || $line =~ /^\s*$/ || $line =~ /^\s*Include\s/i) {
                    push @kept, $line; next;
                }
                my $tmp = $line; $tmp =~ s/#.*$//; $tmp =~ s/^\s+|\s+$//g;
                # if line starts with the requested IP (followed by space or EOL), drop it
                next if $tmp =~ /^\Q$ip\E(?:\s|$)/;
                push @kept, $line;
            }
            close $in;
        }
        open my $out, '>', $ALLOW_FILE or die "Cannot write $ALLOW_FILE: $!";
        print $out @kept;
        close $out;

        my ($rc,$log) = _run_csf_reload();
        print qq{<div class="ls-card" style="padding:10px"><div class="ls-head"><h3>Firewall Allow IPs</h3></div>};
        print "<div class='note'>Removed: <span class='badge-ip'>" . _e($ip) . "</span></div>\n";
        _print_csf_log($rc,$log);
        print qq{</div>};
    }
    else {
        print qq{<div class="ls-card" style="padding:10px"><div class="ls-head"><h3>Firewall Allow IPs</h3></div><div class="note">No operation performed.</div></div>};
    }

    show($form);  # re-render the table below the log box
}

sub show {
    my ($form) = @_;
    my ($entries, $includes) = _parse_allow_file();
    my $script = _script();

    _print_css_once();

    print qq{<div class="ls-card">};

    # header
    print qq{
      <div class="ls-head">
        <h3>Firewall Allow IPs</h3>
        <div class="summary">Total entries: } . scalar(@$entries) . qq{</div>
      </div>
    };

    # ADD form
    print qq{
      <form action="$script" method="post" style="margin:10px 0">
        <input type="hidden" name="action" value="allowop">
        <input type="hidden" name="op" value="add">
        <div class="ls-row">
          <input type="text"   name="ip"  placeholder="IP / CIDR or advanced rule (e.g., tcp|in|d=22|s=1.2.3.4)" class="ls-input" style="min-width:340px;flex:2">
          <input type="text"   name="cmt" placeholder="Comment (optional)" class="ls-input" style="min-width:220px;flex:1">
          <button type="submit" class="ls-btn btn-primary">Add</button>
        </div>
      </form>
      <div class="note"><code>Include ...</code> lines are shown separately and cannot be edited here.</div>
    };

    # Include (read-only)
    if (@$includes) {
        print qq{
          <div class="ls-card" style="background:#0b1320;margin-top:12px">
            <div class="ls-head" style="margin-bottom:6px"><h3 class="hide-sm">Include (read-only)</h3></div>
            <ul style="margin:0 0 0 18px;padding:0">
        };
        for my $inc (@$includes) {
            print "<li class='note'>" . _e($inc) . "</li>\n";
        }
        print "</ul></div>\n";
    }

    # entries table
    print qq{
      <div style="margin-top:12px">
        <table>
          <thead>
            <tr>
              <th class="hide-sm" style="width:45%">IP / Rule</th>
              <th style="width:45%">Comment</th>
              <th style="width:10%">Actions</th>
            </tr>
          </thead>
          <tbody>
    };

    for my $ent (@$entries) {
        my $ip  = _e($ent->{ip});
        my $cmt = _e($ent->{comment});
        print qq{
          <tr>
            <td class="hide-sm"><span class="badge-ip">$ip</span></td>
            <td>$cmt</td>
            <td>
              <form action="$script" method="post" style="display:inline">
                <input type="hidden" name="action" value="allowop">
                <input type="hidden" name="op"     value="del">
                <input type="hidden" name="ip"     value="$ip">
                <div class="actions">
                  <button type="submit" class="ls-btn btn-danger">Delete</button>
                </div>
              </form>
            </td>
          </tr>
        };
    }

    print qq{
          </tbody>
        </table>
      </div>
    };

    print qq{</div>}; # end ls-card
}

1;
