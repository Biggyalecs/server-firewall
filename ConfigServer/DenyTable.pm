package ConfigServer::DenyTable;
use strict;
use warnings;
use utf8;  # pentru „—”

# Config
my $CSF_DENY_FILE = '/etc/csf/csf.deny';
my $CSF_BIN       = '/usr/sbin/csf';

# --- util: escape HTML (folosește specialchars din UI dacă există)
sub _e {
    no strict 'refs';
    if (defined &ConfigServer::DisplayUI::specialchars) {
        return ConfigServer::DisplayUI::specialchars($_[0]);
    }
    if (defined &main::specialchars) {
        return main::specialchars($_[0]);
    }
    my $s = defined $_[0] ? $_[0] : '';
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g;
    return $s;
}

sub _valid_ip {
    my ($ip) = @_;
    return (defined $ip && $ip ne '' && $ip =~ /^[0-9A-Fa-f:\.\/]+$/) ? 1 : 0; # IPv4/IPv6 + /CIDR
}

sub _remove_ip_from_file {
    my ($file, $ip) = @_;
    return 0 unless -r $file && -w $file;

    open my $fh, '<', $file or return 0;
    my @lines = <$fh>;
    close $fh;

    my $changed = 0;
    my @out;
    foreach my $ln (@lines) {
        if ($ln =~ /^\Q$ip\E(?:\s|$)/) { $changed = 1; next; }
        push @out, $ln;
    }
    if ($changed) {
        my $tmp = "$file.tmp";
        open my $fw, '>', $tmp or return 0;
        print $fw @out;
        close $fw;
        rename $tmp, $file;
    }
    return $changed;
}

sub handle_action {
    my ($form) = @_;
    my $op = (defined $form->{op}) ? $form->{op} : '';
    my $ip = (defined $form->{ip}) ? $form->{ip} : '';

    unless (_valid_ip($ip)) {
        print qq{<div class="alert alert-danger">Invalid IP.</div>};
        print qq{<meta http-equiv="refresh" content="1; url=?action=deny">};
        return;
    }

    my $changed = _remove_ip_from_file($CSF_DENY_FILE, $ip);

    my $msg;
    if ($changed) {
        if ($op eq 'unblock') {
            # rulează csf -dr (necesită sudo fără parolă pt userul web)
            my $rc = system('sudo', $CSF_BIN, '-dr', $ip);
            if ($rc == 0) { $msg = "Unblocked and deleted: $ip"; }
            else          { $msg = "Deleted from list: $ip (atenție: csf -dr a eșuat, rc=$rc)"; }
        } else {
            $msg = "Deleted from list: $ip";
        }
    } else {
        $msg = "Didn't found $ip in list";
    }

    print qq{<div class="alert alert-info">}._e($msg).qq{</div>};
    print qq{<meta http-equiv="refresh" content="1; url=?action=deny">};
}

sub render_table {
    my ($form) = @_;
    my $q = (defined $form->{q}) ? $form->{q} : '';
    my $p = (defined $form->{p} && $form->{p} =~ /^\d+$/ && $form->{p} > 0) ? int($form->{p}) : 1;

    # --- per-page: 10 (default), 100, 1000; citim din parametru sau din cookie
    my $per = 10; # implicit
    if (defined $form->{per} && $form->{per} =~ /^(10|100|1000)$/) {
        $per = int($form->{per});
    } elsif (defined $ENV{HTTP_COOKIE} && $ENV{HTTP_COOKIE} =~ /(?:^|;\s*)csf_deny_per=(\d+)/) {
        my $cper = $1;
        $per = int($cper) if $cper =~ /^(10|100|1000)$/;
    }
    my $PER_PAGE = $per;

    # util: urlencode simplu pentru link-urile de paginare
    my $q_url = $q;  $q_url =~ s/([^A-Za-z0-9\-\._~])/sprintf("%%%02X", ord($1))/seg;
    my $per_url = $PER_PAGE; # doar numeric; folosit în linkuri

    my @rows;

    if (!-r $CSF_DENY_FILE) {
        print qq{<div class="alert alert-danger">Can't read $CSF_DENY_FILE</div>};
        return;
    }

    my $fh;
    unless (open $fh, '<', $CSF_DENY_FILE) {
        print qq{<div class="alert alert-danger">Can't open $CSF_DENY_FILE</div>};
        return;
    }
    while (my $ln = <$fh>) {
        next if $ln =~ /^\s*$/ || $ln =~ /^\s*#/;

        # IP-ul (primul token)
        my ($ip) = ($ln =~ /^([0-9A-Fa-f:\.\/]+)/);

        # Tot ce e după # ... (meta)
        my ($after_hash) = ($ln =~ /#\s*(.*)$/);

        my ($left, $date);
        if (defined $after_hash) {
            # Split STRICT la " - " (spațiu minus spațiu); greedy pe stânga => taie la ultimul " - "
            if ($after_hash =~ /^(.*)\s-\s+(.*)$/) {
                ($left, $date) = ($1, $2);
            } else {
                $left = $after_hash;   # fără separator " - " => nu știm data
                $date = '—';
            }
        }

        # Motivul = tot ce e înainte de prima "(" din stânga
        my $mot = '—';
        if (defined $left) {
            if ($left =~ /^(.*?)\s*\(/) { $mot = $1; }
            else                        { $mot = $left; }
        }

        # Țara/Host = conținutul dintre paranteze (...) din stânga
        my $where = '—';
        if (defined $left && $left =~ /\(([^)]*)\)/) { $where = $1; }

        # Normalizări
        $ip    = (defined $ip    && $ip ne ''   ) ? $ip    : '—';
        $mot   = (defined $mot   && $mot ne ''  ) ? $mot   : '—';
        $where = (defined $where && $where ne '') ? $where : '—';
        $date  = (defined $date  && $date ne '' ) ? $date  : '—';

        my $row_text = join(' ', $ip, $mot, $where, $date);
        next if ($q ne '' && $row_text !~ /\Q$q\E/i);

        push @rows, { ip=>$ip, mot=>$mot, where=>$where, date=>$date };
    }
    close $fh;

    # cele mai noi primele (fișierul e append-only)
    @rows = reverse @rows;

    # --- paginare ---
    my $total  = scalar @rows;
    my $pages  = $total ? int( ($total + $PER_PAGE - 1) / $PER_PAGE ) : 1;
    $p = 1 if $p < 1;
    $p = $pages if $p > $pages;

    my $start = ($p - 1) * $PER_PAGE;
    my $end   = $start + $PER_PAGE - 1;
    $end      = $total - 1 if $end > $total - 1;

    my @view = ();
    if ($total > 0 && $start <= $end) {
        @view = @rows[$start .. $end];
    }

    # helper pt. UI paginare (interval pagini cu ellipsis)
    my @page_nums;
    if ($pages <= 9) {
        @page_nums = (1..$pages);
    } else {
        push @page_nums, 1, 2;
        my $a = $p - 2;
        my $b = $p + 2;
        $a = 3 if $a < 3;
        $b = $pages - 2 if $b > $pages - 2;
        push @page_nums, '...' if $a > 3;
        for (my $i=$a; $i<=$b; $i++) { push @page_nums, $i; }
        push @page_nums, '...' if $b < $pages - 2;
        push @page_nums, $pages-1, $pages;
    }

    # CSS (q{} ca să nu se încerce interpolarea lui @media)
    print q{
    <style>
      .ls-card{background:#0f1a2b;border:1px solid #1f2a3c;border-radius:14px;padding:16px;margin-bottom:16px;color:#e9eef6}
      .ls-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap}
      .ls-head h3{margin:0;color:#dfe9ff;font-size:18px}
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
    </style>
    };

    my $q_e = _e($q);

    # componentă paginare (sus + jos)
    my $from = $total ? ($start + 1) : 0;
    my $to   = $total ? ($end + 1)   : 0;

    my $prev_p = $p > 1 ? $p - 1 : 1;
    my $next_p = $p < $pages ? $p + 1 : $pages;

    my $pager_html = qq{
      <div class="pager">
        <a class="} . ($p==1?'disabled':'') . qq{" href="?action=deny&q=$q_url&per=$per_url&p=$prev_p">&laquo; Prev</a>
    };

    foreach my $n (@page_nums) {
        if ($n eq '...') {
            $pager_html .= qq{<span>...</span>};
        } elsif ($n == $p) {
            $pager_html .= qq{<span class="active">$n</span>};
        } else {
            $pager_html .= qq{<a href="?action=deny&q=$q_url&per=$per_url&p=$n">$n</a>};
        }
    }

    $pager_html .= qq{
        <a class="} . ($p==$pages?'disabled':'') . qq{" href="?action=deny&q=$q_url&per=$per_url&p=$next_p">Next &raquo;</a>
        <span class="summary">Display $from–$to from $total</span>
      </div>
    };

    # selector per-page (salvează în cookie și trimite per în query)
    my $sel10   = $PER_PAGE==10   ? 'selected' : '';
    my $sel100  = $PER_PAGE==100  ? 'selected' : '';
    my $sel1000 = $PER_PAGE==1000 ? 'selected' : '';

    print qq{
    <div class="ls-card">
      <div class="ls-head">
        <h3>LinuxShield - LSF — Blocked IPs</h3>
        <form method="get" style="display:flex;gap:8px;align-items:center;">
          <input type="hidden" name="action" value="deny">
          <input type="hidden" name="p" value="1">
          <input class="ls-input" type="text" name="q" value="$q_e" placeholder="Search: IP / Country / host / reason / date">
          <select name="per" class="ls-select" onchange="document.cookie='csf_deny_per='+this.value+';path=/;max-age=31536000'; this.form.submit();">
            <option value="10" $sel10>10 / page</option>
            <option value="100" $sel100>100 / page</option>
            <option value="1000" $sel1000>1000 / page</option>
          </select>
          <button class="ls-btn btn-primary">Search</button>
        </form>
      </div>

      $pager_html

      <div style="overflow:auto">
        <table>
          <thead>
            <tr>
              <th style="min-width:180px">IP / CIDR</th>
              <th class="hide-sm" style="min-width:220px">Country / Host</th>
              <th style="min-width:200px">Reason</th>
              <th class="hide-sm" style="min-width:200px">Date</th>
              <th style="width:190px">Actions</th>
            </tr>
          </thead>
          <tbody>
    };

    if (!@view) {
        print qq{<tr><td colspan="5" style="text-align:center;padding:16px;">No ip found in list.</td></tr>};
    } else {
        foreach my $r (@view) {
            my $ip    = _e($r->{ip});
            my $mot   = _e($r->{mot});
            my $where = _e($r->{where});
            my $date  = _e($r->{date});

            print qq{
              <tr>
                <td><span class="badge-ip">$ip</span></td>
                <td class="hide-sm">$where</td>
                <td>$mot</td>
                <td class="hide-sm">$date</td>
                <td>
                  <div class="actions">
                    <form method="post" onsubmit="return confirm('Unblock and delete: $ip ?');">
                      <input type="hidden" name="action" value="denyop">
                      <input type="hidden" name="op" value="unblock">
                      <input type="hidden" name="ip" value="$ip">
                      <button class="ls-btn btn-warn" type="submit">Unblock</button>
                    </form>
                    <form method="post" onsubmit="return confirm('Delete from list: $ip ?');">
                      <input type="hidden" name="action" value="denyop">
                      <input type="hidden" name="op" value="delete">
                      <input type="hidden" name="ip" value="$ip">
                      <button class="ls-btn btn-danger" type="submit">Delete</button>
                    </form>
                  </div>
                </td>
              </tr>
            };
        }
    }

    print qq{
          </tbody>
        </table>
      </div>

      $pager_html

      <div class="note">Source file: <code>}._e($CSF_DENY_FILE).qq{</code></div>
    </div>
    };
}


1; # end module
