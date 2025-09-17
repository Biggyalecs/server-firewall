package ConfigServer::LSCIConfig;  # sau pachetul tău actual
use strict;
use warnings;
use Fcntl qw(:flock);

my $LSCI_CONF = '/etc/linuxshield/lsci.conf';

# --- util: escape HTML (fallback dacă nu ai deja unul în modul) ---
sub _e {
    my $s = defined $_[0] ? $_[0] : '';
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g;
    return $s;
}

sub _read_lsci_conf {
    my %cfg = ( LOOKBACK_DAYS => 2 ); # default
    return \%cfg unless -r $LSCI_CONF;

    open my $fh, '<', $LSCI_CONF or return \%cfg;
    while (my $line = <$fh>) {
        $line =~ s/^\x{FEFF}//;             # taie BOM dacă există
        $line =~ s/\r//g;                    # CRLF -> LF
        $line =~ s/\#.*$//;                  # taie comentarii după #
        next if $line =~ /^\s*$/;
        if ($line =~ /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/) {
            my ($k,$v)=($1,$2);
            $v =~ s/^["']//; $v =~ s/["']$//; # taie ghilimele exterioare
            $cfg{$k} = $v;
        }
    }
    close $fh;
    return \%cfg;
}

sub _write_lsci_conf {
    my (%in) = @_;
    my $tmp = "$LSCI_CONF.tmp.$$";

    # scriere atomică + lock
    open my $fh, '>', $tmp or return "Cannot open temp file $tmp: $!";
    flock($fh, LOCK_EX);

    print $fh "# LinuxShield unblock configuration\n\n";
    print $fh "# Numărul de zile în urmă pentru care un IP poate fi deblocat\n";
    my $days = defined $in{LOOKBACK_DAYS} ? $in{LOOKBACK_DAYS} : 2;
    print $fh "LOOKBACK_DAYS=$days\n";

    close $fh;

    # permisiuni: 0644 (UI cPanel poate citi direct). Dacă vrei mai strict, pune 0640.
    chmod 0644, $tmp;
    chown 0, 0, $tmp;     # root:root

    rename $tmp, $LSCI_CONF or return "Cannot move $tmp to $LSCI_CONF: $!";
    return; # ok
}
sub LSCI_install {
    # flush output, să nu pară “white page”
    $| = 1;

    my $wget = -x '/usr/bin/wget' ? '/usr/bin/wget' : '';
    my $curl = -x '/usr/bin/curl' ? '/usr/bin/curl' : '';
    my $bash = -x '/bin/bash'     ? '/bin/bash'     : '/usr/bin/bash';

    my $cmd;
    if ($wget) {
        $cmd = "$wget -qO- https://download.linuxshield.net/lsci/install.sh | $bash";
    } elsif ($curl) {
        $cmd = "$curl -fsSL https://download.linuxshield.net/lsci/install.sh | $bash";
    } else {
        $cmd = ''; # nici wget nici curl
    }

    print "<div class='panel panel-default'>";
    print "<div class='panel-heading'><span class='h3'>LinuxShield LSCI — install</span></div>";
    print "<div class='panel-body'>";

    if (!$cmd) {
        print "<div class='alert alert-danger'>Neither <code>/usr/bin/wget</code> nor <code>/usr/bin/curl</code> found. Please install one of them.</div>";
        print "<p><a href='?action=lcsiconfig' class='btn btn-default'>Back</a></p>";
        print "</div></div>";
        return;
    }

    # arată imediat că a început
    print "<div class='alert alert-info'>Starting install… executing:<br><code>"._e($cmd)."</code></div>";

    # rulează comanda și capturează outputul complet (stdout+stderr)
    my $out = qx{$cmd 2>&1};
    my $rc  = $? >> 8;

    if ($rc == 0) {
        print "<div class='alert alert-success'>Install completed successfully (exit code 0).</div>";
    } else {
        print "<div class='alert alert-danger'>Install failed (exit code $rc).</div>";
    }

    print "<pre style='background:#111;color:#eee;padding:1em;border-radius:8px;white-space:pre-wrap;'>";
    $out = '' unless defined $out;
    $out =~ s/&/&amp;/g; $out =~ s/</&lt;/g; $out =~ s/>/&gt;/g; $out =~ s/\"/&quot;/g;
    print $out;
    print "</pre>";

    print "<p><a href='?action=lcsiconfig' class='btn btn-default'>Back to LSCI Config</a></p>";
    print "</div></div>";
    return;
}
sub LSCI_reinstall {
    # flush output, să nu pară “white page”
    $| = 1;

    my $wget = -x '/usr/bin/wget' ? '/usr/bin/wget' : '';
    my $curl = -x '/usr/bin/curl' ? '/usr/bin/curl' : '';
    my $bash = -x '/bin/bash'     ? '/bin/bash'     : '/usr/bin/bash';

    my $cmd;
    if ($wget) {
        $cmd = "$wget -qO- https://download.linuxshield.net/lsci/install.sh | $bash";
    } elsif ($curl) {
        $cmd = "$curl -fsSL https://download.linuxshield.net/lsci/install.sh | $bash";
    } else {
        $cmd = ''; # nici wget nici curl
    }

    print "<div class='panel panel-default'>";
    print "<div class='panel-heading'><span class='h3'>LinuxShield LSCI — Reinstall</span></div>";
    print "<div class='panel-body'>";

    if (!$cmd) {
        print "<div class='alert alert-danger'>Neither <code>/usr/bin/wget</code> nor <code>/usr/bin/curl</code> found. Please install one of them.</div>";
        print "<p><a href='?action=lcsiconfig' class='btn btn-default'>Back</a></p>";
        print "</div></div>";
        return;
    }

    # arată imediat că a început
    print "<div class='alert alert-info'>Starting reinstall… executing:<br><code>"._e($cmd)."</code></div>";

    # rulează comanda și capturează outputul complet (stdout+stderr)
    my $out = qx{$cmd 2>&1};
    my $rc  = $? >> 8;

    if ($rc == 0) {
        print "<div class='alert alert-success'>Reinstall completed successfully (exit code 0).</div>";
    } else {
        print "<div class='alert alert-danger'>Reinstall failed (exit code $rc).</div>";
    }

    print "<pre style='background:#111;color:#eee;padding:1em;border-radius:8px;white-space:pre-wrap;'>";
    $out = '' unless defined $out;
    $out =~ s/&/&amp;/g; $out =~ s/</&lt;/g; $out =~ s/>/&gt;/g; $out =~ s/\"/&quot;/g;
    print $out;
    print "</pre>";

    print "<p><a href='?action=lcsiconfig' class='btn btn-default'>Back to LSCI Config</a></p>";
    print "</div></div>";
    return;
}
sub LSCI_uninstall {
    # flush output, să nu pară “white page”
    $| = 1;

    my $wget = -x '/usr/bin/wget' ? '/usr/bin/wget' : '';
    my $curl = -x '/usr/bin/curl' ? '/usr/bin/curl' : '';
    my $bash = -x '/bin/bash'     ? '/bin/bash'     : '/usr/bin/bash';

    my $cmd;
    if ($wget) {
        $cmd = "$wget -qO- https://download.linuxshield.net/lsci/uninstall.sh | $bash";
    } elsif ($curl) {
        $cmd = "$curl -fsSL https://download.linuxshield.net/lsci/uninstall.sh | $bash";
    } else {
        $cmd = ''; # nici wget nici curl
    }

    print "<div class='panel panel-default'>";
    print "<div class='panel-heading'><span class='h3'>LinuxShield LSCI — Uninstall</span></div>";
    print "<div class='panel-body'>";

    if (!$cmd) {
        print "<div class='alert alert-danger'>Neither <code>/usr/bin/wget</code> nor <code>/usr/bin/curl</code> found. Please install one of them.</div>";
        print "<p><a href='?action=lcsiconfig' class='btn btn-default'>Back</a></p>";
        print "</div></div>";
        return;
    }

    # arată imediat că a început
    print "<div class='alert alert-info'>Starting uninstall… executing:<br><code>"._e($cmd)."</code></div>";

    # rulează comanda și capturează outputul complet (stdout+stderr)
    my $out = qx{$cmd 2>&1};
    my $rc  = $? >> 8;

    if ($rc == 0) {
        print "<div class='alert alert-success'>Uninstall completed successfully (exit code 0).</div>";
    } else {
        print "<div class='alert alert-danger'>Uninstall failed (exit code $rc).</div>";
    }

    print "<pre style='background:#111;color:#eee;padding:1em;border-radius:8px;white-space:pre-wrap;'>";
    $out = '' unless defined $out;
    $out =~ s/&/&amp;/g; $out =~ s/</&lt;/g; $out =~ s/>/&gt;/g; $out =~ s/\"/&quot;/g;
    print $out;
    print "</pre>";

    print "<p><a href='csf.cgi' class='btn btn-default'>Back to LSF</a></p>";
    print "</div></div>";
    return;
}
sub LSCI_config {
    # $script și %FORM probabil există deja în modul tău; dacă nu, folosește CGI.pm
    no strict 'refs';
    my $script = $main::script // $ENV{SCRIPT_NAME} // '';
    my %FORM = %main::FORM;

    my $message = '';
    my $error   = '';

    # handle POST (save)
    if (defined $FORM{do} and $FORM{do} eq 'save') {
        my $val = defined $FORM{LOOKBACK_DAYS} ? $FORM{LOOKBACK_DAYS} : '';
        $val =~ s/\s+//g;

        if ($val !~ /^\d+$/) {
            $error = "LOOKBACK_DAYS must be an integer (>= 0)";
        }
        elsif ($val > 365) {
            # limită rezonabilă (poți schimba)
            $error = "LOOKBACK_DAYS too large (max 365)";
        }
        else {
            if (my $err = _write_lsci_conf(LOOKBACK_DAYS => $val)) {
                $error = _e($err);
            } else {
                $message = "Configuration saved: LOOKBACK_DAYS=$val";
            }
        }
    }

    my $cfg = _read_lsci_conf();
    my $days = $cfg->{LOOKBACK_DAYS};
    $days = 0 unless defined $days && $days =~ /^\d+$/;

    # --- render UI ---
    print "<div class='panel panel-default'>";
    print "<div class='panel-heading'><span class='h3'>LinuxShield Cpanel Interface (LSCI) — Configuration</span></div>";
    print "<div class='panel-body'>";

    if ($message ne '') {
        print "<div class='alert alert-success'>" . _e($message) . "</div>";
    }
    if ($error ne '') {
        print "<div class='alert alert-danger'>" . _e($error) . "</div>";
    }

    print "<form action='"._e($script)."' method='post' class='form-horizontal' autocomplete='off'>";
    print "<input type='hidden' name='action' value='lcsiconfig'>";
    print "<input type='hidden' name='do' value='save'>";

    print "<div class='form-group'>";
    print "  <label class='col-sm-3 control-label' for='LOOKBACK_DAYS'>LOOKBACK_DAYS</label>";
    print "  <div class='col-sm-3'>";
    print "    <input type='number' min='0' max='365' step='1' class='form-control' id='LOOKBACK_DAYS' name='LOOKBACK_DAYS' value='"._e($days)."'>";
    print "    <span class='help-block'>Number of days ago for which an IP can be unblocked from Cpanel interface.</span>";
    print "  </div>";
    print "</div>";

    print "<div class='form-group'>";
    print "  <div class='col-sm-6 col-sm-offset-3'>";
    print "    <button type='submit' class='btn btn-primary'><i class='glyphicon glyphicon-ok'></i> Save</button> ";
    print "    <button type='button' class='btn btn-default' onclick='history.back();'>Cancel</button>";
    print "  </div>";
    print "</div>";

    print "</form>";


    print "<hr>";
    print "<div class='form-inline'>";

    print "<form action='"._e($script)."' method='post' style='display:inline-block;margin-right:5px;'>";
    print "<input type='hidden' name='action' value='lscireinstall'>";
    print "<button type='submit' class='btn btn-warning' ".
        "onclick=\"return confirm('Are you sure you want to reinstall LSCI?');\">".
        "<i class='glyphicon glyphicon-refresh'></i> Reinstall LSCI</button>";
    print "</form>";

    print "<form action='"._e($script)."' method='post' style='display:inline-block;'>";
    print "<input type='hidden' name='action' value='lsciuninstall'>";
    print "<button type='submit' class='btn btn-danger' ".
        "onclick=\"return confirm('Are you sure you want to uninstall LSCI?');\">".
        "<i class='glyphicon glyphicon-remove'></i> Uninstall LSCI</button>";
    print "</form>";

    print "</div>";

    print "<p>File: <code>"._e($LSCI_CONF)."</code></p>";

    print "</div></div>";

    return;
}
