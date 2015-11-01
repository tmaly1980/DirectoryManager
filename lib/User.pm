package User;

use base "Address";
use Net::LDAP;
use Data::Dumper;
use Group;
use FileHandle;
use IPC::Open3;
use IO::Select;
use HTTP::Request::Common;
use MIME::Base64;

sub subclass_init
{
  return ("user", "uidNumber");
}

sub db2cgi
{
  my ($self) = @_;
  my %db2cgi = $self->SUPER::db2cgi();
  my ($oc) = $self->get_schema();
  my $tree = $self->{DBPARAMS}->[0];
  my $pri_key = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};

  my %other_links = $self->get_other_links();

  return
  (
    %other_links, # Non-standard ones...
    %db2cgi,
    accountLock=>[ sub { $self->accountLock(@_) }, "#userPassword#" ],
    acctFlagsList=>[ sub { $self->acctFlagsList(@_) }, "#acctFlags#" ],
    sambaAcctFlagsList=>[ sub { $self->acctFlagsList(@_) }, "#sambaAcctFlags#" ],
    PHOTO_URL=>"cgi-bin/View.pl/$tree/photo/$pri_key=#$pri_key#",
  );
}

sub get_other_links
{
  my ($self) = @_;
  my ($oc) = $self->get_schema;
  my $treename = $self->{DBPARAMS}->[0];
  my $implicit = $self->{GLOBAL}->{CONFIG}->get("IMPLICIT_LINK");
  return () if ( ($implicit == 2 and $self->{GLOBAL}->{MODE} ne 'Edit') or not $implicit or $self->{NOLINK});

  return 
  (
    MANAGER_META=> [ sub { $self->manager_meta(); } ]
  );

  # Hash -> get_pseudo_meta
  # get_pseudo_meta -> db2cgi
  # db2cgi -> get_other_links
  # get_other_links -> get
  # get -> get_pseudo_meta, but prior to returning from previous get_pseudo_meta!
}

sub manager_meta
{
  my ($self) = @_;

  my ($oc) = $self->get_schema;

  # Manager info.
  my @managers = $self->get("manager");
  my @manager_meta = ();
  my $basedn = $self->{GLOBAL}->{CONFIG}->oc_basedn($oc, $treename);
  foreach my $manager (@managers)
  {
    my $manager_meta = undef;
    if(my ($uid) = $manager =~ /^uid=([^,]+),$basedn$/)
    {
      my $mgrobj = User->new();
      $mgrobj->{NOLINK} = 1;
      $mgrobj->search_cols('cn,uid', uid=>$uid);
      if ($mgrobj->count)
      {
        $manager_meta = $mgrobj->hashref;
      } else {
        $manager_meta = {dn=>$manager};
      }
    } else {
      $manager_meta = {dn=>$manager,foo=>1};
    }
    push @manager_meta, $manager_meta;
  }

  return \@manager_meta;
}

sub accountLock
{
  my ($self, $pass) = @_;
  return ($pass =~ /^[!]/ ? 1 : 0);
}

sub acctFlagsList
{
  my ($self, $flags) = @_;
  return { map { ($_, $_) } split ("", $flags) };
}

sub generateRID
{
  my ($self, $uidnumber) = @_;

  # Do lookup of NAME
  $self = User->search_cols('uid', uidNumber=>$uidnumber) if not ref $self;
  my $treename = $self->{DBPARAMS}->[0];
  my $uid = $self->get("UID");

  # SAMBAADM, SAMBADOMADM, SAMBADOMUSERS, SAMBADOMGUEST, SAMBAGUEST
  if ($uid ne '' and $uid eq $self->{GLOBAL}->{CONFIG}->get("SAMBA{ADM}"))
  {
    return 500; # Domain Administrator
  } 
  elsif ($uid ne '' and $uid eq $self->{GLOBAL}->{CONFIG}->get("SAMBA{GUEST}"))
  {
    return 501; # Domain Guest
  } else {
      return (1000+2*$uidnumber);
  }
}

sub samba3_sync
{
  my ($self, %hash) = @_;

    if (ref $hash{SAMBAUSERWORKSTATIONS} eq 'ARRAY') # Convert to comma-separated list.
    {
      $hash{SAMBAUSERWORKSTATIONS} = join(", ", @{ $hash{SAMBAUSERWORKSTATIONS} });
    }
  
    #### SAMBAACCTFLAGS ####
    if ($hash{SAMBAACCTFLAGS_X} or $hash{SAMBAACCTFLAGS_D})
    {
      my $no_expire = $hash{SAMBAACCTFLAGS_X};
      my $disabled = $hash{SAMBAACCTFLAGS_D};
      my @flags = ("U");
    
        push @flags, $disabled if $disabled;
      push @flags, $no_expire if $no_expire;
    
    
      my @new_flags = ();
      for (my $i = 0; $i < 11; $i++)
      {
        $new_flags[$i] = $flags[$i] || ' ';
      }
      my $flags = '[' . join("", @new_flags) . ']';
  
      $hash{SAMBAACCTFLAGS} = $flags;
    }


    # For samba implementation after account created, must come up with id's
    my $server_sid = $self->{GLOBAL}->{CONFIG}->get("SAMBA{SID}");
    $self->system_error("Cannot generate user SID, tree is not configured with a Server SID!") unless $server_sid;
    if ($hash{UIDNUMBER} ne '')
    {
      $hash{SAMBASID} = "$server_sid-" . $self->generateRID($hash{UIDNUMBER});
    }
    if ($hash{GIDNUMBER} ne '')
    {
      $hash{SAMBAPRIMARYGROUPSID} = "$server_sid-" . Group->generateRID($hash{GIDNUMBER});
    }

    if ($hash{USERPASSWORD1})
    {
      require Crypt::SmbHash;
      my ($lmpass, $ntpass) = Crypt::SmbHash::ntlmgen($hash{USERPASSWORD1});
      $hash{SAMBANTPASSWORD} = $ntpass;
      $hash{SAMBALMPASSWORD} = $lmpass;
      $hash{SAMBAPWDMUSTCHANGE} = "2147483647";
      $hash{SAMBAPWDCANCHANGE} = 0;
    }

  if ($hash{CN})
  {
    my @name = split(/\s+/, $hash{CN});
    $hash{DISPLAYNAME} = join(" ", @name);
  }

    return %hash;
}

sub samba2_sync
{
  my ($self, %hash) = @_;

    #### ACCTFLAGS ####
    if ($hash{ACCTFLAGS_X} or $hash{ACCTFLAGS_D})
    {
      my $no_expire = $hash{ACCTFLAGS_X};
      my $disabled = $hash{ACCTFLAGS_D};
      my @flags = ("U");
  
      push @flags, $disabled if $disabled;
      push @flags, $no_expire if $no_expire;
  
  
      my @new_flags = ();
      for (my $i = 0; $i < 11; $i++)
      {
        $new_flags[$i] = $flags[$i] || ' ';
      }
      my $flags = '[' . join("", @new_flags) . ']';

      $hash{ACCTFLAGS} = $flags;
    }

    #### END ACCTFLAGS ####

    #### OTHER SAMBA PASSWORD SETTINGS ####
  	# Eventually, make these customizable per user

    # For samba implementation after account created, must come up with id's
    if ($hash{UIDNUMBER} ne '')
    {
      $hash{RID} = $self->generateRID($hash{UIDNUMBER});
    }
    if ($hash{GIDNUMBER} ne '')
    {
      $hash{PRIMARYGROUPID} = Group->generateRID($hash{GIDNUMBER});
    }

    if ($hash{USERPASSWORD1})
    {
      require Crypt::SmbHash;
      my ($lmpass, $ntpass) = Crypt::SmbHash::ntlmgen($hash{USERPASSWORD1});
      $hash{NTPASSWORD} = $ntpass;
      $hash{LMPASSWORD} = $lmpass;
      $hash{PWDMUSTCHANGE} = "2147483647";
      $hash{PWDCANCHANGE} = 0;
    }

  if ($hash{CN})
  {
    my @name = split(/\s+/, $hash{CN});
    $hash{DISPLAYNAME} = join(" ", @name);
  }

    #### END OTHER SAMBA PASSWORD SETTINGS ####
    return %hash;
}

sub get_pending_changes
{
  my ($self) = @_;
  $self->samba3to2_sync() if $self->{GLOBAL}->{CONFIG}->has_admin_access; # Backwards compat
  $self->SUPER::get_pending_changes();
}

sub samba3to2_sync
{
  my ($self) = @_;
  my $et = $self->get("entry_type") || $self->entry_type();
  return () unless $et eq 'samba32';

  my ($oc) = $self->get_schema;
  my %samba32map = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"SAMBA23MAP"});

    # We need to use 'get' because we need to convert all at once even if
    # All the data was not presented/changed.
    #
    #

    $self->set(map { ($samba32map{$_}, $self->get($_)) } keys %samba32map);
    # Now fix sambaSID and primarygroupID
    my $primarygroupid = $self->get("SAMBAPRIMARYGROUPSID");
    ($primarygroupid) = $primarygroupid =~ /-(\d+)$/;
    $self->set("primaryGroupID", $priamrygroupid);
    my $sambasid = $self->get("SAMBASID");
    my ($rid) = $sambasid =~ /-(\d+)$/;
    $self->set("RID", $rid);
}

sub account_lock_sync
{
  my ($self, %changes) = @_;

  # This gets run right before commit, and 'accountlock' is not mentioned then.
  # So, what do we do?
  # This assumes that no info means to unlock...
  # but shouldnt be the case on the second run of sync...

  my $lock = $changes{ACCOUNTLOCK};

  my $up = $changes{USERPASSWORD} || $self->get("userPassword");
  my $nt3 = $changes{SAMBANTPASSWORD} || $self->get("sambaNTPassword");
  my $lm3 = $changes{SAMBALMPASSWORD} || $self->get("sambaLMPassword");
  my $nt2 = $changes{NTPASSWORD} || $self->get("NTPassword");
  my $lm2 = $changes{LMPASSWORD} || $self->get("LMPassword");

  if ($lock and $up !~ /^[!]/)
  {
    $changes{USERPASSWORD} = "!$up" unless $up =~ /^[!]/;
    if ($samba eq '3' or $samba eq '3+2')
    {
      $changes{SAMBANTPASSWORD} = "!$nt3" unless $nt3 =~ /^[!]/;
      $changes{SAMBALMPASSWORD} = "!$lm3" unless $lm3 =~ /^[!]/;
    } elsif ($samba eq '2' or $samba eq '3+2') {
      $changes{NTPASSWORD} = "!$nt2" unless $nt2 =~ /^[!]/;
      $changes{LMPASSWORD} = "!$lm2" unless $lm2 =~ /^[!]/;
    }
  } elsif ($up =~ /^[!]/ and not $lock) { 
    # Make sure password is unlocked!
    $changes{USERPASSWORD} = $up;
    $changes{USERPASSWORD} =~ s/^[!]//;
    if ($samba eq '3' or $samba eq '3+2')
    {
      $changes{SAMBANTPASSWORD} = $nt3;
      $changes{SAMBALMPASSWORD} = $lm3;
      $changes{SAMBANTPASSWORD} =~ s/^[!]//;
      $changes{SAMBALMPASSWORD} =~ s/^[!]//;
    } elsif ($samba eq '2' or $samba eq '3+2') {
      $changes{NTPASSWORD} = $nt2;
      $changes{LMPASSWORD} = $lm2;
      $changes{NTPASSWORD} =~ s/^[!]//;
      $changes{LMPASSWORD} =~ s/^[!]//;
    }
  }
  return %changes;
}

sub set_sync # Sync to call on set()...
{
  my ($self, %hash) = @_;
  %hash = $self->sync(%hash);

  # Account lock (or unlock)
  %hash = $self->account_lock_sync(%hash);

  return %hash;
}

sub sync # Sync now happens AFTER set(), but STILL may only get subset of data. So still conditional syncing.
{
  my ($self, %hash) = @_;


  %hash = $self->SUPER::sync(%hash);
  my ($oc) = $self->get_schema;
  my %samba32map = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"SAMBA23MAP"});

  #my $samba = $self->{GLOBAL}->{CONFIG}->get_samba_version($self->get_tree);
  my $entry_type = $hash{ENTRY_TYPE}||$self->entry_type();

  my $samba = 
    {
      address=>'0',
      unix=>'0',
      samba=>'2',
      samba3=>'3',
      samba32=>'3+2',
    }->{$entry_type};
  my %samba32map = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"SAMBA23MAP"});
  my %samba23map = reverse %samba32map;

  #### GIDNUMBER ####
  if ($hash{GIDNUMBER} ne '')
  {
    $hash{GIDNUMBER} = $self->get_gidNumber($hash{GIDNUMBER});
  }
  #### END GIDNUMBER ####

  ### GECOS ET AL ###
  if ($hash{CN})
  {
    my @name = split(/\s+/, $hash{CN});
    $hash{SN} = $name[$#name];
    $hash{GIVENNAME} = $name[0];
    $hash{GECOS} = join(" ", @name);
  }
  ### END GECOS ###

  if ($hash{HOMEDIRECTORY_CREATE})
  {
    $self->{HOMEDIRECTORY_CREATE} = 1;
  }



  # DO SAMBA 3 STUFF HERE.....
  %hash = $self->samba3_sync(%hash) if ($samba eq '3' or $samba eq '3+2');

  # SAMBA 2 stuff...
  %hash = $self->samba2_sync(%hash) if ($samba eq '2');

  return %hash;
}

sub import
{
  my ($self, %hash) = @_;
  if ($hash{userPassword} =~ /^[^{]/) # Doesn't start with '{', needs it.
  {
    $hash{userPassword} = "{CRYPT}$hash{userPassword}";
  }
  %hash = $self->SUPER::import(%hash);
}

sub get_gidNumber
{
  my ($self, $gidNumber) = @_;

  if ($gidNumber ne '' and $gidNumber !~ /^\d+$/) # Lookup by name.
  {
    my $group = Group->new();
    $group->search_cols(['gidNumber'], cn=>$gidNumber);
    $self->user_error("No such group with the id/name '$gidNumber'") if not $group->count;
    return $group->get("gidNumber");
  } else {
    return $gidNumber;
  }
}

sub report_vars
{
  my ($self) = @_;
  my %vars = $self->SUPER::report_vars(@_);
  $vars{USERPASSWORD} = $self->{USERPASSWORD_RANDOM};
  undef $vars{ACCOUNTLOCK};
  return %vars;
}

sub post_update
{
  my ($self) = @_;
  $self->SUPER::post_update();
  my ($oc) = $self->get_schema;
  if ($self->{HOMEDIRECTORY_CREATE} && grep { /posixAccount/ } $self->get("objectClass"))
  #if (self->{GLOBAL}->{CONFIG}->get("CREATE_HOME_DIRS"))
  {
    my $dir = $self->get("homeDirectory");
    my $uid = $self->get("uid");
    my $gidNumber = $self->get("gidNumber");
    my $group = Group->search(gidNumber=>$gidNumber);
    my $gid = $group->get("cn");
    $self->user_error("Cannot create home directory: Group with gidNumber '$gidNumber' does not exist in this tree.")
      unless $gid;
    $self->create_home_dir($dir, $uid, $gid);
  }
}

sub post_insert # Add home directory.
{
  my ($self) = @_;
  $self->SUPER::post_insert(); # Still do notification, etc... as needed.
  my ($oc) = $self->get_schema;
  if ($self->{HOMEDIRECTORY_CREATE} && grep { /posixAccount/ } $self->get("objectClass"))
  #if (self->{GLOBAL}->{CONFIG}->get("CREATE_HOME_DIRS"))
  {
    my $dir = $self->get("homeDirectory");
    my $uid = $self->get("uid");
    my $gidNumber = $self->get("gidNumber");
    my $group = Group->search(gidNumber=>$gidNumber);
    my $gid = $group->get("cn");
    $self->user_error("Cannot create home directory: Group with gidNumber '$gidNumber' does not exist in this tree.")
      unless $gid;
    $self->create_home_dir($dir, $uid, $gid);
  }
}

sub create_home_dir # This uses LWP and a dedicated HTTPS Daemon.
{
  my ($self, $dir, $uid, $gid) = @_;
  $self->user_error("Home Directory ($dir) or Username ($uid) or Group ($gid) not valid or not specified!", $self->get("EDIT_URL")) unless ($dir and $uid and $gid);
  my $pass = $self->{GLOBAL}->{CONFIG}->get("MODULES{user}{HOMEDIR}{PASS}");
  my $host = $self->{GLOBAL}->{CONFIG}->get("MODULES{user}{HOMEDIR}{HOST}") || "localhost";
  my $port = $self->{GLOBAL}->{CONFIG}->get("MODULES{user}{HOMEDIR}{PORT}") || "3890";
  $self->user_error("No password specified for home directory creation.", $self->get("EDIT_URL")) unless $pass;

  require LWP::UserAgent;
  $self->{UA} ||= LWP::UserAgent->new(timeout=>15);
  # XXX TODO USE BASIC AUTH TO SEND...

  my $encoded_auth = "Basic ".encode_base64("admin:$pass");

  #my $resp = $self->{UA}->request(POST "https://$host:$port", [DIR=>$dir, UID=>$uid, GID=>$gid], [Authorization=>$encoded_auth);
  my $resp = $self->{UA}->request(POST "http://$host:$port", [DIR=>$dir, UID=>$uid, GID=>$gid], Authorization=>$encoded_auth);
  if (not $resp->is_success)
  {
    my $content = $resp->content || $resp->message;
    $self->system_error("Cannot create home directory: " . $content, $self->get("EDIT_URL"));
  }
}

                                                                                                                                         
sub get_session
{
  my ($self, $session_id) = @_;
  my $session = $self->{GLOBAL}->{SESSION}->default_get_existing_session($session_id);
  return $session unless ref $session eq 'HASH';
  my $uid = $session->{username};
  my $tree = $session->{TREENAME};
  $self->init($tree) if $tree;
  if ($uid)
  {
    $uid =~ s/^uid=([^,]+),.*/$1/;
    $self->search(UID=>$uid);
    $session = { %$session, $self->hash };
  }
  return $session;
}

sub authenticate_session_old # For tie in with MalySession.
{
  my ($self, $u, $p) = @_;
  my $dn = $u;
  if ($dn !~ /[,]/)
  {
    $dn = $self->get_dn("uid=$u");
    if (not $dn)
    {
      $self->{ERROR} = "No such user ($u).";
      $self->internal_error($self->{ERROR});
      return undef;
    }
  }

  #my $temp_ldap = Net::LDAP->new($self->connect_params);
  #if (not $temp_ldap)
  #{
  #  $self->{ERROR} = "Can't connect: $!";
  #  $self->internal_error($self->{ERROR});
  #  return undef;
  #}
  ## Use TLS if needed.
#
#  #
#  my $rc = $temp_ldap->bind($dn, password=>$p);
#  if ($rc and $rc->code)
#  {
#    $self->{ERROR} = "Cannot Login/Authenticate: " . $rc->error;
#    $self->user_error($self->{ERROR});
#  }
#  # Need to set class variable!

  $self->creds($dn, $p);
  $self->connect() and return $dn;
}

sub authenticate_session # For tie in with MalySession.
{
  my ($self, $u, $p, %p) = @_;
  my $dn = $u;

  my @trees = ($p{TREE}, $self->{DBPARAMS}->[0]);

  print STDERR "SELF=($self), DBPARAMS=$self->{DBPARAMS}->[0], PTREE=$p{TREE}\n";

  if ($dn !~ /[,]/)
  {
    my $auth_tree = $self->{GLOBAL}->{CONFIG}->get("AUTH_TREE");
    my $default_tree = $self->{GLOBAL}->{CONFIG}->get("DEFAULT_TREE");
    unshift @trees, $auth_tree;
    push @trees, $default_tree;
  } else { # Absolute DN, try what is in DN
    my ($basedn) = $dn =~ /ou=People,(.+?)$/;
    my $basedn_tree = $self->{GLOBAL}->{CONFIG}->get_treename_by_basedn($basedn);
    unshift @trees, $basedn_tree;
  }

  foreach my $tree (@trees)
  {
    next unless $tree;
    my $tree_basedn = $self->{GLOBAL}->{CONFIG}->prefix_get([$tree, '_GLOBAL'], "BASEDN");
    next unless $tree_basedn;
    if ($u !~ /[,]/)
    {
      $dn = "uid=$u,ou=People,$tree_basedn";
    }

    print STDERR "TRYING BIND AS $dn, PASS=$p, ON=$tree\n";

    $self->creds($dn, $p, 1);
    print STDERR "CREDS=".Dumper($DMLDAP::CREDS)."\n";
    if ($self->connect($tree, 1))
    {
      # Set connect param
      return ($dn, TREENAME=>$tree);
    }
  }
  return undef;
}


sub macro_value
{
  my ($self, $macro) = @_;

  my ($oc) = $self->get_schema;

  my $value = $self->get($macro); # Default to name of attribute.

  my $super_value = $self->SUPER::macro_value($macro);

  if ($super_value eq $value) # No subst was made yet, might be below
  {
    # Other custom ones below:
    if ($macro eq 'uidNum' or $macro eq 'if_uidNum') # Users
    {
      my $existing = $self->getold("uidNumber");
      if ($macro eq 'if_uidNum' and $existing =~ /^\d+$/)
      # Already set, no need to figure out.
      {
        return $existing;
      }

      my $users = $self->new();
      $users->search_cols(['uidNumber']);
      my $uidNumber_start = $self->{GLOBAL}->{CONFIG}->get("MODULES{user}{UIDNUMBER_START}") || '10000';
      my $next_uidNumber = $uidNumber_start - 1;
      my $uidNumber_end = $self->{GLOBAL}->{CONFIG}->get("MODULES{user}{UIDNUMBER_END}") || '19999';

      for($users->first; $users->more; $users->next)
      {
        my $uidNumber = $users->get("uidNumber");
        if ($uidNumber > $next_uidNumber && $uidNumber <= $uidNumber_end)
	# Skip entry if out of range.
        {
          $next_uidNumber = $uidNumber;
        }
      }

      if ($next_uidNumber > $uidNumber_end)
      {
        $self->system_error("Unable to generate UID Number. None available in configured range.");
      }
      $value = $next_uidNumber+1;
    }
  } else {
    $value = $super_value;
  }
  return $value;
}

sub bulk_set
{
  my ($self, %set) = @_;
  if ($set{userPassword})
  {
    $set{userPassword} = $self->assertPassword($set{userPassword});
  }
  $self->SUPER::set(%set);
}

sub edit_msg_page # Anything to send back after edit to display intermediately.
{
  my ($self, $mode) = @_;

  if (my $p=$self->{USERPASSWORD_RANDOM})
  {
    # Some day also send to IT via email? dunno.
    my $dn = $self->get_dn;

    return
    (
      "password_changed",
      DN=>$dn,
      PASSWORD=>$p,
      NEXT_PAGE=>($mode eq 'Edit' ? $self->get("EDIT_URL") : $self->get("VIEW_URL")),
    );
  }
  return ();
}

1;
