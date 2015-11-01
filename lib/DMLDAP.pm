# DONE GLOBAL
package DMLDAP;

use lib "../MalyCGI";
use base "MalyDBOCore";
use MalyLog;
use CGI::Pretty;
use Data::Dumper;
use DMConfig;
use MalyLog;
use UNIVERSAL;
require Net::LDAP;
use MalyMail;
use File::Basename;
use MalyConf;
use MIME::Base64;
require Net::LDAP::LDIF;
use DMEntry;
use Time::Local;
use POSIX qw(strftime);
use MalyVar;

our $REQUEST_DIR = dirname(dirname(__FILE__)) . "/request";
our $CONF = undef;
our $LDAP = undef;
our @DBPARAMS = (); # Host, user, pass, etc...
our $CREDS = []; # Credentials. Spans all classes
our $MAIL = MalyMail->new();
our $self = {};
our $DEBUG = 0;
our $dmbase = dirname(dirname(__FILE__));
our $etcdir = "$dmbase/etc";

sub new
{
  my ($this, @args) = @_;
  my $class = ref ($this) || $this;

  my $self = $class->SUPER::new(@args);
  $self->{DBPARAMS} = [@DBPARAMS]; # We want a COPY, not a ref, since this will follow us around...
  print STDERR "DBPARAMS=".Dumper($self->{DBPARAMS})."\n";
  return $self;
}

sub init # Saves server related information. NOT USER/PASSWORD!!!!
{
  my ($this, @init_dbparams) = @_;
  if (ref $this) # Saving to instance.
  {
    $this->{DBPARAMS} = \@init_dbparams;
    print STDERR "SETTING LOCAL ($self)=".Dumper($this->{DBPARAMS})."\n";
  } else { # Global/Default
    @DBPARAMS = @init_dbparams;
    print STDERR "SETTING GLOBAL=".join(";", @init_dbparams)."\n";
  }
}

sub creds
{
  my ($self, $dn, $p, $sessioncreds) = @_;
  if ($dn and $p)
  {
    $CREDS = [$dn, password=>$p];
    print STDERR "SESSCREDS=$sessioncreds ($CREDS)\n";
    print STDERR "SET_CREDS=$dn/$p\n";
  }
  return (ref $CREDS eq 'ARRAY' ? @$CREDS : ()) if wantarray;
  return ();
}

sub rebind
{
  my ($self, $u, $p) = @_;
  if (!$u and !$p) # Anonymous.
  {
    $CREDS = [];
    return 1;
  }
  my $dn = $u;
  if ($dn !~ /[,]/) # Logging in as username, assume uid=$u
  {
    $dn = $self->get_dn("uid=$u");
    if (not $dn)
    {
      $self->{ERROR} = "No such user ($u)";
      return undef;
    }
  }
  $self->creds($dn, $p);
  return 1;

}

sub connect_params
{
  my ($self, $treename) = @_;
  $self->system_error("Connection not configured, no hook to configuration module") unless $self->{GLOBAL}->{CONFIG};
  $treename ||= $self->{DBPARAMS}->[0] || $DBPARAMS[0];
  my $host = $self->{GLOBAL}->{CONFIG}->prefix_get([$treename, '_GLOBAL'], "HOST");
  my @tree_keys = $self->{GLOBAL}->{CONFIG}->keys();
  if (not $host)
  {
    $self->system_error("Connection not configured, no tree declared via DMLDAP->init()") unless $treename;
    $self->system_error("Connection not configured, invalid tree") if not $self->{GLOBAL}->{CONFIG}->prefix_get($treename);
    $self->system_error("Connection not configured, no host specified");
  }
  my @params = ( $host, version=> 3, timeout=>10 );
  return @params;
}

sub connect
{
  my ($self, $tree, $authcheck) = @_;
  if ($tree)
  {
    $self->init($tree);
  }
  $tree ||= $self->{DBPARAMS}->[0] || $DBPARAMS[0];
  my @connect_params = $self->connect_params($tree);

  print STDERR "CONNECT PARAMS=".join(", ", @connect_params)."\n";

  my $host = $connect_params[0];

  my $conn = join("/", $host); # Eventually maybe port, too?

  if (!$LDAP->{$conn})
  {
    $LDAP->{$conn} = Net::LDAP->new(@connect_params);
    unless ($LDAP->{$conn})
    {
      $self->{ERROR} = "Can't connect to Directory Server (host=$host).";
      $self->internal_error($self->{ERROR});
    }
  }
  $self->{LDAP} = $LDAP->{$conn};

  # Enable SSL/TLS
  my $ssl_tls = $self->{GLOBAL}->{CONFIG}->get("SSL_VERSION");
  my $verify = $self->{GLOBAL}->{CONFIG}->get("SSL_VERIFY") || "optional";
  my $capath = $self->{GLOBAL}->{CONFIG}->get("SSL_CAPATH");
  my $cafile = $self->{GLOBAL}->{CONFIG}->get("SSL_CAFILE");
  my $clientcert = $self->{GLOBAL}->{CONFIG}->get("SSL_CLIENTCERT");
  my $clientkey = $self->{GLOBAL}->{CONFIG}->get("SSL_CLIENTKEY");

  # TODO, THINK about adding in decryptkey sub() to support encrypted client key files.
  if ($ssl_tls)
  {
    my $msg = $self->{LDAP}->start_tls(sslversion=>$ssl_tls, 
      verify=>$verify, capath=>$capath, cafile=>$cafile, 
      clientcert=>$clientcert, clientkey=>$clientkey);
    if ($msg and my $code = $msg->code && $code > 1)
    {
      $self->{ERROR} = "SSL/TLS error (perhaps OpenLDAP libraries were not compiled with StartTLS?). " . $msg->error;
      $self->internal_error($self->{ERROR});
    }
  }

  # Bind as user (specific per session!!!).
  
  my @credentials = $self->creds;

  print STDERR "ORIGINAL CREDS=".join(";", @credentials)."\n";

  # Only bind if DN is in auth tree or current tree
  my $authtree = $self->{GLOBAL}->{CONFIG}->get("AUTH_TREE");
  my $authdn = $self->{GLOBAL}->{CONFIG}->prefix_get($authtree, "BASEDN");
  my $treedn = $self->{GLOBAL}->{CONFIG}->prefix_get($tree, "BASEDN");

  if ($credentials[0] !~ /($authdn|$treedn)/ or not $authdn or not $treedn)
  {
    @credentials = ();
  }

  my $rc = $self->{LDAP}->bind(@credentials);

  my $msg = $rc ? $rc->error : undef;
  my $code = $rc ? $rc->code : undef;
  print STDERR "MSG=$msg, CODE=$code, TREE=$tree, TREEDN=$treedn, AUTHDN=$authdn, CREDS=".join(",", @credentials)."\n";

  print STDERR "RC=$rc\n";
  if ($rc and $rc->code)
  {
    $self->{ERROR} = "Unable to authenticate. " . $rc->error;
    if (not $authcheck) # Just a check, dont want to error out.
    {
      $self->internal_error($self->{ERROR}, "$self->{GLOBAL}->{URL}?action=Login");
    }
    return undef;
  }

  return 1; # OK.
}

sub END
{
  if (ref $LDAP eq 'HASH')
  {
    foreach my $tree (keys %$LDAP)
    {
      if(ref $LDAP->{$tree})
      {
        $LDAP->{$tree}->unbind(); 
        $LDAP->{$tree}->disconnect();
      }
      delete $LDAP->{$tree};
    }
  }
}

sub generate_ldif
{
  my ($self, $changetype) = @_;
  return $self->get_ldif($changetype);
}

sub insert_ldif
{
  my ($self, $ldif) = @_;
  my $mesg = undef;
  if ($ldif)
  {

  # Should perhaps be worrisome of entry being out-of-sync?
  # GRR!!!

  } elsif ($self->{ENTRY}) {
    $self->connect();
    $self->{ENTRY}->changetype('add');
    $mesg = $self->{ENTRY}->update($self->{LDAP});
    $self->{ERROR} = $mesg->error if $mesg->code;
  }
  $self->post_insert();
  return $mesg if defined wantarray;
}

sub update_ldif # Not sure if this works
{
  my ($self, $ldif) = @_;
  my $mesg = undef;
  if ($ldif)
  {

  } elsif ($self->{ENTRY}) {
    $self->connect();
    #$self->{ENTRY}->changetype('modify');
    $mesg = $self->{ENTRY}->update($self->{LDAP});
    $self->{ERROR} = $mesg->error if $mesg->code;
  }
  $self->post_update();
  return $mesg if defined wantarray;
}

# Cuz we generate ldif text now, and want to update via ldif, we should prolly KEEP entry object... XXX TODO

sub get_valid_attributes
{
  my ($self, $also_template_saves) = @_;
  my ($oc) = $self->get_schema();
  my %header = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"HEADER"});
  my @pseudo_fields = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"PSEUDO_FIELDS"});
  my @template_attrs = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"TEMPLATE_ATTRS"});
  my @no_commit_fields = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"NO_COMMIT_FIELDS"});
  my @attrs = (keys %header, @pseudo_fields, @template_attrs, 'objectClass');
  @attrs = grep { my $attr = $_; not grep { lc($_) eq lc($attr) } @no_commit_fields } @attrs;
  return @attrs;
}

sub get_ldif # From entry to ldif string
{
  my ($self, $changetype) = @_;
  $changetype ||= 'modify';
  my ($oc) = $self->get_schema();
  # Now this means to generate ldap::entry from hash....
  $self->get_pending_changes();
  $self->{ENTRY} = Net::LDAP::Entry->new();
  $self->{ENTRY}->changetype($changetype);
  my $dn = $self->get_dn();
  $self->{ENTRY}->dn($dn);

  my @classes = $self->get("objectClass");
  my @attrs = $self->get_valid_attributes();

  # XXX TODO ISNT GENERATING ABSOLUTELY EVERYTHING, ESP SYNC FIELDS....

  # Now do object classes
  $self->{ENTRY}->replace("objectClass", \@classes);

  # Now do all attributes
  foreach my $attr (@attrs)
  {
    my @values = $self->get($attr);
    next unless @values;
    $self->{ENTRY}->replace($attr, \@values);
  }

  my $tmpname = "/tmp/dmldif".time().".$$";

  $self->{LDIF} = Net::LDAP::LDIF->new($tmpname, 'w', encode=>'base64', onerror=>undef);
  $self->{LDIF}->{change} = ($changetype eq 'modify');
  $self->{LDIF}->write_entry($self->{ENTRY});
  $self->{LDIF}->done();

  # Read file...
  open(LDIF, "<$tmpname") or return undef;
  local $/;
  my $ldif = <LDIF>;
  close(LDIF);

  unlink($tmpname);

  return $ldif;
}

sub set_ldif # From ldif string to entry.
{
# Loading into records from ldap::entry too!
  my ($self, $ldif) = @_;

}

sub get_dn # Either formulate from what we've got, or get from filter.
{
  my ($self, $filter) = @_;
  if ($filter)
  {
    return $self->get_dn_by_filter($filter);
  } else { # Formulate from entry!
    my ($oc) = $self->get_schema;
    my $treename = $self->{DBPARAMS}->[0];
    my $basedn = $self->{GLOBAL}->{CONFIG}->oc_basedn($oc, $treename);
    my $key = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};
    my $val = $self->get($key);
    return "$key=$val,$basedn";
  }
}

sub get_dn_by_filter
{
  my ($self, $filter) = @_;
  my $dn = undef;

  my $rc = $self->connect();
  return $rc unless $rc;

  my %search_opts = $self->search_opts();
  my $mesg = $self->{LDAP}->search(%search_opts, filter=>$filter, scope=>"one", attrs=>['dn']);
  if ($mesg->code)
  {
    $self->internal_error($mesg->error);
  } else {
    my $entry = $mesg->entry(0); 
    $dn = $entry->dn if $entry;
  }
  return $dn;
}

sub generate_filter # AND'ed. 
{
  my ($self, $text_params, %params) = @_;
  return if (not %params and (not ref $text_params or (ref $text_params eq 'ARRAY' and not @$text_params)));
  
  my @filter = ();
  if (ref $text_params eq 'ARRAY')
  {
    my @text_filters = @$text_params;
    foreach my $text_filter (@text_filters)
    {
      next unless $text_filter;
      $text_filter = "($text_filter)" unless $text_filter =~ /^\(.+\)$/;
      push @filter, $text_filter;
    }
  }

  # Now go through hash and make equality checks
  foreach my $key (keys %params)
  {
    push @filter, "($key=$params{$key})";
  }

  my $joint_filter = join("", @filter);
  return "(&".$joint_filter.")" if ($joint_filter and @filter > 1);
  return "$joint_filter" if ($joint_filter and @filter == 1);
}

sub search_cols_nolink
{
  my ($this, $cols, @params) = @_;
  my %params = @params;
  # scope/base, etc... is determined purely by configuration !!!
  my $self = ref $this ? $this : $this->new($this->get_schema);
  my ($oc) = $self->get_schema;

  #if ($self->{GLOBAL}->{CONFIG}->get("SEARCH_COLS"))
  #{
    #$cols = [ $self->filter_columns() ];
  #}

  my ($oc) = $self->get_schema;
  my @attrs = ();
  if (($cols and not ref $cols) or (ref $cols eq 'ARRAY' and @$cols))
  {
    @attrs = (ref $cols eq 'ARRAY' ? @$cols : split("[\s,]+", $cols) );
  }

  # Add implied columns (from LINKS) to list, too!
  my @cols = ();
  my %links = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"LINKS"});
  foreach my $attr (@attrs)
  {
    push @cols, $attr;
    if ($links{$attr})
    {
      my @links_cols = ref $links{$attr}->{SRCKEY} eq 'ARRAY' ?
        @{ $links{$attr}->{SRCKEY} } : ($links{$attr}->{SRCKEY}||());
      push @cols, @links_cols;
    }
  }

  # if we ask for a removing column, we want to track it, but not SEND it to the server
  $self->{ALL_COLUMNS} = [@cols];

  @cols = grep { my $col = $_; not grep { $col eq $_ } keys %links } @cols;
  $self->{COLUMNS} = [@cols];

  push @params, (attrs=>\@cols) if @cols;

  # Get search options.
  my %search_opts = $self->search_opts(%meta, @params); # Will automagiccally get objectClass, base, etc... from config.

  # Do search.
  my @records = ();
  if ($self->connect)
  {

    my $result = $self->{LDAP}->search(%search_opts);
    if ($result and $result->code)
    {
      $self->{ERROR} = $result->error;
      $self->log("CONNECTION: ".join(", ", $self->connect_params)."\n");
      $self->log("BOUND AS: ".join(", ", $self->creds)."\n");
      $self->log("SEARCH_OPTIONS: ".Dumper(\%search_opts)."\n");
      $self->internal_error("Search error: " . $self->{ERROR}." (See error log for details)");
    } elsif ($result) {
      for (my $i = 0; $i < $result->count; $i++)
      {
        my $entry = $result->entry($i);
	# Get hashref for entry.
	my $hashref = {};
	$hashref->{uc "dn"} = $entry->dn;
	foreach my $attr ($entry->attributes)
	{
	  my @values = $entry->get_value($attr);
	  $hashref->{uc $attr} = \@values;
	}
	push @records, $hashref;
      }
    }
  }

  $self->{RECORDS} = scalar @records ? [ map { { ORIGINAL=>{%$_},CHANGES=>{},CURRENT=>{%$_} } } @records ] : undef;

  return $self if defined wantarray;
}

sub search_opts
{
  my ($self, @params) = @_;
  my %meta = ();
  my ($oc) = $self->get_schema;
  my %search_opts = $self->{GLOBAL}->{CONFIG}->get("search_opts"); # Not used?
  my $append_filter = $self->{GLOBAL}->{CLASSES}->{$oc}->{"APPEND_FILTER"};
  my $oc_filter = "objectClass=".($self->{GLOBAL}->{CONFIG}->oc_objectclass($oc) || '*');

  # Convert parameters

  my @text_params = ();
  push @text_params, $append_filter if $append_filter;
  push @text_params, $oc_filter if $oc_filter;
  my %params = ();

  for(my $i = 0; $i < @params; $i++)
  {
    my $first = $params[$i];
    my $second = $params[$i+1];
    if (ref $first eq 'ARRAY')
    {
      push @text_params, @$first;
    } else {
      $params{$first} = $second;
      $i++;
    }
  }

  # TODO HERE....

  my $param_filter = $params{filter};
  push @text_params, $param_filter if $params{filter};
  delete $params{filter};
  $search_opts{attrs} = $params{attrs} if $params{attrs};
  delete $params{attrs};


  $search_opts{filter} = $self->generate_filter(\@text_params, %params);

  # Set basedn if available.
  my $base_dn = $self->{GLOBAL}->{CONFIG}->oc_basedn($oc, $self->{DBPARAMS}->[0]);
  if ($base_dn)
  {
    $search_opts{base} = $base_dn;
  }

  return %search_opts;
}

sub commit
{
  my ($self, @changes) = @_;
  $self->SUPER::commit(@changes);
  #$self->subrec_commit(@changes);
}

#sub subrec_commit { my ($self, @changes) = @_; }

sub get_pending_changes # Incorporate getting proper objectClasses (if changes at all).
{
  # NEEDS TO ALSO SET MACRO SUBSTITUTED VALUES AND SYNC ONES IN RECORD....
  my ($self, $key) = @_;

  my $debug_object_classes = 0; # WHether or not to print error messages regarding object class evaluation....
  # Seems to be a recurring problem.
  


  $key ||= 'CHANGES'; # Can be CURRENT if want to get ENTIRE entry.
  my $record = $self->internal_rec;
  my %raw_changes = %{$record->{CHANGES}} if (ref $record->{CHANGES});

  my %changes = ();
  foreach my $key (keys %raw_changes)
  {
    my $raw_value = $raw_changes{$key};
    if ($raw_value eq 'ARRAY' and @$raw_value == 1)
    {
      $changes{$key} = $raw_value->[0];
    } else {
      $changes{$key} = $raw_value;
    }
  }

  # NOW, put objectClasses in list of changes, if anything 

  my %replace = ();
  my @delete = ();

  my $new_rdn = undef;

  my ($oc) = $self->get_schema;
  my %header = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"HEADER"});
  my $prikey = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"});
  my @pseudo_fields = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"PSEUDO_FIELDS"});
  my @no_commit_fields = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"NO_COMMIT_FIELDS"});

  my @approved_attrs = $self->get_valid_attributes();

  foreach my $key (@approved_attrs) # Also need to include pseudo fields.
  {
    next unless grep { /^$key$/i } (keys %changes); # Ignore unless in form, mentioned.
    my @new_value = $self->getnew($key);
    @new_value = () if (@new_value > 0 and not grep { $_ ne '' } @new_value); # Just empty ones. Pretend like nothing there.
    my @old_value = $self->getold($key);
    my $delete_key_value = $delete_key ? $self->getnew($delete_key) : undef;

    # Seems to erase old value somehow...

    if ( (@new_value == 0 and @old_value > 0) or $delete_key_value) # Remove if existing record, and submitted a blank value.
    {
      push @delete, $key;
    } else {
      if (@old_value != @new_value or grep { $old_value[$_] ne $new_value[$_] } (0..$#old_value))
      { # Otherwise, identical! Skip.
	if ($key eq $prikey)
	{
	  my @subst_value = map { $self->macro_map($_) } @new_value;
	  $new_rdn = "$prikey=$subst_value[0]";
	  if ($self->is_new)
	  {
	    $replace{uc $key} = $subst_value[0];
	    $self->set_unchecked(uc $key, $subst_value[0]);
	  }
	} else {
          # Check macro map.
	  my @subst_value = map { $self->macro_map($_) } @new_value;
	  if (@subst_value > 1)
  	  {
            $replace{uc $key} = \@subst_value;
  	    $self->set_unchecked(uc $key, \@subst_value);
  	  } else {
            $replace{uc $key} = $subst_value[0];
    	    $self->set_unchecked(uc $key, $subst_value[0]);
	  }
	}

      }
    }
  }

  # We need to take into consideration having accurate OC's before ->sync(),
  # But removal of respective attrs must come LATER, as may add attrs
  # in between (from ->sync)!

  my @removed_attrs = ();

  my $entry_type = $self->get("entry_type");

  if ($self->{GLOBAL}->{CONFIG}->has_admin_access) 
  {
    my $object_classes = $self->{GLOBAL}->{CLASSES}->{$oc}->{"CLASSES"};
    my @object_classes = ref $object_classes eq 'ARRAY' ? @$object_classes : ();
    my @set_object_classes = ref $replace{OBJECTCLASS} eq 'ARRAY' ? @{$replace{OBJECTCLASS}} : ();
    @set_object_classes = ($replace{OBJECTCLASS}) if $replace{OBJECTCLASS} ne '';
    push @object_classes, @set_object_classes;

    my @remove_object_classes = ();

    my %entry_types = $self->{GLOBAL}->{CONFIG}->get_enabled_entry_types($oc);



    my @type_classes = ref $entry_types{$entry_type}->{CLASSES} eq 'ARRAY' ?
      @{ $entry_types{$entry_type}->{CLASSES} } : ();

    my $object_classes_if = $self->{GLOBAL}->{CLASSES}->{$oc}->{"OPTIONAL_CLASSES"};
    my %object_classes_if = ref $object_classes_if eq 'HASH' ? %$object_classes_if : ();

    print STDERR "ENTRY_TYPES=".Dumper(\%entry_types).", ET=$entry_type, TYPE_CLASSES=".Dumper(@type_classes)."\n" if $debug_object_classes;

    if (not keys %entry_types or not $entry_type or not @type_classes) 
    # Just base upon class conditionals...
    {
      # ACTUALLY DISABLE! CUZ WE DONT DO THIS ANYMORE....
#  
#      my $class_ref = $self->{GLOBAL}->{CLASSES}->{$oc};
#      my $conf = $self->{GLOBAL}->{CONFIG}->get();
#      my $vars = {CONF=>$conf, CLASS=>$class_ref};
#      foreach my $oci (keys %object_classes_if)
#      {
#        my $eval = $object_classes_if{$oci}->{EVAL};
#	next unless $eval; # Skip if no evaluation defined
#        my $oc_attrs = $object_classes_if{$oci}->{ATTRS};
#        my $ec = MalyVar->evaluate_content($eval, $vars);
#        my $ev = eval $ec;
#        if ($eval and not $ev)
#        {
#          push @remove_object_classes, $oci;
#  	  # Now remove attributes related.... ONLY IF WE HAVE THEM!
#  	  my @oc_attrs = ref $oc_attrs eq 'ARRAY' ? @{ $oc_attrs } : ();
#	  push @removed_attrs, @oc_attrs;
#        } else {
#          push @object_classes, $oci;
#        }
#        # Should implicitly remove invalid ones!
#      }
  
    } else { # Base oc's upon entry type selected.

      my @all_classes = (@object_classes, keys %object_classes_if);

      print STDERR "ALL OBJECT_CLASSES ARE=".join("; ", @all_object_classes)."\n" if $debug_object_classes;


      # FYI, should remove samba stuff here....

      foreach my $class (@all_classes)
      {

        if (not grep { $class eq $_ } @type_classes) # Remove.
	{
          push @remove_object_classes, $class;
	  # Remove attributes related....
	  print STDERR "REMOVING OC=$class AND ATTRS\n" if $debug_object_classes;
          my $oc_attrs = $object_classes_if{$class}->{ATTRS};
  	  my @oc_attrs = ref $oc_attrs eq 'ARRAY' ? @{ $oc_attrs } : ();
	  push @removed_attrs, @oc_attrs;
	} else {
          push @object_classes, $class;
	}
      }
    }

    print STDERR "OBJECT_CLASSES POSSIBLE ARE=".join("; ", @object_classes)."\n" if $debug_object_classes;
    print STDERR "OBJECT_CLASSES REMOVING ARE=".join("; ", @remove_object_classes)."\n" if $debug_object_classes;
    print STDERR "ATTRIBUTES REMOVING ARE=".join("; ", @removed_attrs)."\n" if $debug_object_classes;

    if (not @object_classes)
    {
      $self->internal_error("Unable to generate object classes.");
    }

    my @current_object_classes = $self->getold("objectClass");
    my @previous_object_classes = $self->getold("objectClass");

    print STDERR "CURRENT OBJECT_CLASSES ARE=".join("; ", @current_object_classes)."\n" if $debug_object_classes;
    print STDERR "PREVIOUS OBJECT_CLASSES ARE=".join("; ", @previous_object_classes)."\n" if $debug_object_classes;


    foreach my $class (@object_classes)
    {
      if (not grep { uc($class) eq uc($_) } @current_object_classes)
      {
        push @current_object_classes, $class;
      }
    }

    print STDERR "NEW CURRENT OBJECT_CLASSES (after figuring possible) ARE=".join("; ", @current_object_classes)."\n" if $debug_object_classes;

    my @keep_object_classes = ();

    foreach my $coc (@current_object_classes)
    {
      push @keep_object_classes, $coc unless grep { uc($coc) eq uc($_) } @keep_object_classes or grep { uc($coc) eq uc($_) } @remove_object_classes;
    }

    print STDERR "KEEPING OBJECT_CLASSES ARE=".join("; ", @keep_object_classes)."\n" if $debug_object_classes;

    my %differ = ();
    map { $differ{uc $_}--; } @previous_object_classes;
    map { $differ{uc $_}++; } @keep_object_classes;

    if (grep { $differ{$_} != 0 } keys %differ)
    {
      $replace{OBJECTCLASS} = \@keep_object_classes;
      print STDERR "REPLACING OBJECT_CLASSES\n";
      $self->set_unchecked(uc("objectClass"), \@keep_object_classes);
    }
  } else { # Some other person. Don't let attributes of an OC enabled NOW, but not BEFORE get through.
    # FIXME TODO XXX HERE, INCLUDING CONDITION....
    # I.e. when samba just enabled, but admin hasnt gone to account.
    my @current_object_classes = $self->getold("objectClass");
    my $object_classes_if = $self->{GLOBAL}->{CLASSES}->{$oc}->{"OPTIONAL_CLASSES"};
    my %object_classes_if = ref $object_classes_if eq 'HASH' ? %$object_classes_if : ();
    my $class_ref = $self->{GLOBAL}->{CLASSES}->{$oc};
    my $conf = $self->{GLOBAL}->{CONFIG}->get();
    my $vars = {CONF=>$conf, CLASS=>$class_ref};

    # NEED TO FIX, CUZ NO MORE EVAL XXX TODO FIXME
    # may allow in general, but dont count on it.

    # if found an optional object class with an eval, 
    #
    # must go through all object 

    foreach my $oci (keys %object_classes_if)
    {
      my $eval = $object_classes_if{$oci}->{EVAL};
      my $oc_attrs = $object_classes_if{$oci}->{ATTRS};
      my $ec = MalyVar->evaluate_content($eval, $vars);
      my $ev = eval $ec;
      if (not $ev and not grep { /^$oci$/i } @current_object_classes) 
      # Class just now enabled.
      # OR, cleaning up irrelevent stuff to entry (i.e. samba attrs when not kind)
      {
	# Remove attributes related.... Since not privileged to add OC!
	my @oc_attrs = ref $oc_attrs eq 'ARRAY' ? @{ $oc_attrs } : ();
	map { delete $replace{uc $_}; $self->set_unchecked($_, undef); } @oc_attrs;
      }
    }
  }



  # Sync stuff
  my %sync = $self->sync(%replace);
  %sync = map { (uc($_), $sync{$_}) } grep {my $key=$_; grep { uc($key) eq uc($_) } @approved_attrs } keys %sync;
  # Get rid of crap stuff, i.e. form junk.
  $self->set_unchecked(%sync);
  %replace = (%replace, %sync) if %sync;

  my @keep_object_classes = ();

  foreach my $oc_attr (@removed_attrs)
  {
    if ($self->getold($oc_attr) ne '') # Only if already in DB.
    {
      push @delete, uc $oc_attr if not grep { uc($_) eq uc($oc_attr) } @delete;
    } else {
    }
    delete $replace{uc $oc_attr};
    $self->set_unchecked($oc_attr, undef);
    print STDERR "REMOVING ATTR=$oc_attr\n" if $debug_object_classes;
  }



  return \%replace, \@delete, $new_rdn if defined wantarray;
}

sub get
{
  my ($self, @args) = @_;
  my @values = ();
  foreach my $arg (@args)
  {
    my @argvals = $self->SUPER::get($arg);
    # Do macro translation
    my @xargvals = map { $self->macro_map($_) } @argvals;
    # Not sure if this is needed, but its causing infinite loops!
    # If asked for more than one thing, MUST return arrayref!
    push @values, (@args > 1 ? \@xargvals : @xargvals);
  }
  return @values if wantarray;
  return $values[0] if defined wantarray;
}

sub set_sync
# Stuff that IS NOT filtered for appropriateness, so we better be sure!
{
  my ($self, %hash) = @_;
  %hash = $self->sync(%hash);
  return %hash;
}  

sub sync { my ($self, %h) = @_; return (%h); }  # Stuff that IS NOT filtered for appropriateness, so we better be sure!
# Should pass hash through anyway.
# We don't know certain info like uid necessarily until this call, thus why we separate certain things to here.

sub check_required_fields # As determined by configuration.
{
  my ($self) = @_;

  my ($oc) = $self->get_schema;
  my $treename = $self->{DBPARAMS}->[0];
  my %header = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"HEADER"});

  #if($self->{GLOBAL}->{CONFIG}->has_admin_access) # No need otherwise. 
  # Well, we really only want to complain if it was changed to (or always was) a blank.
  {
    my @tree_required_attrs = $self->{GLOBAL}->{CONFIG}->get("MODULES{$oc}{REQUIRED}");
    my @required_attrs = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"REQUIRED"});
    push @required_attrs, @tree_required_attrs;

    my @all_columns = $self->filter_columns();

    my $entry_type = $self->get("entry_type");

    my %entry_types = $self->{GLOBAL}->{CONFIG}->get_enabled_entry_types($oc);
    my %optional_classes = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"OPTIONAL_CLASSES"});

    my @entry_type_classes = ref $entry_types{$entry_type}->{CLASSES} eq 'ARRAY' ?
      @{ $entry_types{$entry_type}->{CLASSES} } : ();

    my @disabled_entry_type_classes = grep { my $optc=$_; not grep { $optc eq $_ } @entry_type_classes } keys %optional_classes;

    my @disabled_entry_type_columns = ();

    foreach my $entry_type_class (@disabled_entry_type_classes)
    {
      my @class_columns = ref $optional_classes{$entry_type_class}->{ATTRS} eq 'ARRAY'
        ? @{ $optional_classes{$entry_type_class}->{ATTRS} } : ();
      push @disabled_entry_type_columns, @class_columns;
    }

    foreach my $attr (@required_attrs) # Only care for what one can edit...
    {
      # Skip ones not allowed to edit.
      next unless grep { $attr eq $_ } @all_columns;

      # Skip if for some other entry type we don't have set.
      next if scalar @disabled_entry_type_columns and 
        grep { $attr eq $_ } @disabled_entry_type_columns;

      $self->user_error("Value required for '" . $header{$attr} . "'") unless $self->get($attr) ne '';
    }
  }
}

sub update
{
  my ($self, @set) = @_; # Make sure CHANGES as we get them are an ARRAY REF....
  $self->set(@set) if scalar @set;

  $self->check_required_fields();

  my ($replace, $delete, $new_rdn) = $self->get_pending_changes;
  my $dn = $self->get("dn");

  $self->connect();

  if (ref $replace or ref $delete)
  {
    my $mesg = $self->{LDAP}->modify($dn, delete=>$delete, replace=>$replace);
    if ($mesg->code)
    {
      print STDERR "Edit Error for '$dn'. Replace values=".Dumper($replace)."\n";
      $self->internal_error("Edit Error (Please see Apache error log for details): " . $mesg->error);
    }
  }
  # Check modified DN...
  if ($new_rdn)
  {
    my $mesg = $self->{LDAP}->moddn($dn, newrdn=>$new_rdn, deleteoldrdn=>1);
    $self->internal_error("ModDN Error: " . $mesg->error) if ($mesg->code);
  }

  # Do deletes.


  $self->post_update();
  return $self if defined wantarray;
}

sub insert # May just be able to wrap, pretend like same.
{
  my ($self, @set) = @_;
  $self->set(@set);
  my ($oc) = $self->get_schema;
  my $base_dn = $self->{GLOBAL}->{CONFIG}->oc_basedn($oc, $self->{DBPARAMS}->[0]);
  my $prikey = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};


  $self->check_required_fields();

  my ($replace, $delete, $new_rdn) = $self->get_pending_changes;
  $self->{GLOBAL}->{LOGGER}->debug("REPLACE=".Dumper($replace).", DELETE=".Dumper($delete).", NEW_RDN=".Dumper($new_rdn));
  my $prival = $self->get($prikey);
  $self->user_error("Illegal name '$prival'. Only numbers, letters and spaces allowed.")
    if ($prival =~ /[^0-9A-Za-z ]/);
  my $dn = "$prikey=$prival,$base_dn";
  $self->internal_error("Unable to generate Distinguished Name, '$prikey=$prival,$base_dn'") unless ($prikey and $prival and $base_dn);

  if (ref $replace eq 'HASH')
  {
    $self->connect();
    my $mesg = $self->{LDAP}->add($dn, attrs=>[%$replace]);
    if ($mesg->code)
    {
      $self->internal_error("Add Error: " . $mesg->error);
    }
  } else {
    $self->internal_error("Unable to generate entry. No data available.");
  }
  $self->post_insert();
  return $self if defined wantarray;
}

sub import
{
  my ($self, %hash) = @_;
  $self->set(%hash);
}

sub should_insert
{
  my ($self) = @_;
  my $dn = $self->get("DN");
  return !$dn;
}

sub key_name
{
  my ($self) = @_;
  my ($oc) = $self->get_schema;
  my $prikey = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};
}

sub report_vars
{
  my ($self, $changes_only) = @_;

  # Make sure to keep DN and entry type.
  my %hash = $self->uc_smart_hash;
  $hash{MODIFYTIMESTAMP} = $hash{MODIFY_TIMESTAMP_HR};
  $hash{CREATETIMESTAMP} = $hash{CREATE_TIMESTAMP_HR};

  return %hash;
}

sub post_insert {;}
sub post_update {;}

sub new_rdn
{
  my ($self, $prival) = @_;
  my ($oc) = $self->get_schema;
  my $current_dn = $self->get("dn");
  return undef unless $current_dn;
  my $prikey = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};
  my ($current_rdn) = $current_dn =~ /^($prikey=.*?)[,]/;

  #my $prival = $self->getnew($prikey);
  my $new_rdn = "$prikey=$prival";

  return $new_rdn if ($new_rdn ne $current_rdn);
  return undef;
}

sub generate_dn
{
  my ($self) = @_;

}

sub delete
{
  my ($self) = @_;
  my $dn = $self->get("dn") or $self->internal_error("Delete Error: Cannot get Distinguished Name");
  if ($self->connect)
  {
    my $rc = $self->{LDAP}->delete($dn);
    if ($rc and $rc->code)
    {
      $self->{ERROR} = $rc->error;
      $self->internal_error("Delete Error: " . $self->{ERROR});
      return undef;
    }
  }
  return 1;
}

sub unique_filter
{
  my ($self) = @_;
  my ($oc) = $self->get_schema;

  my $prikey = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};
  my $prival = $self->get($prikey);
  return "$prikey=$prival";
}

sub filter_columns
{
  my ($self, $mode) = @_;
  $mode ||= lc $self->{GLOBAL}->{MODE};
  my ($oc) = $self->get_schema;
  my @section_names = $self->filter_sections($mode, 1);
  # Skip section evaluation, as may have attributes we need to clean up
  my $sections = $self->{GLOBAL}->{CLASSES}->{$oc}->{"SECTIONS"};
  my $prikey = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};
  my $dispkey = $self->{GLOBAL}->{CLASSES}->{$oc}->{"HEADER_KEY"};
  my $pseudo_fields = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PSEUDO_FIELDS"};
  my @columns = ($prikey, $dispkey, 'objectClass', (ref $pseudo_fields eq 'ARRAY' ? @$pseudo_fields:()));
  my $links = $self->{GLOBAL}->{CLASSES}->{$oc}->{"LINKS"};
  
  return () unless ref $sections eq 'ARRAY';

  foreach my $section (@$sections)
  {
    next unless grep { $section->{ABBREV} eq $_ } @section_names;
    my @sec_cols = ref $section->{COLUMNS} eq 'ARRAY' ? @{ $section->{COLUMNS} } : ();

    # If any of the columns are fake (i.e. LINKS), we need to get them REALLY
    # from link->{SRCKEY}
    foreach my $col (@sec_cols)
    {
      next unless $col;  # Placeholder
      push @columns, $col;
      if($links->{$col}) # subrec, get srckey
      {
        push @columns, ref $links->{$col}->{SRCKEY} eq 'ARRAY' ? 
	  @{ $links->{$col}->{SRCKEY} } : $links->{$col}->{SRCKEY};
      }
    }
  }
  return @columns;
}

sub filter_sections # Gets sections you can see.
{
  my ($self, $mode, $skip_eval) = @_;

  $mode ||= lc $self->{GLOBAL}->{MODE};
  my ($oc) = $self->get_schema;
  my $tree = $self->{DBPARAMS}->[0];
  #my $oc = $self->{GLOBAL}->{OC};
  my $dn_me = $self->{GLOBAL}->{DN_ME}; # SHOULD HAVE NO MATTER WHAT, BUT DONT HAVE {DN} IF NO RECORD!

  $mode = 'search' if $mode eq 'browse'; # Same thing! 
  $mode = 'edit' if $mode eq 'add'; # Same thing! 
  my ($mode_key) = $mode =~ /^(\w)/;
  $mode_key = uc $mode_key;

  #return () unless $mode eq 'edit' or $mode eq 'view'; # Only applies in these cases.
  return () unless $tree;

  # Go through each section for the class

  my $sections = $self->{GLOBAL}->{CLASSES}->{$oc}->{"SECTIONS"};
  return () unless ref $sections eq 'ARRAY';
  my @enabled_sections = ();

  # XXX TODO KEEP SEARCH AS SEPARATE, NOT A SECTION!!!!!
  my $conf = $self->{GLOBAL}->{CONFIG}->get();
  my %conf = ref $conf eq 'HASH' ? %$conf : ();
  my $class = $self->{GLOBAL}->{CLASSES}->{$oc};

  foreach my $section (@$sections)
  {
    my @list = ();
    if ($mode eq 'edit')
    {
      @list = ref $section->{WRITE} eq 'ARRAY' ? @{ $section->{WRITE} } : ();
    } elsif ($mode eq 'view' or $mode eq 'search') {
      @list = ref $section->{READ} eq 'ARRAY' ? @{ $section->{READ} } : ("ADMIN", "REQUESTOR", "MODERATOR", "SELF", "ALL");
    }
    # Is list of who has access: ADMIN, REQUESTOR, MODERATOR, SELF, ALL

    next unless (
      (grep { $_ eq 'ADMIN' } @list and $self->{GLOBAL}->{CONFIG}->has_admin_access($oc)) or
      (grep { $_ eq 'REQUESTOR' } @list and $self->{GLOBAL}->{CONFIG}->has_request_access($oc)) or
      (grep { $_ eq 'MODERATOR' } @list and $self->{GLOBAL}->{CONFIG}->has_moderator_access($oc)) or
      (grep { $_ eq 'SELF' } @list and $self->get_dn eq $self->{GLOBAL}->{DN_ME}) or
      (grep { $_ eq 'ALL' } @list)
      );

    my %entry_types = $self->{GLOBAL}->{CONFIG}->get_enabled_entry_types($oc);
    my $entry_type = $self->get("ENTRY_TYPE");
    my @entry_type_sections = ref $entry_types{$entry_type}->{SECTIONS} eq 'ARRAY' ?
      @{ $entry_types{$entry_type}->{SECTIONS} } : ();

    next if ($mode eq 'view' and @entry_type_sections and 
      not grep { $section->{ABBREV} eq $_ } @entry_type_sections and $section->{ABBREV} ne 'tracking');
    # Don't load extra ones if only view mode...

    if ($section->{EVAL} and not $skip_eval)
    {
      my $rc = MalyVar->evaluate_content($section->{EVAL}, {CONF=>$conf, CLASS=>$class});
      my $er = eval $rc;
      next unless $er;
    }
    
    push @enabled_sections, $section->{ABBREV};
  }
  return @enabled_sections;
}

sub filter_columns_old
{
  my $self = shift;
  my $mode = lc $self->{GLOBAL}->{MODE};
  my ($oc) = $self->get_schema;
  #my $oc = $self->{GLOBAL}->{OC};
  my $dn_me = $self->{GLOBAL}->{DN_ME}; # SHOULD HAVE NO MATTER WHAT, BUT DONT HAVE {DN} IF NO RECORD!

  $mode = 'search' if $mode eq 'browse'; # Same thing! 
  $mode = 'edit' if $mode eq 'add'; # Same thing! 
  my ($mode_key) = $mode =~ /^(\w)/;
  $mode_key = uc $mode_key;

  my @admins = $self->{GLOBAL}->{CONFIG}->get("ADMINS");
  my @requestors = $self->{GLOBAL}->{CONFIG}->get("REQUESTORS");

  my @out_keys = ();

  my $mode_keys = $self->{GLOBAL}->{CLASSES}->{$oc}->{uc $mode};
  my @mode_keys = ref $mode_keys eq 'ARRAY' ? @$mode_keys : ();

  # Check admin only. If admin, use this list instead (may overlap with above list)

  my @admin_mode_keys = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"ADMIN_" . uc($mode) });

  @admin_mode_keys = @mode_keys unless @admin_mode_keys;

  my @requestor_mode_keys = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"REQUESTOR_" . uc($mode) });

  if (grep { $dn_me && $dn_me =~ /$_/ } @admins)
  {
    if ($mode eq 'view') # Get rid of empty fields.
    {
      return grep { $self->get($_) ne ''; } @admin_mode_keys;
    } else {
      return @admin_mode_keys;
    }
  } elsif (grep { $dn_me && $dn_me =~ /$_/ } @requestors and $mode eq 'edit') {
    return @requestor_mode_keys;
  } else {
    if ($mode eq 'view') # Get rid of empty fields.
    {
      return grep { $self->get($_) ne ''; } @mode_keys;
    } else {
      return @mode_keys;
    }
  }

}

sub db2cgi
{
  my ($self) = @_;
  my ($oc) = $self->get_schema();
  my $tree = $self->{DBPARAMS}->[0];
  my $pri_key = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};

  my %links = $self->get_implicit_links();

  return
  (
    %links,
    ENTRY_TYPE=>[ sub { $self->entry_type(); } ],
    ENABLED_SECTIONS=>[ sub { [ $self->filter_sections(@_) ] } ],
    VIEW_URL=>"cgi-bin/View.pl/$tree/$oc/$pri_key=#$pri_key#",
    EDIT_URL=>"cgi-bin/Edit.pl/$tree/$oc/$pri_key=#$pri_key#",
    HAS_EDIT_ACCESS=>[ sub { $self->has_edit_access } ],
    MODIFY_TIMESTAMP_HR=>[ sub { $self->human_readable_date(@_) }, '#MODIFYTIMESTAMP#' ],
    CREATE_TIMESTAMP_HR=>[ sub { $self->human_readable_date(@_) }, '#CREATETIMESTAMP#' ],
  );
}

sub human_readable_date
{
  my ($self, $date) = @_;
  return undef unless $date;
  my ($y, $mon, $d, $h, $m, $s, $z) = $date =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(.*)/; 
  if ($z eq 'Z') # UTC, convert to local!
  {
    my $time = Time::Local::timegm($s, $m, $h, $d, $mon-1, $y);
    ($s, $m, $h, $d, $mon, $y) = localtime($time);
    return strftime("%m/%d/%Y %H:%M:%S %Z", localtime($time));
    #return sprintf '%02u/%02u/%4u %02u:%02u:%02u %s', $mon, $d, $y+1900, $h, $m, $s, $localz;
  } else {
    return sprintf '%02u/%02u/%4u %02u:%02u:%02u %s', $mon, $d, $y, $h, $m, $s, $z;
  }
}

sub entry_type
{
  my ($self) = @_;
  my $oc = $self->get_oc;
  my %types = $self->{GLOBAL}->{CONFIG}->get_enabled_entry_types($oc);
  my @types = keys %types;
  return undef unless @types;

  # Find the one with the most number of classes matching. Note that all in config must be in self

  my @set_classes = $self->get("objectClass");

  my %types_matched = ();

  foreach my $type (@types)
  {
    my @type_classes = ref $types{$type}->{CLASSES} eq 'ARRAY' ? @{ $types{$type}->{CLASSES} } : ();
    next unless @type_classes;

    next if (grep { my $c=$_; not grep { $c eq $_ } @set_classes } @type_classes);
    # Entry is missing class mentioned in type config.

    # We've found an entry that has all the requirements of the entry type.
    # But, there may be a more appropriate entry type, i.e. that has more classes.
    # Do some tallying to see if it's the BEST entry type.

    $types_matched{$type} = scalar(@type_classes);
  }

  my @best_types = reverse sort { $types_matched{$a} <=> $types_matched{$b} } keys %types_matched;

  my $best_type = $best_types[0];
}

sub has_edit_access
{
  my ($self) = @_;
  my $admin = $self->{GLOBAL}->{CONFIG}->has_admin_access;
  my $is_me = $self->is($self->{GLOBAL}->{DN_ME});
  my ($oc) = $self->get_schema();
  my $treename = $self->{DBPARAMS}->[0];
  my $moderator = $self->{GLOBAL}->{CONFIG}->has_moderator_access($oc);
  my $edit = !$self->is_new;
  return $edit && ($admin || $is_me || $moderator);
}

sub is # Compares DN's.
{
  my ($self, $other) = @_;
  # Check object
  my $other_dn = undef;
  if (UNIVERSAL::isa($other, "UNIVERSAL") and $other->can("get_dn"))
  {
    $other_dn = $other->get_dn();
  }
  elsif (ref $other eq 'HASH')
  {
    $other_dn = $other->{dn} || $other->{DN};
  } 
  elsif (not ref $other)
  {
    $other_dn = $other;
  }

  my $my_dn = $self->get_dn();
  return ($other_dn eq $my_dn);
}

sub macro_map
{
  my ($self, @values) = @_;
  my @new_values = ();
  foreach my $value (@values)
  {
    my %macro_names = ();
    while ($value =~ /\$[{]([a-zA-Z_]+)[}]/g)
    {
      my $macro = $1;
      $self->internal_error("Macro reference loop. A macro referenced another macro, referencing itself, again.") if ($macro_names{$macro}++);
      my $macro_value = $self->macro_value($macro) || $self->get($macro);
      $value =~ s/\$[{]$macro[}]/$macro_value/g;
    }
    push @new_values, $value;
  }
  return @new_values if wantarray;
  return $new_values[0];
}

sub bulk_set
{
  my ($self, @set) = @_;
  $self->SUPER::set(@set);
}

sub macro_value { my ($self, $macro) = @_; return $self->get($macro); }

sub col_in
{
  my ($self, $col, @values) = @_;
  my @filter = map { "($col=$_)" } @values;
  my $filter = join("", @filter);
  $filter = "(|$filter)" if @filter > 1;
  return [$filter];
}

sub request_submit
{
  my ($self, $requestor, %hash) = @_;
  $self->set(%hash) if %hash;
  my ($oc) = $self->get_schema;
  my $treename = $self->{DBPARAMS}->[0];
  $self->directory_assert("$REQUEST_DIR/$treename/$oc");
  my $filename = $self->request_filename(1);

  my %hash = $self->hash;

  open(FILE, ">$filename") or $self->system_error("Unable to write to file '$filename'. Check directory permissions.");

  # So even if requestor, dont lose stuff they couldnt edit (UNIX stuff)
  my %header = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"HEADER"});
  my @pseudo_fields = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"PSEUDO_FIELDS"});
  my @template_keys = keys %header, @pseudo_fields;

  foreach my $key (@template_keys)
  {
    my $value = $hash{uc $key};
    if (ref $value eq 'ARRAY')
    {
      foreach my $eachval (@$value)
      {
        $content .= "$key=$eachval\n" if $eachval ne '';
      }
    } else {
      $content .= "$key=$value\n" if $value ne '';
    }
  }

  print FILE $content;
  close(FILE);

  my @to = 
    $self->{GLOBAL}->{CONFIG}->get("MODULES{$oc}{REQUEST_RECIP}") ||
    $self->{GLOBAL}->{CONFIG}->get("REQUEST_RECIP");
  my $from = 
    $self->{GLOBAL}->{CONFIG}->get("MODULES{$oc}{REQUEST_FROM}") ||
    $self->{GLOBAL}->{CONFIG}->get("REQUEST_FROM");

  map {
    $MAIL->sendmail_text(
    {
      From=>$from,
      To=>$_,
      Subject=>"New DirectoryManager Entry Request From $requestor",
    },
    "The following entry request has been added, accessible at:

$self->{GLOBAL}->{COMPLETE_HTML_BASE_PATH}/cgi-bin/Request.pl/$treename/$oc?action=Login

Here's what was submitted:

$content

Sincerely,
DirectoryManager Server
",
    )
  } @to;
}

sub request_load
{
  my ($self, @filenames) = @_; # Merge of one or more filenames, with the latter preceeding the former
  my ($tree) = $self->{DBPARAMS}->[0];
  my ($oc) = $self->get_schema;
  my $found = 0;
  foreach my $filename (@filenames)
  {
    $filename = "$REQUEST_DIR/$tree/$oc/$filename" unless $filename =~ m{/};
    next unless $filename and -f $filename; # Skip non-existent files and empty filenames.
    $found++;
    open(FILE, "<$filename") or $self->system_error("Unable to load file '$filename'. Check read permissions.");
    #my %hash = map { chomp; (split(/=/, $_, 2)) } <FILE>;
    # Need to generate hash of array refs..... i.e., for multiple emails.
    foreach my $line (<FILE>)
    {
      chomp $line;
      my ($attr, $value) = split(/=/, $line, 2);
      if (ref $hash{$attr} eq 'ARRAY')
      {
        push @{ $hash{$attr} }, $value;
      } else {
        $hash{$attr} = [ $value ];
      }
    }
    $self->set(%hash);
    close(FILE);
  }
  return $found;
}

sub request_complete
{
  my ($self) = @_;
  my $file = $self->request_filename(1);
  if (-e $file)# and $file !~ /_Default_Template[.]dmr$/)  # Else, be silent.
  {
    unlink($file) or $self->system_error("Unable to remove entry request '$file'. Check directory/file permissions.");
  }
}

sub request_filename
{
  my ($self, $abs) = @_;
  my ($oc) = $self->get_schema;
  my $treename = $self->{DBPARAMS}->[0];
  my $key = $self->{GLOBAL}->{CLASSES}->{$oc}->{"HEADER_KEY"};
  my $value = $self->get(lc $key);
  my @parts = split(/\s+/, $value);
  $self->user_error("Unable to generate filename, no value for '$key'") unless @parts;
  $self->directory_assert("$REQUEST_DIR/$treename/$oc", 1);
  my $filename = "$treename/$oc/" . join("_", @parts).".dmr";
  if ($abs)
  {
    return "$REQUEST_DIR/$filename";
  } else {
    return $filename;
  }
}

sub directory_assert
{
  my ($self, $dir, $fail_ok) = @_;
  my @dirs = split("/", $dir);
  for(my $i = 0; $i < @dirs; $i++)
  {
    my $subdir = join("/", @dirs[0..$i]);
    if (! -d $subdir)
    {
      if (not mkdir($subdir, 0755))
      {
        return if $fail_ok;
        $self->system_error("Unable to create directory '$subdir': $!");
      }
    }
  }
}

sub get_requests
{
  my ($self, $filter, $content_also) = @_;
  my ($oc) = $self->get_schema;
  my $treename = $self->{DBPARAMS}->[0];
  $self->directory_assert("$REQUEST_DIR/$treename/$oc", 1);
  opendir(DIR, "$REQUEST_DIR/$treename/$oc") or $self->system_error("Unable to open request directory '$REQUEST_DIR/$treename/$oc'. Check permissions.");
  my @files = grep { /^.+[.]dmr$/ } readdir(DIR);
  if ($filter)
  {
    @files = grep { /^$filter$/ } @files;
  }
  closedir(DIR);
  my %requests = ();
  foreach my $file (@files)
  {
    my $value = $file;
    $value =~ s/[.]dmr$//;
    $value =~ s/_/ /g;
    if ($content_also)
    {
      my %req = ();
      open(REQ, "<$REQUEST_DIR/$treename/$oc/$file") or $self->system_error("Unable to open request '$REQUEST_DIR/$treename/$oc/$file'");
      foreach my $line (<REQ>)
      {
        my ($attr, $value) = split('=', $line, 2);
	if (ref $req{$attr} eq 'ARRAY')
	{
	  push @{ $req{$attr} }, $value;
	} else {
	  $req{$attr} = [ $value ];
	}
      }
      $requests{$file} = \%req;
      close(REQ);
    } else {
      $requests{$file} = $value;
    }
  }
  return %requests;
}

sub template_names
{
  my ($self) = @_;
  my ($oc) = $self->get_schema;
  my @templates = $self->{GLOBAL}->{CONFIG}->get("MODULES{$oc}{TEMPLATES}");
  my $i = 0; my @template_names = grep { $i++ % 2 == 0 } @templates;
  return @template_names;
}

# XXX When saving a template, how do we specify it should be global?
# Maybe we just need to have a new section for template saving...
# give name, as well as global or not.

sub template_load
{
  my ($self, $name) = @_;
  $name ||= 'Default';
  my ($oc) = $self->get_schema;
  my ($treename) = $self->{DBPARAMS}->[0];
  my %tree_template = $self->{GLOBAL}->{CONFIG}->prefix_get($treename, "MODULES{$oc}{TEMPLATES}{$name}");
  my %global_template = $self->{GLOBAL}->{CONFIG}->prefix_get('_GLOBAL', "MODULES{$oc}{TEMPLATES}{$name}");
  # Make sure no merging!
  my %template = ();

  if (not %tree_template)
  {
    %template = %global_template;
    $template{GLOBAL_TEMPLATE} = 1;
  } else {
    %template = %tree_template;
    $template{GLOBAL_TEMPLATE} = 0;
  }
  $template{TEMPLATE_IN_GLOBAL} = 1 if %global_template;
  $template{TEMPLATE_IN_TREE} = 1 if %tree_template;
  $template{TEMPLATE_NAME} = $name;

  $self->set(%template) if %template;
}

sub template_remove
{
  my ($self) = @_;

}

sub template_save
{
  my ($self, $global) = @_;
  my ($oc) = $self->get_schema;
  my $name = $self->get("template_name");
  $self->user_error("Must provide a name for the template") unless $name;

  # get smart hash, or raw?
  my %hash = $self->hash;

  my %minimal_hash = ();

  # Only keep valid attributes
  # As well as other pseudo-ones for template saving....
  my @attrs = $self->get_valid_attributes(1);
  push @attrs, ("entry_type"); # Other internal stuff we wanna keep.
  foreach my $key (keys %hash)
  {
    if (grep { uc($_) eq uc($key) } @attrs and $hash{$key} ne '')
    {
      $minimal_hash{$key} = $hash{$key};
    }
  }

  # NOW, save to disk!
  my $prefix = $global ? "_GLOBAL" : $self->{DBPARAMS}->[0];

  $self->{GLOBAL}->{CONFIG}->prefix_set($prefix, 
    "MODULES{$oc}{TEMPLATES}{$name}" => \%minimal_hash);

  my $err = $self->{GLOBAL}->{CONFIG}->write_protected($prefix);
  $self->system_error($err) if $err;

  return $name;
}

sub set
{
  my ($self, %hash) = @_;
  return () unless %hash;
  my %real_hash = ();
  my ($oc) = $self->get_schema;

  foreach my $key (keys %hash)
  {
    my @choices = ref $multiple{uc $key} eq 'ARRAY' ? @{ $multiple{uc $key} } : ();
    my $value = $hash{$key};

    if (ref $value eq 'ARRAY')
    {
      $value = [ grep { $_ ne '' } @$value ]; # Remove empty ones.
    }
    $real_hash{$key} = $value;
  }

  $self->SUPER::set(%real_hash);

print STDERR "CALLING SYNC!\n";
  $self->set_unchecked($self->set_sync($self->uc_smart_hash));
print STDERR "CALLED SYNC!\n";

  # Now, get changes via set_filter()
  # React to any changes. i.e. adds/removes of objectClasses.
  #$self->set_filter();
}

sub set_filter { my ($self, %hash) = @_; } # Overwritten by child.
# Should only do things if ->has_changed(X)

sub set_append_unchecked
{
  my ($self, $attr, @values) = @_;
  my @oldvalues = $self->get($attr);
  foreach my $value (@values)
  {
    push @oldvalues, $value if not grep { $value eq $_ } @oldvalues;
  }

  $self->set_unchecked($attr, \@oldvalues);
}

sub set_remove_unchecked
{
  my ($self, $attr, @values) = @_;
  my @oldvalues = $self->get($attr);
  my @newvalues = grep { my $v = $_; not grep { $v eq $_ } @values } @oldvalues;

  $self->set_unchecked($attr, \@newvalues);
}

sub cgi2db
{
  my ($self, %changes) = @_;

  # Take care of linked records!
  my ($oc) = $self->get_schema;
  my %links = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"LINKS"});
  my $implicit = $self->{GLOBAL}->{CONFIG}->get("IMPLICIT_LINK");
  my %header = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"HEADER"});
  foreach my $key (keys %links)
  {
    my @valkey = ref $links{$key}->{VALKEY} eq 'ARRAY' ? @{ $links{$key}->{VALKEY} } :
      ($links{$key}->{VALKEY});
    my $destkey = $links{$key}->{DESTKEY};
    my $destoc = $links{$key}->{DESTOC};
    my @srckey = ref $links{$key}->{SRCKEY} eq 'ARRAY' ? 
      @{ $links{$key}->{SRCKEY} } : ($links{$key}->{SRCKEY});
    next unless @valkey and $destkey and @srckey;
    if ($implicit) # What we recieved is list in entirety, not just changes
    {
      my @values = ref $changes{uc $key} eq 'ARRAY' ? @{ $changes{uc $key} } :
        ($changes{uc $key}||());
      #$changes{$key} = \@values;

      # Need to now muck with object
      my $subrec = DMEntry->new($links{$key}->{DESTOC});
      # Someday when can do cross-tree, implement here....

      # Generate filter


      my @filter = map { "($destkey=".$self->get($_).")" } @srckey;
      my $filter = join("", @filter);
      $filter = "(|$filter)" if @filter > 1;
      $subrec->search(filter=>$filter);

      my %found = ();

      for($subrec->first; $subrec->more; $subrec->next)
      {
        # Remove undesirables.
	my $destval = $subrec->get($valkey[0]);
	if (not @values or not grep { $_ eq $destval } @values)
	{
	  #$subrec->delete();
	} else {
	  $found{$destval}++;
	}
      }
      # Add new ones. Subrecord must exist prior!
      foreach my $value (@values)
      {
        if (not $found{$value})
	{
	  # FIX TO HANDLE ANY-OF valkeys!
	  my @filter = map { "($_=$value)" } @valkey;
	  my $filter = join("", @filter);
	  $filter = "(|$filter)" if @filter > 1;
	  my $subrec = DMEntry->new($destoc);
	  $subrec->search(filter=>$filter);
	  $self->user_error("No such entry '$value' for field '$header{$key}'. Must exist prior to adding.") unless $subrec->count;
	  my @destvals = $subrec->get($destkey);
	  push @destvals, $entry->get($srckey[0]);
	  $subrec->set($destkey=>\@destvals);
	  $subrec->commit();
	}
      }

    } else { # CHANGES only, Just take care of #ATTR#_add, #ATTR#_remove
      my @adds = ref $changes{uc $key."_add"} eq 'ARRAY' ? 
        @{ $changes{uc $key."_add"} } : ($changes{uc $key."_add"}||());
      my @removes = ref $changes{uc $key."_remove"} eq 'ARRAY' ? 
        @{ $changes{uc $key."_remove"} } : ($changes{uc $key."_remove"}||());

      if (@adds or @removes)
      {
        # Do adds, Ensure no duplicates!
	if (@adds)
	{
	  foreach my $add (@adds)
	  {
	    my $subrec = DMEntry->new($destoc);
	    # Fix to handle any-of valkeys!!! TODO
	    my @filter = map { "($_=$add)" } @valkey;
	    my $filter = join("", @filter);
	    $filter = "(|$filter)" if @filter > 1;
	    $subrec->search(filter=>$filter);
	    $self->user_error("No such entry '$add' for field '$header{$key}'. Must exist prior to adding.") unless $subrec->count;
	    my @subvals = $subrec->get($destkey);
	    my $srcval = $self->get($srckey[0]);
	    if (not grep { my $subval = $_; grep { $self->get($_) eq $subval } @srckey } @subvals)
	    # Not already there...
	    {
	      push @subvals, $self->get($srckey[0]);
	      $subrec->set($destkey, \@subvals);
	      $subrec->commit();
	    }
	  }
	}

	if (@removes)
	{
	  foreach my $remove (@removes)
	  {
	    my $subrec = DMEntry->new($destoc);
	    my @filter = map { "($_=$remove)" } @valkey;
	    my $filter = join("", @filter);
	    $filter = "(|$filter)" if @filter > 1;
	    $subrec->search(filter=>$filter);
	    $self->user_error("No such entry '$remove' for field '$header{$key}'. Must exist prior to removing.") unless $subrec->count;
	    my @subvals = $subrec->get($destkey);

	    # A lil complicated, with more than one possible subkey
	    # Will silently ignore subrecs that dont have self in it....
	    # WILL complain if non-existent subrec, though.
	    my @final_subvals = ();
	    foreach my $subval (@subvals)
	    {
	      if (not grep { $subval eq $self->get($_) } @srckey)
	      {
	        push @final_subvals, $subval;
	      }
	    }
	    $subrec->set($destkey=>\@final_subvals);
	    $subrec->commit();
	  }
	}
      }
    }
  }

  my %uc_changes = ();

  foreach my $key (keys %changes)
  {
    my $value = $changes{$key};
    my $scalar = scalar @{$changes{$key}} if ref $changes{$key} eq 'ARRAY';
    $value = $changes{$key}->[0] if $scalar ne '' and $scalar <= 1;
    $uc_changes{uc($key)} = $value;
  }

  return %uc_changes;
}

sub get_implicit_links
{
  my ($self) = @_;

  # Don't do linking if edit-only set and not edit mode
  my $implicit = $self->{GLOBAL}->{CONFIG}->get("IMPLICIT_LINK");
  return () if !$implicit or 
    ($implicit == 2 and $self->{GLOBAL}->{MODE} ne 'Edit') or 
    $self->{NOLINK};

  my ($oc) = $self->get_schema;
  my %links = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"LINKS"});

  my @all_cols = ref $self->{ALL_COLUMNS} eq 'ARRAY' ? @{$self->{ALL_COLUMNS}} : ();

  my @link_keys = grep { my $col=$_; scalar @all_cols == 0 or grep { $col eq $_ } @all_cols } keys %links;
  # Skip ones we didnt explicitly ask for, IF columns explicitly asked for (and not implicitly ALL)


  # ALSO, when we ask for auxGidNUmber on search, we need to explicitly get the related column!
  # Skip the ones that we don't explicitly ask for

  # For more complicated ones like ou=Aliases, the rfc822MailMember can be
  # either the uid or any of the mail attribute of the user. We need a way
  # to say 'the source value is any of these keys', even when one is multival.
  #


  return map
  {
    ($_ => [ DMEntry->new($links{$_}->{DESTOC}), $links{$_}->{SRCKEY}, $links{$_}->{DESTKEY} ], ),
  } @link_keys;
}

sub get_tree
{
  my ($self) = @_;
  return $self->{DBPARAMS}->[0];
}

sub get_oc
{
  my ($self) = @_;
  my ($oc) = $self->get_schema;
  return $oc;
}

sub get_oc_tree
{
  my ($self) = @_;
  my ($oc) = $self->get_schema;
  return ($oc, $self->{DBPARAMS}->[0]);
}

sub edit_msg_page { return; } # i.e. 'password changed to X. Click to continue'

sub struct_get
{
  my ($self, $struct, $key, $pseudo) = @_;
  return MalyVar->get($struct, $key, $pseudo);
}

1;
