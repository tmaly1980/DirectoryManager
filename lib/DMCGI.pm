package DMCGI;

use lib "../modules/lib";
use lib "../MalyCGI";
use lib "../etc";
use MalyCGI;
use base "MalyCGI";
use Data::Dumper;
use DMLDAP;
use DMConfig;
use User;
use File::Basename;
use MalyLicense;
use POSIX qw();

sub new # Subclass should call $self = SUPER->new() and then $self->display()
{
  my ($this, @args) = @_;
  my $globals = {};

  my $basedir = dirname(dirname(__FILE__));

  if (@args == 1) { $globals = $args[0]; } else { $globals = {@args}; }

  my $class = ref($this) || $this;
  # Since $self isn't instantiated, we must
  # Call the functions below passing $self as arg 0

  #$globals->{BASEDIR} = $basedir;
  ($globals->{MODE}) = $ENV{SCRIPT_NAME} =~ /([a-zA-Z.0-9_]+)[.]pl$/; 
    # Add, Search, View, Browse, Edit
  $globals->{REAL_MODE} = $globals->{MODE};
  $globals->{TITLE} = "Directory Manager";
  $globals->{REAL_MODE} = "Edit" if $globals->{REAL_MODE} eq 'Add';
  $globals->{REAL_MODE} = "Search" if $globals->{REAL_MODE} eq 'Browse';
  my $cgiprefix = $`; # Since REFERER is everything, even pathinfo.
  ($globals->{REFERER_MODE}) = $ENV{HTTP_REFERER} =~ 
    m{$cgiprefix([a-zA-Z.0-9_]+)}; # Add, Search, View, Browse, Edit

  $globals->{CONFIG} = DMConfig->new("$basedir/etc/DirectoryManager/");
  $globals->{CONFIG}->load_class_meta($globals);

  DMLDAP->set_globals($globals);
  my $ldap = User->new();
  $ldap->{NOLINK} = 1; # Don't bother with subrecs!
  # As the instances take copies into $self, of connection info, we can safely set it here and reset it to the default later.

  $globals->{AUTH_TREE} = $globals->{CONFIG}->prefix_get("_GLOBAL", "AUTH_TREE");
  $globals->{DEFAULT_TREE} = $globals->{CONFIG}->prefix_get("_GLOBAL", "DEFAULT_TREE");

  $ldap->init($globals->{AUTH_TREE});
  DMLDAP->init($globals->{AUTH_TREE});

  # We also want group subrecords to take on auth_tree....hmmm...

  $globals->{SESS_AUTH} = sub { $ldap->authenticate_session(@_) };
  $globals->{SESS_GET} = sub { $ldap->get_session(@_) };
  $globals->{SESS_POST} = sub { $ldap->rebind(@_) };
  $globals->{SESSION_DISPLAY_HOME} = 1;
  $globals->{SESSION_ID_NAME} = 'DirectoryManager';
  $globals->{SESSION_DISPLAY_REFERER} = 1;
  $globals->{HOME_PAGE} = "cgi-bin/index.pl";
  
  $globals->{MANUAL_PROCESS} = 1; # Since DN_ME is referenced in process()...
  $globals->{STYLE} = "style.css";
  $globals->{PATH_INFO_KEYS} ||= qw(tree class filter);

  my $self = $class->SUPER::new($globals);


  $self->{GLOBAL}->{DBPARAMS} = [ $self->{GLOBAL}->{CONFIG}->get("HOST"), version=>3 ];
  $self->{GLOBAL}->{SEARCH_OPTS} = [ scope=>"sub", base=>$self->{GLOBAL}->{CONFIG}->get("BASEDN"), filter=>"(objectClass=*)" ];

  # Bootstrap order:
  #
  # get_tree, gets or default
  # session_process, sets ME, DN_ME in GLOBAL
  # straps config onto tree too
  # DMLDAP->init($tree), gets host info for $tree configured
  # get_enabled_classes, relies on tree and session
  # get_class, or default (requires get_enabled_classes to be ready)
  # 

  $self->session_process(); # Might be logging into tree, so need given before session process
  my $class = $self->get_class;

  $self->{GLOBAL}->{OC} = $class;

  # ACL check within LDAP....



  my $total = 1 if ($self->{GLOBAL}->{MODE} =~ /View|Edit/);
  $total = $self->get("per_page") if ($self->{GLOBAL}->{MODE} =~ /Search|Browse/);
  $self->{GLOBAL}->{TOTAL} = $total;
  $self->{GLOBAL}->{OFFSET} = $self->get("offset");
  $self->{GLOBAL}->{SORT} = $self->get("sort");
  $self->{GLOBAL}->{DESC} = $self->get("desc");
  $self->{GLOBAL}->{FILTER} = $self->query_filter;

  $self->{GLOBAL}->{ADMIN} = $self->{GLOBAL}->{CONFIG}->has_admin_access;

  my $require_login = $self->{GLOBAL}->{CONFIG}->get("REQUIRE_LOGIN");

  if ($require_login and ref $self ne 'configCGI') # Don't require on config CGI!
  {
    $self->login("Authorization Required");
  }

  $self->verify_access();

  $self->process($self->get('action')); # Now do process, once DN_ME is set.

  return $self;
}

sub other_session_process_params
{
  my ($self) = @_;
  my $tree = $self->get("tree");
  $self->get_tree($tree) if $tree;
  return
  (
    TREE=>($self->get_path_info("tree")),
  );
}

sub verify_access
{
  my ($self) = @_;
  my $tree = $self->{GLOBAL}->{TREE};
  my $class = $self->{GLOBAL}->{OC};

  my @enabled_classes = $self->{GLOBAL}->{CONFIG}->get_enabled_classes();

  if (not $self->{GLOBAL}->{NO_LDAP}) # MUST DO AFTER SESSION GATHERING, AS ENCORPORATES!
  {
    if ($tree and $class and $class ne 'photo')
    {
      if ($class eq 'aclgroup')
      {
        my $auth_tree = $self->{GLOBAL}->{CONFIG}->get("AUTH_TREE");

        if (not $auth_tree)
	{
	  $self->system_error("Authentication Tree not configured.", "admin/");
	} elsif ($auth_tree ne $tree)
	{
	  $self->user_error("Sorry, this tree is not the authentication tree.", "$self->{GLOBAL}->{URL}/$auth_tree/aclgroup");
	} 

	my @my_groups = $self->{GLOBAL}->{CONFIG}->get_acl_groups();

        my @admin_groups = $self->{GLOBAL}->{CONFIG}->get_access_list("ADMIN_GROUP");
	my $admin_dn = $self->{GLOBAL}->{CONFIG}->get("ROOTDN");
	my $admin_group = join("; ", @admin_groups);

	my $authorized = (
	  $self->{GLOBAL}->{DN_ME} eq $admin_dn
	  #or grep { $_ eq 'ADMIN_DN' } 
	  #  ($self->{GLOBAL}->{CONFIG}->get_access_levels('ADMIN')) 
	  or grep { my $g=$_; grep { $g eq $_ } @my_groups } @admin_groups
	);

        if (not $admin_dn)
	{
          $self->system_error("Authentication tree not configured with an ACL Profile/'Admin DN'");
	} elsif (not $admin_group) {
          $self->user_error("You MUST log in as <b>$admin_dn</b>. You are currently logged in as '$self->{GLOBAL}->{DN_ME}'.", "$self->{GLOBAL}->{PATHINFO_URL}?action=RequiredLogin") unless $authorized;
	} else {
          $self->user_error("You MUST log in as <b>$admin_dn</b> or a member of the <b>$admin_group</b> group(s). You are currently logged in as '$self->{GLOBAL}->{DN_ME}'.", "$self->{GLOBAL}->{PATHINFO_URL}?action=RequiredLogin") unless $authorized;
	}
      } elsif (not grep { $_ eq $class } @enabled_classes) {
        $self->system_error("Module '$class' not available/enabled.", "cgi-bin/index.pl"); 
      }
    }
  }
}

sub session_process # Sets up ME and DN_ME in GLOBAL
{
  my ($self) = @_;

  if ($self->{GLOBAL}->{SESSION} && (my $username = $self->{GLOBAL}->{SESSION}->get("username")))
  {
    #$self->{GLOBAL}->{LOGGER}->log("SETTING SELF, WE GOT SESSION!");
    my $uid = undef;
    if ($username =~ /^uid=(.+?)[,]/) 
    { 
      $uid = $1; 
    } elsif ($username !~ /[,]/) {
      $uid = $username;
    } else {
      $self->{GLOBAL}->{DN_ME} = $username; 
      # I.e., the LDAP manager. It doesn't have an entry.
    }
    # Only set self if user has entry in system.
    my $tree = $self->{GLOBAL}->{SESSION}->get("TREENAME");
    my $form_tree = $self->get("tree");
    if(not $self->{PATH_INFO_ORIG}->{tree} or $self->just_logged_in)
    {
      $self->get_tree($form_tree || $tree);
    }

    if ($uid and $tree)
    {
      my $search = User->new();
      $search->init($tree);
      $self->{GLOBAL}->{ME} = $search->search(uid=>$uid);
      $self->{GLOBAL}->{DN_ME} = $search->get("DN");
    }
  }
}

sub init # Done prior to session handling...
{
  my ($self) = @_;

  # Load license file.
  $self->load_license();

  $self->msg_page("Directory Manager not properly configured. Please configure first, via the following link:",
  "admin/")
  if (
    not $self->{GLOBAL}->{NO_LDAP} and ref $self ne 'configCGI' and
    (
    not $self->{GLOBAL}->{CONFIG}->get_treenames or
    not $self->{GLOBAL}->{CONFIG}->prefix_get("_GLOBAL", "AUTH_TREE") or
    not $self->{GLOBAL}->{CONFIG}->prefix_get("_GLOBAL", "DEFAULT_TREE") 
    )
  );


  $self->get_tree();
  $self->{GLOBAL}->{SESS_LOGIN_PAGE} = sub { $self->template_display("login", MSG=>$_[0]); };
}

sub get_tree
{
  my ($self, $treename) = @_;
  my $action = $self->get("action");
  #$self->set_path_info(tree=>$self->get("tree")) if $action eq 'Login' or $action eq 'Anonymous Login';
  $self->set_path_info(tree=>$treename) if ($treename);
  $self->set_path_info_default("tree", $self->{GLOBAL}->{CONFIG}->prefix_get('_GLOBAL', "DEFAULT_TREE"));
  $treename = $self->get_path_info("tree");
  $self->user_error("No such tree.", "cgi-bin/index.pl")
    unless grep { $treename eq $_ } $self->{GLOBAL}->{CONFIG}->get_treenames;
  $self->{GLOBAL}->{TREE} = $treename;
  $self->{GLOBAL}->{CONFIG}->{PREFIX} = [$treename, '_GLOBAL'];
  DMLDAP->init($treename) if not $self->{GLOBAL}->{NO_LDAP}; # NEed to call BEFORE get_enabled_classes, as ultimately does
  return $treename;
}

sub get_class
{
  my ($self) = @_;
  my @enabled_classes = $self->{GLOBAL}->{CONFIG}->get_enabled_classes();
  my $tree_class = $enabled_classes[0] || "user";
  $self->set_path_info_default("class", $tree_class);
  my $class = $self->get_path_info("class");
}

sub template_display # Insert session information.
{
  my ($self, $page, @args) = @_;
  my $me = {};
  if ($self->{GLOBAL}->{ME})
  {
    $me = $self->{GLOBAL}->{ME}->hashref;
  } 
  elsif ($self->{GLOBAL}->{DN_ME})
  {
    $me = {DN=>$self->{GLOBAL}->{DN_ME}};
  }
  # Adjust template if asking for customized one.
  my $template = $self->get("_template");
  my @page = ref $page eq 'ARRAY' ? @$page : ($page);
  unshift @page, "../custom_templates/$template" if $template;
  my $oc = $self->get_path_info("class");
  my $config = $self->{GLOBAL}->{CONFIG}->get;
  my $admin = $self->{GLOBAL}->{CONFIG}->has_admin_access;
  my $requestor = $self->{GLOBAL}->{CONFIG}->has_request_access;
  my $moderator = $self->{GLOBAL}->{CONFIG}->has_moderator_access;
  my @multiple_choice = $oc ? (MULTIPLE_CHOICE=>[ $self->{GLOBAL}->{CONFIG}->get("${oc}_MULTIPLE")]) : ();

  my %min_access_level = $self->{GLOBAL}->{CONFIG}->get_min_access_level;

  my $access = $self->{GLOBAL}->{CONFIG}->get_access_level;

  my @enabled_entry_types = $self->{GLOBAL}->{CONFIG}->get_enabled_entry_types;

  my $tree = $self->{GLOBAL}->{CONFIG}->hashref;
  my $rootconf = $self->{GLOBAL}->{CONFIG}->hashref(undef);

  my $classconf = $self->{GLOBAL}->{CONFIG}->get("MODULES{$oc}");

  my @tabs = $self->{GLOBAL}->{CONFIG}->get_modules;

  $self->SUPER::template_display(\@page, ME=>$me, MIN_ACCESS_LEVEL=>\%min_access_level, ACCESS=>$access,
    HAS_MODERATOR_ACCESS=>$moderator, HAS_ADMIN_ACCESS=>$admin,HAS_REQUEST_ACCESS=>$requestor,
    HAS_BULKCHANGE_ACCESS=>($moderator||$admin),
    HAS_REQUESTOR_ACCESS=>$requestor, # To avoid confusion
    CONFIG=>$config, CUSTOM_DIR=>"custom_fields/$self->{GLOBAL}->{REAL_MODE}/$oc",
    CLASSCONF=>$classconf,
    CUSTOM_DIR_EDIT=>"custom_fields/Edit/$oc",
    CUSTOM_DIR_VIEW=>"custom_fields/View/$oc",
    CUSTOM_GLOBAL_OC_DIR=>"custom_fields/$oc",
    CUSTOM_GLOBAL_DIR=>"custom_fields",
    CLASSNAME=>$oc,
    CLASSREF=>$self->{GLOBAL}->{CLASSES}->{$oc},
    MODE=>$self->{GLOBAL}->{MODE},
    REAL_MODE=>$self->{GLOBAL}->{REAL_MODE},
    ENABLED_ENTRY_TYPES=>\@enabled_entry_types,
    TABS=>\@tabs,
    TREE=>$tree,
    ROOTCONF=>$rootconf,
    @multiple_choice,
    @args,
    );
}

sub query_filter # Generates search filter from form pathinfo OR querystring field=value
{
  my ($self) = @_;
  my $path_info_filter = $self->get_path_info("filter");
  return $path_info_filter if ($path_info_filter);
  my $value = $self->get("value");
  my $regex = $self->get("regex");
  $regex =~ s/X/$value/g;
  $regex ||= $value;
  $regex = '*' if (not $value);
  my $field = $self->get("field");
  my $form_filter = "$field=$regex";
  return $form_filter if ($field);
}

sub load_license
{
  my ($self) = @_;

  $self->{LICENSE} = MalyLicense::load("$self->{GLOBAL}->{BASEDIR}/etc/DirectoryManager-license.conf");

  if (not ref $self->{LICENSE} eq 'HASH')
  {
    $self->system_error("No license key file found ($self->{LICENSE}). Please purchase licenses from <a href='http://www.malysoft.com/products/'>http://www.malysoft.com/products/</a>", "http://www.malysoft.com/products/");
  } elsif (not grep { $_ > 0 } values %{ $self->{LICENSE} }) {
    $self->system_error("Invalid license key file. Please purchase licenses from <a href='http://www.malysoft.com/products/'>http://www.malysoft.com/products/</a>", "http://www.malysoft.com/products/");

  }

}

sub license_check
{
  my ($self) = @_;

  my $mode = $self->{GLOBAL}->{MODE};
  my %form = $self->hash;
  my $action = $self->get("action");
  my $class = $self->get_path_info("class");

  print STDERR "HAA=".$self->{GLOBAL}->{CONFIG}->has_admin_access."\n";
  print STDERR "MIDE=$mode, ACTION=$action, FORM=".Dumper(\%form)."\n";

  return if ($mode ne 'Add' or
    not $self->{GLOBAL}->{CONFIG}->has_admin_access or
    $class eq 'aclgroup' or
    ($action and $action ne 'Add Entry' and not %form) or (%form and $action ne 'Add Entry')
    );

  print STDERR "CHECKING LICENSE!!!\n";

  # Ignore if:
  # Not add
  # not admin (ie. requestor)
  # fiddling with page after add (i.e not blank form or not 'Add Entry')
  # 

  my %mod = $self->{GLOBAL}->{CONFIG}->get_modules();
  my $modkey = $self->{GLOBAL}->{OC};
  my $tree = $self->{GLOBAL}->{TREE};

  $self->system_error("Unable to determine module.") unless $modkey;
  $self->system_error("Unable to determine tree.") unless $tree;

  my %treelics = $self->{GLOBAL}->{CONFIG}->get("LICENSES{$modkey}");
  print STDERR "OC=$modkey, TREE=$tree, TREELICS=".Dumper(\%treelics)."\n";
  my $allocated_tree = $treelics{$tree};

  my $allocated = $self->get_allocated_entries($modkey, keys %treelics);

  my $used = $self->get_used_tree_entries($tree, $modkey);

  my $licensed = $self->{LICENSE}->{$modkey};

  my $auto_allocate = $self->{GLOBAL}->{CONFIG}->get("LICENSE_AUTOALLOCATE");

  print STDERR "ALLALLOCATED=$allocated, ALLOCATEDTREE=$allocated_tree, LICENSED=$licensed, USED=$used\n";

  if ($allocated > $licensed)
  {
    $self->system_error("No more licenses available for module '$mod{$modkey}'. Please <a href='cgi-bin/admin/config.pl/license' target='_new'>reallocate</a> or purchase more from <a href='http://www.malysoft.com/products/'>http://www.malysoft.com/products/</a>");
  } 
  elsif ($used eq '')
  {
    $self->internal_error("Unable to calculate existing entries.");
  }
  elsif ($used+1 > $allocated_tree and $allocated+($used-$allocated_tree)+1 <= $licensed and $auto_allocate)
  {
    # Need to re-allocate automatically!
    print STDERR "AUTOALLOCATING!\n";
    $self->{GLOBAL}->{CONFIG}->prefix_set('_GLOBAL',"LICENSES{$modkey}{$tree}"=>($used+1));
    $self->{GLOBAL}->{CONFIG}->write_protected('_GLOBAL');
  }
  elsif ($used+1 > $allocated_tree or ($used-$allocated_tree)+$allocated+1 > $licensed)
  {
    $self->system_error("No more licenses available for module '$mod{$modkey}'. Please <a href='cgi-bin/admin/config.pl/license' target='_new'>reallocate</a> or purchase more from <a href='http://www.malysoft.com/products/'>http://www.malysoft.com/products/</a>");
  }
}

sub get_allocated_entries 
{
  my ($self, $modkey, @trees) = @_;
  print STDERR "MODKEY=$modkey, TREES=".join(";", @trees)."\n";

  my $allocated = 0;
  my $licensed = $self->{LICENSE}->{$modkey};
  foreach my $tree (@trees)
  {
    my $tree_allocated = $self->{GLOBAL}->{CONFIG}->get("LICENSES{$modkey}{$tree}")||0;
    $allocated += $tree_allocated;
  }
  return $allocated;
}

sub get_used_tree_entries
{
  my ($self, $tree, $oc) = @_;

  # Do quick/efficient search....
  my $server = $self->{GLOBAL}->{CONFIG}->prefix_get($tree, "HOST");
  my $basedn = $self->{GLOBAL}->{CONFIG}->oc_basedn($oc, $tree);
  my $objectclass = $self->{GLOBAL}->{CONFIG}->oc_objectclass($oc);
  my $ldap = Net::LDAP->new($server, timeout=>10,version=>3)
    or $self->system_error("LDAP Server not running.");

  # Implement SSL/TLS stuff here, too.
  my $ssl_tls = $self->{GLOBAL}->{CONFIG}->prefix_get($tree, "SSL{VERSION}");
  my $verify = $self->{GLOBAL}->{CONFIG}->prefix_get($tree, "SSL{VERIFY}") || "optional";
  my $capath = $self->{GLOBAL}->{CONFIG}->prefix_get($tree, "SSL{CAPATH}");
  my $cafile = $self->{GLOBAL}->{CONFIG}->prefix_get($tree, "SSL{CAFILE}");
  my $clientcert = $self->{GLOBAL}->{CONFIG}->prefix_get($tree, "SSL{CLIENTCERT}");
  my $clientkey = $self->{GLOBAL}->{CONFIG}->prefix_get($tree, "SSL{CLIENTKEY}");

  # TODO, THINK about adding in decryptkey sub() to support encrypted client key files.
  if ($ssl_tls)
  {
    $ldap->start_tls(sslversion=>$ssl_tls, 
      verify=>$verify, capath=>$capath, cafile=>$cafile, 
      clientcert=>$clientcert, clientkey=>$clientkey);
  }

  # Bind as who we are!
  my $dn = $self->session_get("username");
  my $pw = $self->session_get("passwd");
  if ($dn and $pw)
  {
    my $bindmsg = $ldap->bind($dn, password=>$pw);
    $self->internal_error("Unable to bind: ". $bindmsg->error) if $bindmsg->code;
  }

  my @params = (base=>$basedn,filter=>"(objectclass=$objectclass)",scope=>'sub',attrs=>['1.1']);
  print STDERR "PARAMS=".Dumper(\@params)."\n";
  my $msg = $ldap->search(@params);


  $self->internal_error("Unable to query directory: ". $msg->error) if $msg->code;
  my $count = $msg->count;
  my $err = $msg->error;
  print STDERR "SERVER=$server, BAEDN=$basedn, FILTER=$objectclass, COUNT=$count, ERR=$err\n";

  my $used = $count;
}

1;
