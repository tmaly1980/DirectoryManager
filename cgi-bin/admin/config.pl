#!/usr/bin/perl

# ACCESS CONTROL !!! HOW? .htpasswd? local in file password!

our @lists = qw(DOMAIN_MAP ACL_PROFILE CLASSES REQUIRED MULTIPLE); 
# All other fields will only have their first value extracted.

configCGI->new(TEMPLATE_DIR=>"../../templates/config", NO_SESSION=>1, NO_LDAP=>1); # Add file of hashref to user=>pass here, i..e, required

package configCGI;

use lib "../../MalyCGI";
use lib "../../lib";
use lib "../../modules/lib";
use base DMCGI;
use Data::Dumper;
use POSIX;
use File::Basename;
use DMConfig;

sub process
{
  my ($self, $action) = @_;
  my $dmbase = dirname(dirname(dirname(__FILE__)));
  my $etcdir = "$dmbase/etc";
  my @path_info = $self->get_path_info_list();
  $path_info[0] ||= "general";
  my $path_info = "/".join("/", @path_info);
  my $tab = $path_info[0];
  my $tree = $self->get("TREE") || "_GLOBAL";
  my $saved = 0;

  my $addtree = ($tab eq 'tree' and $self->get("add"));


  my $config = $self->{GLOBAL}->{CONFIG}; #DMConfig->new("$etcdir/DirectoryManager/");
  $config->load_class_meta();
  $config->{UNDEF_DELETE} = 1;
  $config->{PREFIX} = $tree;

  my @treenames = grep { $_ ne '_GLOBAL' } $config->keys;

  $self->msg_page("Please click on the following link to configure your default directory tree:", "cgi-bin/admin/config.pl/tree?add=1") if not @treenames and not $addtree;

  my @tabs =
  (
    "general"=>"General",
    "ssl"=>"SSL/TLS",
    "modules"=>"Modules",
    ($tree and $tree ne '_GLOBAL' ? ("samba"=>"Samba 3") : ()),
  );

  @tabs = () if not grep { $_ ne '_GLOBAL' } $config->keys; # If no trees set up, show no tabs.

  unshift @tabs, ("tree"=>"Tree Settings") if ($tree and $tree ne '_GLOBAL');

  my %tabclass = map { $_ eq $tab ? ($_, 'selectedtab') : ($_, 'unselectedtab') } (keys %{{@tabs}}, 'acl', 'license');

  $tabclass{acl} = 'selectedtab' if $tab eq 'profile';

  ##########################################


  my $tmpl = $tab;

  # Here we do whatever extra form input manipulation we need to go from human manageable to 
  # computer storable...

  # WE WILL IMPLEMENT AN 'INHERIT' checkbox for each thingy...which just means to make it 'undef' and removed!
  # Set INHERIT CHECKBOX AUTOMTICALLY TO CHECKED ON LOAD WHEN THAT IS SO....

  # Fix inheritance, PRIOR to conversion from flat hash to complex data structure.
  my @form_keys = $self->get_keys;
  my @inherit_items = grep { /^INHERIT_/ } @form_keys;
  foreach my $inherit (@inherit_items)
  {
    my ($item) = $inherit =~ /^INHERIT_(.*)/;
    if ($self->get($inherit) and $item)
    {
      $self->set($item, undef);
    }
  }

  # Do conversion from nasty flat hash to complex data structures, as well as prepare page, etc...

  if ($tab eq 'tree')
  {
    $self->redirect("cgi-bin/admin/config.pl/general")
      if ((not $tree or $tree eq '_GLOBAL') and not $addtree);

    #$self->tree(); # Does absolutely nothing anymore...

    $self->prepare_tree() if $action eq 'Update';
    $self->initialize_tree() if $action eq 'Initialize';
    $self->delete_tree() if $action eq 'Delete Tree From Configuration';
    $self->add_tree() if $addtree and $action eq 'Update';

  } elsif ($tab eq 'general') {
    $self->general();
  } elsif ($tab eq 'samba') {
    $self->samba3();
  } elsif ($tab eq 'modules') {
    $self->bulk_migrate() if $action eq 'Bulk Migrate';
    $self->modules();
  } elsif ($tab eq 'profile') {
    #$config->{PREFIX} = '_GLOBAL'; # Already done by url!
    $self->profile();
  } elsif ($tab eq 'ssl') {
    $self->ssl();
  } elsif ($tab eq 'acl') {
    $self->generate_dmacl() if $action eq 'Generate Access Control File';
    $self->acl();
  } elsif ($tab eq 'license') {
    $self->license();
  } else {
    $tab = undef; # INVALID!
  }

  #%vars = (%vars, %gv, %sv, %mv);
  # May be obsolete with $self->set()...

  if ($action eq 'Update' and $tab)
  {
    my %form = $self->get_form;
    $config->set(%form);
    print STDERR "TREE=$config->{PREFIX}, FORM=".Dumper(\%form)."\n";
    my $err = $config->write_protected();
    $self->system_error($err) if $err;

    $saved=1;

    # Now, mark that we actually GOT to this page before.
    $config->prefix_set('_GLOBAL',"CONFIGURED{$ENV{PATH_INFO}}",1);
    $err = $config->write_protected('_GLOBAL');
    $self->system_error($err) if $err;
  }

  if ($self->{POST_URL}) # Redirect instead...
  {
    $self->redirect($self->{POST_URL});
  }

  my $CONFROOT = $config->hashref(undef);
  my $CONFREF = $config->hashref;
  my $DEFAULTREF = $config->hashref("_GLOBAL");
  my $EFFECTIVEREF = $addtree ? {} : $config->merge($DEFAULTREF, $CONFREF);
  my $treekeys = $config->keys;
  my @treekeys = ref $treekeys eq 'ARRAY' ? @$treekeys : ();
  my @treenames = grep { $_ ne '_GLOBAL' } @treekeys;

  my %vars = ref $self->{VARS} eq 'HASH' ? %{ $self->{VARS} } : ();

  my @modules = $config->get_modules();

  my $oc_spec = $config->oc_spec();

  $self->template_display("$tmpl", TABS=>\@tabs, TABCLASS=>\%tabclass,
    CONF=>$EFFECTIVEREF,
    PATH=>$path_info,
    TREES=>$CONFROOT,
    TREECONF=>$CONFREF,
    TREEKEYS=>$treekeys,
    TREENAMES=>\@treenames,
    DEFAULT=>$DEFAULTREF,
    IS_DEFAULT=>($tree eq '_GENERAL' ? 1 : 0),
    MODULE_NAMES=>[@modules],
    MODULES=>$oc_spec,
    SAVED=>$saved,
    TREE=>$tree,
    TAB=>$tab,
    %vars,
  );

  $self->user_error("No such page.");

}

sub get_form
{
  my ($self) = @_;

  my %form = $self->get_smart_hash;
  delete $form{TREE}; delete $form{MODULE}; delete $form{ACTION}; delete $form{_UPLOAD};

  foreach my $key (keys %form)
  {
    if ($key =~ /^INHERIT_/i)
    {
      delete $form{$key};
      next;
    }

    # Only cut down arrays to scalar element if it has only one element and not in explicit list names

    #if (ref $form{$key} eq 'ARRAY' and scalar @{$form{$key}} == 1 and not grep { $_ =~ /^$key/i } @lists)
    #{
    #  print STDERR "CHOPPING $key\n";
    #  $form{$key} = $form{$key}->[0] eq '' ? undef : $form{$key}->[0];
    #} # Else, do nothing.

    # Maybe we should just get normal hash, and for ones that MUST be array, we convert those within each tab's function?
    if (grep { $_ =~ /^$key/i } @lists and not ref $form{$key})
    {
      $form{$key} = $form{$key} eq '' ? undef : [ $form{$key} ];
    } 
  }

  my %conf_form = ref $self->{CONF_FORM} eq 'HASH' ? %{ $self->{CONF_FORM} } : ();
  # Stuff to be taken in literally, not cutting down array stuff....

  %form = (%form, %conf_form);
  return %form;
}

sub initialize_tree
{
  my ($self, $server, $basedn, $description) = @_;
  my $treename = $self->get("TREE");

  my $server = $self->{GLOBAL}->{CONFIG}->get("HOST");
  my $basedn = $self->{GLOBAL}->{CONFIG}->get("BASEDN");
  my $description = $self->{GLOBAL}->{CONFIG}->get("NAME");

  my ($rootdn, $rootpw) = $self->get("ROOTDN", "ROOTPW");
  $self->user_error("Must specify the Root DN and Password to initialize.") unless $rootdn and $rootpw;
  $self->user_error("No tree, server host or Base DN specified.") unless $treename and $server and $basedn;

  my @ldif_tree = get_tree_struct($basedn, $description);

  eval
  {
    require Net::LDAP;
  } or $self->system_error("Net::LDAP perl module must be installed, available in the perl-ldap package from http://search.cpan.org/");

  my $ldap = Net::LDAP->new($server, timeout=>10, version=>3) or $self->system_error("LDAP server not running.");

  # Implement SSL/TLS stuff here, too.
  my $ssl_tls = $self->{GLOBAL}->{CONFIG}->get("SSL{VERSION}");
  my $verify = $self->{GLOBAL}->{CONFIG}->get("SSL{VERIFY}") || "optional";
  my $capath = $self->{GLOBAL}->{CONFIG}->get("SSL{CAPATH}");
  my $cafile = $self->{GLOBAL}->{CONFIG}->get("SSL{CAFILE}");
  my $clientcert = $self->{GLOBAL}->{CONFIG}->get("SSL{CLIENTCERT}");
  my $clientkey = $self->{GLOBAL}->{CONFIG}->get("SSL{CLIENTKEY}");

  # TODO, THINK about adding in decryptkey sub() to support encrypted client key files.
  if ($ssl_tls)
  {
    $ldap->start_tls(sslversion=>$ssl_tls, 
      verify=>$verify, capath=>$capath, cafile=>$cafile, 
      clientcert=>$clientcert, clientkey=>$clientkey);
  }

  #

  $ldap->bind($rootdn, password=>$rootpw);

  for(my $i = 0; $i < @ldif_tree; $i+=2)
  {
    my $dn = $ldif_tree[$i];
    my $attrs = $ldif_tree[$i+1];
    my $mesg = $ldap->search(base=>$dn, scope=>'base', filter=>'objectClass=*');
    if (not $mesg->count) # Add.
    {
      $mesg = $ldap->add($dn, attr=>$attrs);
      $mesg->code && $self->system_error($mesg->error . ": for $dn");
    }
  }

  $self->{GLOBAL}->{CONFIG}->set("INITIALIZED", 1);
  my $err = $self->{GLOBAL}->{CONFIG}->write_protected();
  $self->system_error($err) if $err;
  $self->msg_page("Directory Initialized", "cgi-bin/admin/config.pl/tree?tree=$treename");
}

sub set
{
  my ($self, %h) = @_;
  my $caller = join(",", caller());
  $self->SUPER::set(%h);
}

sub get_tree_struct
{
  my ($dc, $description) = @_;
  my @parts = map { s/(dc|o)=//g; $_ } split(/,/, $dc);

  my @dc = ();

  # Do both organization and dcObject.
  if ($dc =~ /^o=/i && $dc !~ /,/)
  {
    @dc = map { s/^o=//g; $_ } split(/[.]/, $dc);
  } elsif ($dc =~ /^dc=/i && $dc !~ /[.]/) {
    @dc = map { s/^dc=//g; $_ } split(/,/, $dc);
  } else {
    $self->user_error("Base DN must either follow 'o=domain.com' or 'dc=domain,dc=com' convention.");
  }

  my $domain = join(".", @dc);

  $description ||= $domain;
  
  return
  (
    $dc=>
    [
      objectClass=>["top", "organization", "dcObject"],
      o=>$domain,
      description=>$description,
      dc=>$dc[0],
    ],
    "ou=People,$dc"=>
    [
      objectClass=>["top", "organizationalUnit"],
      ou=>"People",
      description=>"User Accounts (UNIX/Samba)",
    ],
    "ou=Contacts,$dc"=>
    [
      objectClass=>["top", "organizationalUnit"],
      ou=>"Contacts",
      description=>"Address Book Contacts (non-UNIX)",
    ],
    "ou=Machines,$dc"=>
    [
      objectClass=>["top", "organizationalUnit"],
      ou=>"Machines",
      description=>"Samba Machine Trust Accounts",
    ],
    "ou=Groups,$dc"=>
    [
      objectClass=>["top", "organizationalUnit"],
      ou=>"Groups",
      description=>"Group Accounts (UNIX)",
    ],
    "ou=ACLGroups,$dc"=>
    [
      objectClass=>["top", "organizationalUnit"],
      ou=>"ACLGroups",
      description=>"Directory Manager Access Groups",
    ],
    "ou=Aliases,$dc"=>
    [
      objectClass=>["top", "organizationalUnit"],
      ou=>"Aliases",
      description=>"Email Aliases/Mailing Lists",
    ],
    "ou=Locations,$dc"=>
    [
      objectClass=>["top", "organizationalUnit"],
      ou=>"Locations",
      description=>"Room/Building Locations",
    ],
  );
}

sub generate_dmacl
{
  my ($self) = @_;

  $self->set_dmacl_sync(1);

  # need to require DMCGI.conf file. but AFTER dirman.conf is written!
  #my $dmbase = dirname(dirname(__FILE__));
  #my $etcdir = "$dmbase/etc";
  #my $config = require "$etcdir/DMCGI.conf" or $self->system_error("Unable to read $etcdir/DMCGI.conf");

  print "Content-type: application/unknown\n";
  print "Content-Disposition: inline; filename=DMACL.conf\n";
  print "\n";

  my $auth_tree = $self->{GLOBAL}->{CONFIG}->get("AUTH_TREE") ||
    $self->system_error("Access Control Tree MUST be specified (was '$auth_tree')!");

  my $auth_basedn = $self->{GLOBAL}->{CONFIG}->prefix_get($auth_tree, "BASEDN") ||
    $self->system_error("No such directory tree ('$auth_tree')!");
  
  my $file = "DMACL.conf";

  my %acl = $self->{GLOBAL}->{CONFIG}->get("ACCESS_CONTROL");

  my @trees = $self->{GLOBAL}->{CONFIG}->keys();

  foreach my $treename (@trees)
  {
    next if $treename eq '_GLOBAL';
    my @profiles = $self->{GLOBAL}->{CONFIG}->prefix_get($treename, "ACL_PROFILE");
    my %oc = $self->{GLOBAL}->{CONFIG}->prefix_get($treename, "MODULES");
    my @oc = keys %oc;
    my %default_oc = $self->{GLOBAL}->{CONFIG}->get_modules();
    @oc = keys %default_oc if not @oc; # Default

    push @oc, "aclgroup" if $treename eq $auth_tree;

    my %joint_acl = ();

    # (GENERALLY SPEAKING, if you cannot edit some self attr, you wont be able to see it)
    # In other words, self has no MORE access than moderator (maybe less!)

    # FIRST, generate a list of the common attributes that get associated with the types of levels.
    	# Joint: what attrs admin(w), self(w), and moderators(w) have in common
	# moderator: what attrs admin(w) and moderators(w) have in common (self, else readonly)
	# Self: what attrs self can write (admin implicit write, else readonly)
	# Default: admins write, else read
    # THEN to print out each set of acls, get the group NAMES for this specific tree.

    # NEED to generate list of group names per objectclass.
    # Now, go through each module's branch and set access
    foreach my $oc (@oc)
    {
      # Administrators
      my @admin_dns = grep { $_ ne '' } map { $acl{$_}->{ADMIN_DN} } @profiles;
      my @admin_groups = grep { $_ ne '' } map { $acl{$_}->{ADMIN_GROUP} } @profiles;
      my @oc_admin_groups = grep { $_ ne '' } map { $acl{$_}->{uc "${oc}_ADMIN_GROUP"} } @profiles;

      my $admin_dn_text = join("\n", map { "\tby dn=\"$_\" write" } @admin_dns);
      my $admin_group_text = join("\n", map { "\tby group/groupOfNames/member.exact=\"cn=$_,ou=ACLGroups,$auth_basedn\" write" } @admin_groups);
      my $oc_admin_group_text = join("\n", map { "\tby group/groupOfNames/member.exact=\"cn=$_,ou=ACLGroups,$auth_basedn\" write" } @oc_admin_groups);

      my $admins = join("\n", grep { $_ ne '' } ($admin_dn_text, $admin_group_text, $oc_admin_group_text) );

      # Moderators
      my @moderator_groups = grep { $_ ne '' } map { $acl{$_}->{MODERATOR_GROUP} } @profiles;
      my @oc_moderator_groups = grep { $_ ne '' } map { $acl{$_}->{uc "${oc}_MODERATOR_GROUP"} } @profiles;

      my $moderator_group_text = join("\n", map { "\tby group/groupOfNames/member.exact=\"cn=$_,ou=ACLGroups,$auth_basedn\" write" } @moderator_groups);
      my $oc_moderator_group_text = join("\n", map { "\tby group/groupOfNames/member.exact=\"cn=$_,ou=ACLGroups,$auth_basedn\" write" } @oc_moderator_groups);

      my $moderators = join("\n", grep { $_ ne '' } ($moderator_group_text, $oc_moderator_group_text) );

      # Now, get common attributes.



      my $dn = $self->{GLOBAL}->{CONFIG}->oc_basedn($oc, $treename);

      # MUST get attributes by section, now.
      my @sections = $self->{GLOBAL}->{CONFIG}->oc_spec($oc, "SECTIONS");
      my @no_commit_fields = $self->{GLOBAL}->{CONFIG}->oc_spec($oc, "NO_COMMIT_FIELDS");
      push @no_commit_fields, qw(creatorsName modifiersName createTimestamp modifyTimestamp);

      my %attrs = ();

      my @write_all = ();
      my @admin_mod = ();
      my @admin_self = ();
      
      foreach my $section (@sections)
      {
        my @writers = ref $section->{WRITE} eq 'ARRAY' ? @{$section->{WRITE}} : ();
	my %writers = map { ($_, 1) } @writers;
        my @columns = ref $section->{COLUMNS} eq 'ARRAY' ? @{$section->{COLUMNS}} : ();
	@columns = grep { $_ } @columns;  # REmove undef fillers
	@columns = grep { my $col = $_; not grep { uc($_) eq uc($col) } @no_commit_fields } @columns;

	if ($writers{ADMIN} and $writers{MODERATOR} and $writers{SELF})
	{
	  push @write_all, @columns;
	} elsif ($writers{ADMIN} and $writers{MODERATOR}) {
	  push @admin_mod, @columns;
	} elsif ($writers{ADMIN} and $writers{SELF}) {
	  push @admin_self, @columns;
	}
      }

      my $write_all = join(",", @write_all);
      my $admin_mod = join(",", @admin_mod);
      my $admin_self = join(",", @admin_self);

      $admins = "\n$admins" if $admins;
      $moderators = "\n$moderators" if $moderators;

      # Now, print out text.
      if ($write_all)
      {
      print STDOUT "
access to dn.subtree=\"$dn\" attrs=\"$write_all\" $admins $moderators
	by self write
	by * read

";
      }

      # Do moderator acl entry.
      if ($admin_mod)
      {
        print STDOUT "
access to dn.subtree=\"$dn\" attrs=\"$admin_mod\" $admins $moderators
	by * read

";
      }

      # Do admin/self entry.
      if ($admin_self)
      {
        print STDOUT "
access to dn.subtree=\"$dn\" attrs=\"$admin_self\" $admins
	by self write
	by * read

";
      }

      # Do remainder read entry.
      print STDOUT "
access to dn.subtree=\"$dn\" $admins
	by * read

";

    }

  }

  # Final generic entry.
    print STDOUT "
access to * by * read
";

   close(STDOUT);

   exit;
}

sub samba3
{
  my ($self) = @_;
  # Save into new names...
  my %form = $self->get_form();
  my %samba = ();
  foreach my $key (keys %form)
  {
    next unless $key =~ /^SAMBA(.*)/;
    $samba{$1} = $form{$key};
    $self->set($key, undef);
  }
  $self->set_conf_form(SAMBA => \%samba);
}

sub general 
{
  my ($self) = @_;
  my @map = $self->get("DOMAIN_MAP");
  @map = map { (split(/:/, $_)) } @map;
  $self->set_conf_form("DOMAIN_MAP" => @map ? \@map : undef);
}

sub ssl 
{
  my ($self) = @_;

  # Save into new names...
  my %form = $self->get_form();
  my %ssl = ();
  foreach my $key (keys %form)
  {
    next unless $key =~ /^SSL_(.*)/;
    $ssl{$1} = $form{$key};
    $self->set($key, undef);
  }
  $self->set_conf_form(SSL => \%ssl);
}

sub profile
{
  my ($self) = @_;
  my %form = $self->get_form;
  my $profile_name = $self->get("profile");
  my $action = $self->get("action");
  my $add = !$profile_name;
  if ($profile_name)
  {
    $self->{VARS}->{PROFILE} = $self->{GLOBAL}->{CONFIG}->get("ACCESS_CONTROL{$profile_name}");
    $self->{VARS}->{PROFILE_NAME} = $profile_name;
  }

  if ($action eq 'Update')
  {
    # If changed profile name....

    $self->set_dmacl_sync(undef) if $add;

    my $profile_name = $form{PROFILE_NAME};

    # Update cross-referenced trees.
    $self->update_cross_referenced_trees($profile_name, $self->get("assigned_trees"));

    $self->set_conf_form(map { ("ACCESS_CONTROL{$profile_name}{$_}", $form{$_}) } 
      qw(ADMIN_DN ADMIN_GROUP REQUESTOR_GROUP MODERATOR_GROUP));

    my %modules = $self->{GLOBAL}->{CONFIG}->get_modules();
    my @modules = keys %modules;

    foreach my $module (@modules)
    {
      my %hash = (map { ("ACCESS_CONTROL{$profile_name}{$_}", $form{$_}) } 
        (
          uc($module."_ADMIN_GROUP"), 
          uc($module."_REQUESTOR_GROUP"), 
          uc($module."_MODERATOR_GROUP"), 
        )
      );

      $self->set_conf_form(%hash);
    }

    $self->{POST_URL} = "cgi-bin/admin/config.pl/acl?profile_added=1" if $add;
  }
  elsif ($profile_name and $action eq 'Delete Profile From Configuration') 
  {
    $self->set_conf_form("ACCESS_CONTROL{$profile_name}", undef);
    $self->{POST_URL} = "cgi-bin/admin/config.pl/acl";
  }

  foreach my $key (keys %form)
  {
    $self->set($key, undef);
  }

}

sub update_cross_referenced_trees # Trees assigned to a profile, FROM the profile page itself.
{
  my ($self, $profile, @trees) = @_;
  my $config = $self->{GLOBAL}->{CONFIG};

  my @all_trees = $config->get_treenames;
  foreach my $tree (@all_trees)
  {
    my @profiles = $config->prefix_get($tree, "ACL_PROFILE");
    if (grep { $tree eq $_ } @trees) # Add
    {
      next if grep { $profile eq $_ } @profiles;
      push @profiles, $profile;

    } else { # Remove.
      next if not grep { $profile eq $_ } @profiles;
      @profiles = grep { $profile ne $_ } @profiles;
    }
    $config->prefix_set($tree, ACL_PROFILE=>\@profiles);
    my $err = $config->write_protected($tree);
    $self->system_error($err) if $err;
  }
}

sub license
{
  my ($self) = @_;
  my $action = $self->get("action");
  my %form = $self->get_form;
  my $config = $self->{GLOBAL}->{CONFIG};
  my @trees = $config->get_treenames;
  my %modules = $config->get_modules();
  my %lic = ();
  my %liccount = ();
  if ($action eq 'Update')
  {
    foreach my $tree (@trees)
    {
      foreach my $mod (keys %modules)
      {
        my $count = $form{uc "${tree}_$mod"};
	$lic{$mod}{$tree} = $count || '0';
	$liccount{$mod} += $count;
      }
    }
    # MUST do reality check!

    foreach my $mod (keys %modules)
    {
      if ($liccount{$mod} > $self->{LICENSE}->{$mod})
      {
        $self->user_error("Sorry, too many licenses allocated for '$modules{$mod}'");
      }
    }

    $self->set_conf_form("LICENSES"=>\%lic);
    $self->set_conf_form("LICENSE_AUTOALLOCATE",$form{LICENSE_AUTOALLOCATE});

    foreach my $key (keys %form)
    {
      $self->set($key, undef);
    }
  }
  $self->{VARS}->{LICENSE} = $self->{LICENSE};
}

sub acl
{
  my ($self) = @_;
  my $action = $self->get("action");
  my %form = $self->get_form;
  # Duplicate this auth information into tree.
  if ($action eq 'Update' and $form{AUTH_TREE})
  {
    # Not sure if this is doing anything useful, assume not....


    #$form{"TREES{$form{AUTH_TREE}}{HOST}"} = $form{"AUTH_HOST"};
    #$form{"TREES{$form{AUTH_TREE}}{BASEDN}"} = $form{"AUTH_BASEDN"};
    #if (not $config->get("TREES{$form{AUTH_TREE}}{NAME}"))
    #{
    #  $form{"TREES{$form{AUTH_TREE}}{NAME}"} = "Default";
    #}
  }
}

sub set_conf_form
{
  my ($self, %hash) = @_;
  foreach my $key (keys %hash)
  {
    print STDERR "SETTING $key=$hash{$key}\n";
    $self->{CONF_FORM}->{$key} = $hash{$key};
    $self->unset($key);
  }
}

sub session_process
{
  my ($self) = @_;
  $self->{GLOBAL}->{DN_ME} = $self->get("AUTHDN");
}

sub bulk_migrate
{
  my ($self) = @_;
  my $entry_type = $self->get("MIGRATE_ENTRY_TYPE");
  my $tree = $self->get("TREE");
  my $module = $self->get("MODULE");
  my $filter = $self->get("FILTER");
  my @filter = $filter ? (filter=>$filter) : ();
  my $dn = $self->get("AUTHDN");
  my $pw = $self->get("AUTHPW");

  return if $tree eq '_GLOBAL' or $tree eq '' or not $entry_type or not $module or not $dn or not $pw;

  $self->{GLOBAL}->{CONFIG}->{PREFIX} = [$tree, '_GLOBAL'];

  #DMLDAP->set_globals($globals);
  DMLDAP->init($tree); # So know what tree to do on....

  # Configure authorization...
  DMLDAP->creds($dn, $pw);

  my $entries = DMEntry->new($module);
  $entries->search(@filter);
  my $count = $entries->count;

  print $self->{GLOBAL}->{TEMPLATE}->content_type("text/plain")."\n";
  print "Found $count entries for tree '$tree', module '$module'.\n";
  print "Filter is '$filter'.\n" if $filter;
  print "Migrating to entry type '$entry_type'.\n";
  print "\n";

    $entries->{DEBUG} = 1;

  for($entries->first; $entries->more; $entries->next)
  {
    my $dn = $entries->get("DN");
    print "Migrating: $dn: ";
    $entries->commit(entry_type=>$entry_type);
    print "DONE!\n\n";
  }

  print "\n\nDONE! Click back in your browser to continue.\n";

  exit;
}

sub get_tree
{
  my ($self) = @_;
  return $self->get("TREE");
}

sub get_class
{
  my ($self) = @_;
  return $self->get("MODULE");
}

sub modules
{
  # XXX TODO inherit for modules, as well as doing proper multiple's/required's
  my ($self) = @_;
  my $module = $self->get("MODULE") || $self->{GLOBAL}->{CONFIG}->get_modules(1);
  $self->{VARS}->{MODULE} = $module;
  $self->{VARS}->{CLASSREF} = $self->{GLOBAL}->{CONFIG}->oc_spec($module);

  # should STILL operate this block unless access is '0'.
  # COULD be inheriting!

  my $access = $self->get("ACCESS");

  if ($access ne '0') # NOT disabled, something, even if inheriting.
  {
    # convert entry types....
    my %et = $self->{GLOBAL}->{CONFIG}->oc_spec($module, "ENTRY_TYPES");
    my %entry_types = ();
    foreach my $key (keys %et)
    {
      my $v = $self->get("ENTRY_TYPE_$key");
      $entry_types{$key} = $v;
      $self->set("ENTRY_TYPE_$key", undef);
    }
    $self->set(ENTRY_TYPES => \%entry_types) if %entry_types;
  
    # Convert homedir stuff...
    if ($module eq 'user')
    {
      my %homedir = 
      (
        CREATE=>$self->get("CREATE_HOME_DIRS"),
        HOST=>$self->get("CREATE_HOME_DIR_HOST"),
        PORT=>$self->get("CREATE_HOME_DIR_PORT"),
        SSL=>$self->get("CREATE_HOME_DIR_SSL"),
        PASS=>$self->get("CREATE_HOME_DIR_PASS"),
      );
      map { $self->set("CREATE_HOME_DIR$_", undef); } qw(S _PASS _PORT _HOST _SSL);
      $self->set(HOMEDIR => \%homedir);
    }

    # Let's do Required fields...
    my @required = $self->get("REQUIRED"); # Force into array, if just scalar.

    if ($self->get("INHERIT_REQUIRED"))
    {
      $self->set(REQUIRED=>undef);
    } else { # If list is empty, we're removing requirements!
      $self->set(REQUIRED => \@required);
    }

  
    # Let's do multiple choices
    my @mchoice = $self->get("MULTIPLE");
    
    my %mchoice = map { (split(/\|/, $_, 2)) } @mchoice;
    %mchoice = map { ($_, [split(":", $mchoice{$_})]) } keys %mchoice;

    if ($self->get("INHERIT_MULTIPLE"))
    {
      $self->set(MULTIPLE=>undef);
    } else { # If list is empty, we're removing list!
      $self->set(MULTIPLE => \%mchoice);
    }

    # Map everything to go under <TREE>{MODULES}{$module} ...
    my %form = $self->get_form;
    #$Data::Dumper::Maxdepth = 4;
    foreach my $key (keys %form)
    {
      my $value = $form{$key};
      if (ref $value eq 'HASH')
      {
        $value = { %{ $form{$key} } };
      } elsif (ref $value eq 'ARRAY') {
        $value = [ @{ $form{$key} } ];
      }
      $self->set_conf_form("MODULES{$module}{$key}" => $value);
      $self->set($key, undef);
    }
  
  } else { # Ignore everything EXCEPT 'ACCESS'
    my %form = $self->get_form;
    foreach my $key (keys %form)
    {
      $self->set($key, undef);
    }
    $self->set_conf_form("MODULES{$module}{ACCESS}" => $form{ACCESS});
  }
}

# Move generate DMACL to within tree?
# What about auth tree?
# XXX TODO....
sub tree
{
  my ($self) = @_;
  my $treename = $self->get("tree");
  my $action = $self->get('action');
  my $add = $self->get("add");

  $self->{VARS}->{ADD} = $add;
  $self->set("add", undef);
}

sub rename_tree
{
  my ($self, $newname) = @_;
  $self->{GLOBAL}->{CONFIG}->rename($oldname, $newname);
}

sub prepare_tree
{
  my ($self) = @_;
  my %form = $self->hash;
  my $treename = $self->get("tree");

  my $configured = ($form{NAME} and $form{TREENAME} and $form{HOST} and $form{BASEDN}) ? 1 : 0;
  $self->user_error("All fields in RED are required.")
    unless ($configured);
  $self->set("CONFIGURED", $configured);

  $self->user_error("Illegal character in tree abbreviation, only letters, numbers, _ and - allowed")
    if ($form{TREENAME} =~ /\W/);

  my $addtree = $self->get("ADD");
  if (not $addtree)
  {
    $self->{GLOBAL}->{CONFIG}->rename($form{TREENAME}) if $treename and $treename ne $form{TREENAME};
    $self->{GLOBAL}->{CONFIG}->{PREFIX} = $form{TREENAME};
  }
}

sub delete_tree
{
  my ($self) = @_;
  my $tree = $self->get("tree");
  my $config = $self->{GLOBAL}->{CONFIG};
  $config->delete($tree);
  $self->redirect("cgi-bin/admin/config.pl/general")
}

sub add_tree
{
  my ($self) = @_;
  my %form = $self->get_form;
  delete($form{ADD});
  my $config = $self->{GLOBAL}->{CONFIG};
  $self->user_error("All fields in RED are required.")
    unless ($form{NAME} and $form{TREENAME} and $form{HOST} and $form{BASEDN});

  $config->{PREFIX} = $form{TREENAME};

  $config->set(%form);
  my $err = $config->write_protected();
  $self->system_error($err) if $err;

  my @other_trees = grep { $_ ne $form{TREENAME} } $config->get_treenames();
  print STDERR "TREES=".Dumper(\@other_trees)."\n";

  # Set as default tree if no others.
  if (not @other_trees)
  {
  print STDERR "NO OTHER TREES, SETTING TO $form{TREENAME}!\n";
    $config->prefix_set("_GLOBAL", DEFAULT_TREE=>$form{TREENAME}, AUTH_TREE=>$form{TREENAME});
    my $err = $config->write_protected('_GLOBAL');
    $self->system_error($err) if $err;
  }

  $self->set_dmacl_sync(undef);
    
  $self->redirect("cgi-bin/admin/config.pl/tree?tree=$form{TREENAME}")
}

sub set_dmacl_sync
{
  my ($self, $value) = @_;
  my $config = $self->{GLOBAL}->{CONFIG};
  $config->prefix_set("_GLOBAL", DMACL_SYNC => $value);
  my $err = $config->write_protected('_GLOBAL');
  $self->system_error($err) if $err;
}

1;

    # dmconfig to read one tree per file....
    # get dmconfig to work out of infinitely hierarchical files....
    # put in some dummy tree-based settings...
    # pass global as well as tree-based config, display which is.
    # GLOBAL STUFF SHOULD BE UNDER _GLOBAL 
    # TREE STUFF SHOULD BE UNDER TREENAME

    # 

__END__

