package DMConfig;
use lib "../MalyCGI";
use base "MalyConf";
use Data::Dumper;
use File::Basename;
use MalyVar;
use Aclgroup;

our $DMBASE = dirname(dirname(__FILE__));
our $ETCDIR = "$DMBASE/etc";
our $GLOBALS = undef;
our $LOGGER = MalyLog->new();
our $MODULES =
[
    user=>"Users",
    group=>"Groups",
    mail=>"Mailing Lists",
    location=>"Locations",
];

#sub new
#{
#  my ($this, @params) = @_;
#  my $class = ref $this || $this;
#  my $self = $class->SUPER::new(@params);
#}

#sub new
#{
#  my ($this, $globals) = @_;
#  my $class = ref $this || $this;
#  my $self = bless {}, $class;
#  $self->{GLOBAL} = $globals;
#  $LOGGER->system_error("Bad Configuration Syntax in etc/DirectoryManager.conf")
#    if $CONF->{CONF_FOUND} and not $CONF->{CONF_LOADED};
#
#  # Can we set $CONF->{MALYCONF}->{PREFIX} here?
#  return $self;
#}

sub oc_spec
{
  my ($self, $oc, $key) = @_;
  return MalyVar->get($self->{GLOBAL}->{CLASSES}) unless $oc;
  my $classref = $self->{GLOBAL}->{CLASSES}->{$oc};
  return MalyVar->get($classref, $key); # If key not passed, just gets all
}

sub oc_basedn # Is possile we pass authtree name 
{
  my ($self, $oc, $treename) = @_;
  $oc ||= $self->{GLOBAL}->{OC};
  $treename ||= $self->{GLOBAL}->{TREE};

  my $basedn = $self->prefix_get([$treename, '_GLOBAL'], "BASEDN");
  my $ou = $self->{GLOBAL}->{CLASSES}->{$oc}->{OU};
  $basedn = "ou=$ou,$basedn" if $ou;
  return $basedn;
}

sub get_treename_by_basedn
{
  my ($self, $basedn) = @_;
  my @treenames = $self->keys;
  foreach my $treename (@treenames)
  {
    my $tree_basedn = $self->get("BASEDN");
    return $treename if $basedn eq $tree_basedn;
  }
}

sub oc_objectclass
{
  my ($self, $oc) = @_;
  return $self->{GLOBAL}->{CLASSES}->{$oc}->{OBJECT_CLASS};
}

sub get
{
  my ($self, @params) = @_;
  my $value = $self->SUPER::get(@params);
  return get_wanted_format($value, wantarray);
}

sub get_root_dns
{
  my ($self, $treename) = @_;
  $treename ||= $self->{GLOBAL}->{TREE};
  my @profiles = $self->prefix_get([$treename,'_GLOBAL'], "ACL_PROFILE");
  my @dns = ($self->prefix_get($treename, "ROOTDN"));
  foreach my $proname (@profiles)
  {
    my $profile = $self->get("ACCESS_CONTROL{$proname}");
    push @dns, $profile->{ADMIN_DN} if $profile->{ADMIN_DN};
  }

  return grep { $_ ne '' } @dns;
}

sub has_admin_access
{
  my ($self, @oc) = @_;

  my $session_dn = $self->{GLOBAL}->{DN_ME};
  my @root_dns = $self->get_root_dns();
  # Check to see if Root DN.... MUST be accurate, with no spacing discrepencies!

  if ($session_dn and @root_dns and grep { $session_dn eq $_ } @root_dns)
  {
    if (wantarray)
    {
      return map { ($_, 1) } @oc;
    } else {
      return 1;
    }
  }

  return $self->check_access_level("ADMIN", @oc);
}

sub get_acl_groups
{
  my ($self) = @_;
  my $auth_tree = $self->get("AUTH_TREE");
  my $dn = $self->{GLOBAL}->{DN_ME};
  my ($rdn) = $dn =~ /^([^,]+),/;
  my $groups = Aclgroup->new();
  $groups->init($auth_tree);

  # Who we are may not be under auth_tree, so only do RDN if matches auth_tree
  my $filter = "(member=$dn)";
  if (my ($rdn) = $dn =~ /^([^,]+),ou=People,$auth_tree$/)
  {
    $filter = "(|(member=$dn)(member=$rdn))";
  }

  $groups->search(filter=>$filter);
  return $groups->get_all("CN") if wantarray;
  return $groups;
}

sub load_access
{
  my ($self, $level, @oc) = @_;

  my $treename = $self->{GLOBAL}->{TREE};
  my $session_dn = $self->{GLOBAL}->{DN_ME};
  my $auth_tree = $self->get("AUTH_TREE");
  return undef unless $session_dn and $auth_tree;
  @oc = ($self->{GLOBAL}->{OC}) unless @oc; # Just the current one.

  if (not exists $self->{"HAS_${level}_ACCESS"}->{$session_dn}->{"$treename"})
  # List of groups....
  # This really needs to be cached, being called each entry for HAS_EDIT_ACCESS
  {
    $self->{ACL_GROUPS} = [ $self->get_acl_groups() ];
    my @groups = @{ $self->{ACL_GROUPS} };

  
    my @aclnames = $self->get("ACL_PROFILE");
    foreach my $aclname (@aclnames)
    {
      my %acl_list = $self->get("ACCESS_CONTROL{$aclname}");
      foreach my $key (keys %acl_list)
      {
        if (ref $self->{ACL}->{$key} eq 'ARRAY')
        {
          push @{ $self->{ACL}->{$key} }, $acl_list{$key};
  
        } else {
          $self->{ACL}->{$key} = [ $acl_list{$key} ];
        }
      }
    }
  
    $self->{ACL_DNS} = $self->{ACL}->{"${level}_DN"} || [];
    $self->{ACL_GROUPS} = $self->{ACL}->{"${level}_GROUP"} || [];

    my @acl_dns = @{ $self->{ACL_DNS} };
    my @acl_groups = @{ $self->{ACL_GROUPS} };


    $self->{"ACCESS_LEVELS"} ||= [];

    $self->{"${level}_DN"} = (@acl_dns and grep { $_ eq $session_dn } @acl_dns);
    $self->{"${level}_GROUP"} = (@groups and grep { my $group = $_; grep { $group eq $_ } @groups } (@acl_groups));

    push @{ $self->{"ACCESS_LEVELS"} }, "${level}_DN" if $level_dn;
    push @{ $self->{"ACCESS_LEVELS"} }, "${level}_GROUP" if $level_group;

  }

  my @groups = ref $self->{ACL}->{uc "${level}_GROUP"} eq 'ARRAY' ? @{ $self->{ACL}->{uc "${level}_GROUP"} } : ();
    print STDERR "GROUPS=".join("; ", @groups)."\n";
  @groups = grep { $_ } @groups; # Skip empty ones...

  
  foreach my $oc (@oc)
  {
    my @oc_acl_groups = ref $self->{ACL}->{uc "${oc}_${level}_GROUP"} eq 'ARRAY' ? @{ $self->{ACL}->{uc "${oc}_${level}_GROUP"} } : ();
    @oc_acl_groups = grep { $_ } @oc_acl_groups; # Skip empty ones...
    my @matching_group = grep { my $group = $_; grep { $group eq $_ } @groups } (@oc_acl_groups);
    my $oc_level_group = (@groups and @matching_group);

    push @{ $self->{"ACCESS_LEVELS"} }, uc("${oc}_${level}_GROUP") if $oc_level_group;

    print STDERR "SDn=$session_dn, TREE=$treename, oc=$oc\n";
    print STDERR "AMTHINCG=".join("; ", @matching_group)."\n";
    print STDERR "OC_ACL_GROUPS=".join("; ", @oc_acl_groups)."\n";
  print STDERR "LEVEL_DN=$self->{'${level}_DN'}, LEVEL_GOU=$self->{'${level}_GROUP'}, OC_LEVL=$oc_level_group\n";
  
    $self->{"HAS_${level}_ACCESS"}->{$session_dn}->{$treename}->{$oc} = 1
      if ($self->{"${level}_DN"} or $self->{"${level}_GROUP"} or $oc_level_group);
  }
}

sub get_access_levels
{
  my ($self, $level) = @_;
  $self->load_access($level, undef);
  return @{ $self->{ACCESS_LEVELS} } if wantarray;
  return $self->{ACCESS_LEVELS};
}

sub check_access_level # For a certain entry.
{
  my ($self, $level, @oc) = @_;
  my $treename = $self->{GLOBAL}->{TREE};
  my $session_dn = $self->{GLOBAL}->{DN_ME};
  @oc = ($self->{GLOBAL}->{OC}) unless @oc; # Just the current one.

  $self->load_access($level, @oc);

  $Data::Dumper::Maxdepth =5;
  print STDERR "ACCESS=".Dumper($self->{"HAS_${level}_ACCESS"})."\n";

  if (wantarray)
  {
    #return () if not exists $self->{"HAS_${level}_ACCESS"} or not exists $self->{"HAS_${level}_ACCESS"}->{$session_dn} or
    #  not exists $self->{"HAS_${level}_ACCESS"}->{$session_dn}->{"$treename"};
    return ref $self->{"HAS_${level}_ACCESS"}->{$session_dn}->{"$treename"} eq 'HASH' ? 
      %{ $self->{"HAS_${level}_ACCESS"}->{$session_dn}->{"$treename"} } : ();
  } else {
    #return undef if not exists $self->{"HAS_${level}_ACCESS"} or $self->{"HAS_${level}_ACCESS"}->{$session_dn} or
    #  $self->{"HAS_${level}_ACCESS"}->{$session_dn}->{"$treename"} or
    #  $self->{"HAS_${level}_ACCESS"}->{$session_dn}->{"$treename"}->{$oc[0]};
    return $self->{"HAS_${level}_ACCESS"}->{$session_dn}->{"$treename"}->{$oc[0]};
  }
}

sub get_wanted_format
{
  my ($value, $wantarray) = @_;

  if ($wantarray and not ref $value and $value eq '')
  {
    return ();
  }
  elsif (ref $value eq 'ARRAY' and $wantarray)
  {
    return @{$value};
  }
  elsif (ref $value eq 'HASH' and $wantarray)
  {
    return %{$value};
  } else {
    return $value;
  }
}

sub mode
{
  my ($self) = @_;
  my $mode = $self->{GLOBAL}->{MODE};
  $mode = uc($mode);
  $mode = "SEARCH" if $mode eq 'BROWSE';
  $mode = 'EDIT' if $mode eq 'ADD';
  return $mode;
}

sub has_request_access
{
  my ($self, @oc) = @_;
  return $self->check_access_level("REQUESTOR", @oc);
}

sub has_moderator_access
{
  my ($self, @oc) = @_;
  return $self->check_access_level("MODERATOR", @oc);
}

sub get_enabled_classes
{
  my ($self, $treename) = @_;
  my %min_access_level = $self->get_min_access_level;
  my @tabs = ref $MODULES eq 'ARRAY' ? @$MODULES : ();
  my $i = 0; my @tab_names = grep { $i++ % 2 == 0 } @tabs;
  my @enabled_classes = ();

  # Humor this...
  my %access_levels = $self->get_access_level(@tab_names);

  #
  foreach my $oc (@tab_names)
  {
    my $real_level = $self->get("MODULES{$oc}{ACCESS}");
    $real_level = 'ANON' if $real_level eq ''; 
    # DEFAULT TO ANON!
    # MUST EXPLICITLY DISABLE!

    my $levels = $min_access_level{$real_level};
    # The requirements...

    #my $access_level = $self->get_access_level($treename, $oc);
    my $access_level = $access_levels{$oc} || 'ANON';
    # The user's access levle

    my @levels = ref $levels eq 'ARRAY' ? @$levels : ();


    if (grep { $access_level eq $_ } @levels)
    {
      push @enabled_classes, $oc;
    }
  }

  return @enabled_classes;
}

sub get_min_access_level
{
  my ($self) = @_;
  my %min_access_level = 
  (
    ""=>[qw(ADMIN MODERATOR REQUESTOR SELF USER ANON)],
    # In case not explicitly set in config
    "ANON"=>[qw(ADMIN MODERATOR REQUESTOR SELF USER ANON)],
    "USER"=>[qw(ADMIN MODERATOR REQUESTOR SELF USER)],
    "SELF"=>[qw(ADMIN MODERATOR REQUESTOR SELF USER)],
    "REQUESTOR"=>[qw(ADMIN MODERATOR REQUESTOR)],
    "MODERATOR"=>[qw(ADMIN MODERATOR)],
    "ADMIN"=>[qw(ADMIN)],
  );

  return %min_access_level if wantarray;
  return \%min_access_level if defined wantarray;
}

sub get_access_level
{
  my ($self, @oc) = @_;
  @oc = ($self->{GLOBAL}->{OC}) unless @oc; # Just the current one.

  my %admin = $self->has_admin_access(@oc);
  my %requestor = $self->has_request_access(@oc);
  my %moderator = $self->has_moderator_access(@oc);

  if (wantarray)
  {
    my %access = ();
    foreach my $oc (@oc)
    {
      $access{$oc} = "ANON";
      $access{$oc} = "USER" if $self->{GLOBAL}->{DN_ME};
      $access{$oc} = "REQUESTOR" if $requestor{$oc};
      $access{$oc} = "MODERATOR" if $moderator{$oc};
      $access{$oc} = "ADMIN" if $admin{$oc};
    }
    return %access;
  } else {
    my $access = "ANON";
    $access = "USER" if $self->{GLOBAL}->{DN_ME};
    $access = "REQUESTOR" if $requestor{$oc[0]};
    $access = "MODERATOR" if $moderator{$oc[0]};
    $access = "ADMIN" if $admin{$oc[0]};
    return $access;
  }
  return 'ANON'; # Default.
}

sub get_enabled_entry_types
{
  my ($self, $oc) = @_;
  $oc ||= $self->{GLOBAL}->{OC};

  if (not ref $self->{ENABLED_ENTRY_TYPES}->{$oc} eq 'ARRAY')
  {
    $self->{ENABLED_ENTRY_TYPES}->{$oc} = [];

    my @entry_types = ref $self->{GLOBAL}->{CLASSES}->{$oc}->{"ENTRY_TYPES"} eq 'ARRAY' ?
      @{ $self->{GLOBAL}->{CLASSES}->{$oc}->{"ENTRY_TYPES"} } : ();
    my @enabled_entry_types = ();

    my $class_ref = $self->{GLOBAL}->{CLASSES}->{$oc};
    my $conf = $self->get();
    my %conf = ref $conf eq 'HASH' ? %$conf : ();
    my %class = ref $class_ref eq 'HASH' ? %$class_ref : ();
  
    my $vars = {CONF=>$conf, CLASS=>$class_ref, %conf, %class};
  
    for (my $i = 0; $i < @entry_types; $i+=2)
    {
      my $et = $entry_types[$i];
      my $meta = $entry_types[$i+1];
      my $rc = $self->get("MODULES{$oc}{ENTRY_TYPES}{$et}");
      next if $rc eq '0'; # Omission (blank) or 1 means ok, only disable on explicit '0'
      push @{ $self->{ENABLED_ENTRY_TYPES}->{$oc} }, ($et, $meta);
    }
  }

  return @{ $self->{ENABLED_ENTRY_TYPES}->{$oc} };
}

sub load_class_meta
{
  my ($self, $globals) = @_;
  if ($globals)
  {
    $self->{GLOBAL} = $globals;
  }

  my @class_confs = <$DMBASE/etc/class/*.conf>;
  foreach my $file (@class_confs)
  {
    my ($prefix) = $file =~ m{/(\w+)[.]conf$};
    my $conf = do $file;
    $self->{GLOBAL}->{CLASSES}->{$prefix} = $conf;

    next unless ref $conf->{SECTIONS} eq 'ARRAY';
    push @{ $conf->{SECTIONS} },
    {
      NAME=>"Internal Tracking",
      ABBREV=>"tracking",
      READ=>[qw(ADMIN MODERATOR)],
      WRITE=>[qw(ADMIN MODERATOR)],
      COLUMNS=>
      [
        "creatorsName", "modifiersName",
	"createTimestamp", "modifyTimestamp",
      ],
    };

    next unless ref $conf->{HEADER} eq 'ARRAY';
    push @{ $conf->{HEADER} },
    (
      creatorsName=>"Created By",
      createTimestamp=>"Creation Timestamp",
      modifiersName=>"Last Modified By",
      modifyTimestamp=>"Last Modified Timestamp",
    );

    $conf->{READONLY} = [] unless ref $conf->{READONLY} eq 'ARRAY';
    $conf->{BULK_CHANGE}->{EXCLUDE} = [] unless ref $conf->{BULKCHANGE}->{EXCLUDE} eq 'ARRAY';
    push @{ $conf->{READONLY} }, (qw[creatorsName createTimestamp modifiersName modifyTimestamp]);
    push @{ $conf->{BULK_CHANGE}->{EXCLUDE} }, (qw[creatorsName createTimestamp modifiersName modifyTimestamp]);
  }
}

sub get_modules
{
  my ($self, $first) = @_;
  return $MODULES->[0] if $first;
  return wantarray ? @{ $MODULES } : $MODULES;
}

sub get_access_list # Given what access dn/group looking for, merges info from profiles.
{
  my ($self, $level, $module) = @_;
  my @profiles = $self->get("ACL_PROFILE");
  my @members = ();

  $level = uc("${module}_$level") if $module;

  foreach my $profile (@profiles)
  {
    my $name = $self->get("ACCESS_CONTROL{$profile}{$level}");
    push @members, $name if $name;
  }
  return @members if wantarray;
  return \@members;
}

sub get_treenames
{
  my ($self) = @_;
  my @treenames = $self->keys;
  @treenames = grep { $_ ne '_GLOBAL' } @treenames;
}

1;
