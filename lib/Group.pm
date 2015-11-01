package Group;

use base "DMLDAP";
use User;
use Data::Dumper;

sub subclass_init
{
  return ("group");
}

sub set_filter
{
  my ($self) = @_;

  my %changes = ();

  my @oc = $self->get("OBJECTLCASS");
}

sub db2cgi
{
  my ($self) = @_;
  my %db2cgi = $self->SUPER::db2cgi();
  return
  (
    %db2cgi,


  );
}

sub sync
{
  my ($self, %hash) = @_;

  my $entry_type = $hash{ENTRY_TYPE}||$self->entry_type();
  my $samba =
    {
      unix=>'0',
      samba3=>'3',
    }->{$entry_type};
  my $treename = $self->{DBPARAMS}->[0];
  my $tree = $self->{GLOBAL}->{CONFIG}->get("TREES{$treename}");
  if ($samba eq '3')
  {
    $hash{SAMBAGROUPTYPE} = 2; # Domain group

    my $server_sid = $self->{GLOBAL}->{CONFIG}->get("SAMBA{SID}");

    if ($hash{GIDNUMBER} ne '')
    {
      $self->system_error("Cannot generate group SID, tree is not configured with a Server SID!") unless $server_sid;
      ($rid, $hash{DISPLAYNAME}) = $self->generateRID($hash{GIDNUMBER}, $hash{DESCRIPTION} || $hash{CN});
      $hash{SAMBASID} = "$server_sid-$rid";
    }
  }

  return %hash;
}


sub macro_value
{
  my ($self, $macro) = @_;
  my ($oc) = $self->get_schema;

  my $value = $self->get($macro); # Default to name of attribute.

  if ($macro eq 'gidNum' or $macro eq 'if_gidNum') # Used in groups
  {
    my $existing = $self->getold("gidNumber");
    if ($macro eq 'if_gidNum' and $existing =~ /^\d+$/)
    # Already set, no need to figure out.
    {
      return $existing;
    }

    my $groups = $self->new();
    $groups->search_cols(['gidNumber']);

    my $gidNumber_start = $self->{GLOBAL}->{CONFIG}->get("MODULES{group}{GIDNUMBER_START}") || '10000';
    my $gidNumber_end = $self->{GLOBAL}->{CONFIG}->get("MODULES{group}{GIDNUMBER_END}") || '19999';
    my $next_gidNumber = $gidNumber_start - 1;

    for($groups->first; $groups->more; $groups->next)
    {
      my $gidNumber = $groups->get("gidNumber");
      if ($gidNumber > $next_gidNumber and $gidNumber <= $gidNumber_end)
      # In range and higher than what we already got.
      {
        $next_gidNumber = $gidNumber;
      }
    }
    $value = $next_gidNumber+1;

    if ($next_gidNumber > $gidNumber_end)
    {
      $self->system_error("Unable to generate GID Number. None available in configured range.");
    }
  }
  
  return $value;
}

sub generateRID
{
  my ($self, $gidnumber, $displayname) = @_;
  # Need to actually do lookup
  $self = Group->search_cols('cn', gidNumber=>$gidnumber) if not ref $self;
  my $cn = $self->get("CN");

  # SAMBAADM, SAMBADOMADM, SAMBADOMUSERS, SAMBADOMGUEST, SAMBAGUEST
  if ($cn ne '' and $cn eq $self->{GLOBAL}->{CONFIG}->get("SAMBA{DOMADM}"))
  {
    return 512 if not wantarray;
    return (512, "Domain Admins"); # Domain admins
  } 
  elsif ($cn ne '' and $cn eq $self->{GLOBAL}->{CONFIG}->get("SAMBA{DOMUSERS}"))
  {
    return 513 if not wantarray;
    return (513, "Domain Users"); # Domain users
  }
  elsif ($cn ne '' and $cn eq $self->{GLOBAL}->{CONFIG}->get("SAMBA{DOMGUEST}"))
  {
    return 514 if not wantarray;
    return (514, "Domain Guests"); # Domain guests
  } else {
    return 1001+2*$gidnumber if not wantarray;
    return (1001+2*$gidnumber, $displayname);
  }
}

1;
