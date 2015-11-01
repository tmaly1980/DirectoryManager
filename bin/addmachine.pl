#!/usr/bin/perl
# Copyright 2004 Maly Soft, http://www.malysoft.com/
# No unauthorized use, distribution, or modification.
#

BEGIN { unshift @INC, "../modules/lib"; };
use Net::LDAP;
use Net::LDAP::Util;
use Data::Dumper;

# Standalone script to add machine accounts into an LDAP directory.

# Configuration options, please customize.
my $CONFIG =
{
  HOST=>"127.0.0.1", # Hostname/IP address of LDAP server
  START_TLS=>0, # 1 = Enabled, 0 or undef = Disabled
  BASE_DN=>"dc=malysoft,dc=com", # Base DN of server, parent node of account container
  OU=>"Machines", # Container for machine accounts.... Defaults to 'Machines'
  BIND_DN=>"cn=manager,dc=malysoft,dc=com", # DN to BIND as when connecting. Typically the Root DN
  BIND_PW=>"manager", # Password to send along with BIND_DN
  GID_NUMBER=>"219", # Group ID Number for machine trust accounts
  UID_NUMBER_START=>"10000",
};

# Don't touch below....

my $machine = $ARGV[0] || die("Usage: $0 <machine name>\n");

my $ldap = Net::LDAP->new($CONFIG->{HOST}, version=>3, timeout=>10);

die("Cannot connect to server: $@") unless $ldap;

if ($CONFIG->{START_TLS})
{
  my $tls=$ldap->start_tls();
  die("Cannot start_tls: ".$tls->error) if $tls->code;
}


$ldap->bind($CONFIG->{BIND_DN}, password=>$CONFIG->{BIND_PW});

my $dn = "uid=$machine,ou=".($CONFIG->{OU}||"Machines").",$CONFIG->{BASE_DN}";

# Make sure doesn't already exist. If so, just silently exit.
my $previous = $ldap->search(base=>$dn, scope=>"base", attrs=>['1.1'], filter=>'(objectClass=posixAccount)');
my $code = $previous->code;
die($previous->error) if ($code && $code != 32);

#$previous->code != 32 && die($previous->error);
# code = 32 means no such object, i.e. ok...
$previous->count && exit;

my $uidNumber = $CONFIG->{UID_NUMBER_START};

# Find next uidNumber available...
my $result = $ldap->search(base=>$CONFIG->{BASE_DN}, filter=>"(objectClass=posixAccount)", attrs=>["uidNumber"]);

$result->code && die($result->error);

foreach my $entry ($result->all_entries)
{
  my $entry_uidNumber = $entry->get_value("uidNumber");
  $uidNumber = $entry_uidNumber + 1 if $uidNumber < $entry_uidNumber;
}

my $entry =
[
  objectClass=>[qw(top person posixAccount)],
  uid=>$machine,
  cn=>"Machine Trust Account",
  sn=>"Account",
  homeDirectory=>"/tmp",
  loginShell=>"/bin/false",
  uidNumber=>$uidNumber,
  gidNumber=>$CONFIG->{GID_NUMBER},
];

$result = $ldap->add($dn, attr => $entry);

$result->code && die($result->error);

$ldap->unbind();

