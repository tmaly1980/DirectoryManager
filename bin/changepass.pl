#!/usr/bin/perl
# Copyright 2004 Maly Soft, http://www.malysoft.com/
# No unauthorized use, distribution, or modification.
#

BEGIN { unshift @INC, "../modules/lib"; };
use Net::LDAP;
use Digest::SHA1;
use MIME::Base64;

# Standalone script to change a user's password (i.e. userPassword) in an LDAP directory.
# Note that Samba 3.x has built-in support for this already -- this script is not necessary.

# Configuration options, please customize.
my $CONFIG =
{
  HOST=>"127.0.0.1", # Hostname/IP address of LDAP server
  START_TLS=>1, # 1 = Enabled, 0 or undef = Disabled
  BASE_DN=>"dc=malysoft,dc=com", # Base DN of server, parent node of account container
  BIND_DN=>"cn=manager,dc=malysoft,dc=com", # DN to BIND as when connecting. Typically the Root DN
  BIND_PW=>"manager", # Password to send along with BIND_DN
  GID_NUMBER=>"219", # Group ID Number for machine trust accounts
  UID_NUMBER_START=>"10000",
};

# Don't touch below....

my $username = $ARGV[0] || die("Usage: $0 <username>\n");

my $ldap = Net::LDAP->new($CONFIG->{HOST}, version=>3, timeout=>10);

die("Cannot connect to server: $@") unless $ldap;

$ldap->start_tls() if $CONFIG->{START_TLS};

$ldap->bind($CONFIG->{BIND_DN}, password=>$CONFIG->{BIND_PW});

my $dn = "uid=$username,ou=People,$CONFIG->{BASE_DN}";

# Make sure exists. Otherwise, exit.
my $result = $ldap->search(base=>$dn, scope=>"base", attrs=>['1.1'], filter=>'(objectClass=posixAccount)');
$result->code && die($result->error);

# NOW, ask for password, twice.

# Turn off terminal.
system("stty -echo");

print "Password: ";
my $p1 = <STDIN>;
chomp $p1;
print "\n";
print "Password Again: ";
my $p2 = <STDIN>;
chomp $p2;
print "\n";

system("stty echo");

die("Password too short") unless length($p1) >= 4;
die("Passwords do not match") unless $p1 eq $p2;

# Generate, using SHA1
my $hash = Digest::SHA1->new()->add($p1)->digest();
my $b64hash = encode_base64($hash, "");
my $userPassword = "{SHA}$b64hash";

my $entry = $result->entry(0);

$entry->replace('userPassword'=>$userPassword);
my $rc = $entry->update($ldap);

$rc->code && die($rc->error);

print "Password changed\n";
