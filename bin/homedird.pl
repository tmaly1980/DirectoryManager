#!/usr/bin/perl

# Home Directory Creation Daemon.
# RUN AS ROOT, Default port 3890.
#
# Parameters (optional):
# -x (Run once, i.e. from inetd, then exit)

my $port = "3890";
my $USER = "admin";
my $USE_SSL = 1;
my $CERT_FILE = "/etc/openldap/server.cert"; # REQUIRED IF USE_SSL=1
my $KEY_FILE = "/etc/openldap/server.key"; # REQUIRED IF USE_SSL=1
my $CA_FILE = ""; # OPTIONAL
my $PASS = "r3w7"; # PASSWORD, required.
my @commands = (
  "cp -R /etc/skel /home/%u",
  "chown -R %u:%g /home/%u",
);

# XXX TODO
# NEED TO IMPLEMENT BASIC AUTH FOR PASSWORD BEING SENT!!!!
# Allow ASSERT, just return OK if dirs already exist and OK.
# Die if info not quite right (wrong owner)...

BEGIN { unshift @INC, "../modules/lib"; };
use HTTP::Status;
use URI::Escape;
use Data::Dumper;
use IPC::Open3;
use IO::Select;
use MIME::Base64;

my @opts = @ARGV;
my %opts = ();

for (my $i = 0; $i < @opts; $i++)
{
  my ($key, $value) = split(/=/, $opts[$i]);
  $value = 1 if $opts[$i] !~ /=/; # No value passed, assume 1
  $key =~ s/^-{1,2}//g; # Get rid of leading -'s
  $opts{$key} = $value;
}

my $d = undef;
if ($USE_SSL)
{
  $d = HTTP::Daemon::SSL->new(LocalPort=>$port, ReuseAddr=>1, SSL_key_file=>$KEY_FILE, SSL_cert_file=>$CERT_FILE, SSL_ca_file=>$CA_FILE) || die("Cannot listen on port $port");
} else {
  $d = HTTP::Daemon->new(LocalPort=>$port, ReuseAddr=>1) || die("Cannot listen on port $port");
}

while (my $c = $d->accept)
{
  while (my $r = $c->get_request)
  {
    # Check authentication....
    my $headers = $r->headers();
    my $authenticated = undef;
    my $authheader = $r->header('Authorization');
    my ($authencoded) = $authheader =~ /Basic\s+(.+)/;
    my $authdecoded = decode_base64($authencoded);
    my ($user, $pass) = split(":", $authdecoded);

    my $crypt_match = ($pass and $pass eq $PASS);
    #crypt($pass, $CRYPT_PASS) eq $CRYPT_PASS);
    print STDERR "CRYPT=".$crypt_match."\n";
    print STDERR "USER=$user, PASS=$pass, AUTHDEC=$authdecoded\n";
    my $authenticated = ($user eq $USER and $pass and $crypt_match);

    print STDERR "GOT HEADERS=".$headers->as_string."\n";

    if (not $authenticated)
    {
      my $response = HTTP::Response->new(401, "Authorization Required", undef, "Unauthorized");
      $response->push_header("WWW-Authenticate", 'Basic realm="Admin"');
      $c->send_response($response);
    } 
    elsif ($r->method eq 'POST')
    {
      # Read form.
      my $content = $r->content;
      my @parts = split(/[&]/, $content);
      my %query = map { (split(/=/, $_, 2)) } @parts;
      %query = map { (uc($_), uri_unescape($query{$_})) } keys %query;
      print STDERR "QUERY=".Dumper(\%query)."\n";

      if (not $query{UID} or not $query{DIR} or not $query{GID})
      {
	$c->send_response(HTTP::Response->new(500, "Internal Server Error", undef,
	  "Must specify ALL parameters (UID, GID, DIR)"));
      }
      elsif (-d $query{DIR}) # Already exists.
      {
        my @stat = stat($query{DIR});
	my @duser = getpwuid($stat[4]);
	my @dgroup = getgrgid($stat[5]);
	my $duser = $duser[0];
	my $dgroup = $dgroup[0];
	if ($duser eq $query{UID} and $dgroup eq $query{GID}) 
	# ok perms/ownership
        {
          $c->send_response(HTTP::Response->new(200, "OK", undef, "Directory Created"));
        }
        else # Wrong ownership
        {
          $c->send_response(HTTP::Response->new(500, "Internal Server Error", undef, "Directory exists but has wrong owner/group"));
	}
      }
      elsif (not @commands)
      {
	$c->send_response(HTTP::Response->new(500, "Internal Server Error", undef,
	  "No commands specified in script"));
      } else {
        for (my $i = 0; $i < @commands; $i++)
	{
	  my $command = $commands[$i];
	  $command =~ s/%u/$query{UID}/g;
	  $command =~ s/%g/$query{GID}/g;
	  #$command =~ s/%d/$query{DIR}/g;
	  # Really, no reason to implement. I.e. master root dir may be different
	  # (i.e. if using automount)

	  my $pid = open3(\*IN, \*OUT, \*ERR, $command);
	  my $sel = IO::Select->new();
	  $sel->add(\*ERR);

	  my $error = undef;

	  if (my ($errh) = $sel->can_read(1))
	  {
	    $error = <$errh>;
	  }

	  waitpid($pid,0);

	  $c->send_response(HTTP::Response->new(500, "Internal Server Error", undef,
	    "Error running command '$command': $error")) if $error;
	}
      }
      $c->send_response(HTTP::Response->new(200, "OK", undef, "Directory Created"));
      $c->close();
    }
  }
  exit if $args{x}; # Run once.
}
