#!/usr/bin/perl

# Sorry, please don't run, this is not yet fully implemented.

unshift @INC, ".";
use CPAN;
use CPAN::FirstTime;
use Text::Wrap qw();
use POSIX qw();
use File::Basename qw();

my $force_install = 1;
$::BASEDIR = File::Basename::dirname(POSIX::getcwd());

my @prereqs = 
(
  "HTML::Tagset"=>'3.03',
  "HTML::Parser"=>'3.26',
  "Net::SSLeay"=>'1.25',
  "IO::Socket::SSL"=>'0.96',
  "HTTP::Daemon::SSL"=>'1.02',
  "Convert::ASN1"=>'0.16',
  "Digest::MD5"=>'2.20',
  "Net::LDAP"=>'0.32',
  "Digest::base"=>'1.00',
  "Digest::SHA1"=>'2.10',
  "Crypt::SmbHash"=>'0.12',
  "URI"=>'1.21',
  "Compress::Zlib"=>'1.10',
  "LWP::UserAgent"=>'2.001',
);

my %version = @prereqs;
my $k = 0; my @prereq_names = grep { $k++ % 2 == 0 } @prereqs;

my %args = map { @x=split(/=/, $_); ($x[0],$x[1]||1) } @ARGV;

$::LOCAL_INSTALL = 1 if $args{"local"};

printw("This script will help you get your prerequisite modules verified and/or installed. Please answer the following questions:\n\n");

if ($> ne '0' and not $::LOCAL_INSTALL)
{
  my $ok = prompt("You appear to not be root. Modules will install locally to the 'modules/' directory instead. Do you wish to continue (y or n)");
  exit if not $ok;
  $::LOCAL_INSTALL = 1;
} elsif ($> eq '0') {
  my $globalinstall = prompt("Do you wish to install these modules globally to your system (typically under /usr/lib/perl5)? If not, they will install under the local '../modules' directory. ");
  $::LOCAL_INSTALL = 1 if not $globalinstall;
}

if ($::LOCAL_INSTALL)
{
  printw("Installing modules locally to ../modules\n\n");
  unshift @INC, "$::BASEDIR/modules/lib";
  $ENV{PERL5LIB} = "$::BASEDIR/modules/lib";
} else {
  printw("Installing modules into system-wide location\n\n");
}

require CPAN::Config; # Load file we've got...

my $homedir = prompt("Is this server your Home Directory Server (i.e. will recieve requests from Directory Manager regarding automatic home directory creation when users get added)");

my $dmserver = undef;

if ($homedir)
{
  unless (my $dmserver = prompt("Is this server your Directory Manager web server"))
  {
    @prereq_names = grep { $_ =~ /SSL/ } @prereq_names;
  }
} else {
  @prereq_names = grep { $_ !~ /HTTP::Daemon::SSL/ } @prereq_names;
}

my $ssl = prompt("Do you wish to use SSL/TLS encyption between Directory Manager and OpenLDAP for better security (HIGHLY recommended)");

@prereq_names = grep { $_ !~ /SSL/ } @prereq_names unless $ssl;

printw("Starting installation... You may be asked to specify CPAN settings for these modules.\n");

my $auto = prompt("Do you wish to automatically compile all required modules (versus being prompted)");

my $reconfigcpan = prompt("Do you wish to FORCE reconfiguring CPAN (recommended if installation fails)");

if ($reconfigcpan)
{
  CPAN::FirstTime->init();
}

my @notinstalled = ();

print "\n";

foreach my $modname (@prereq_names)
{
  printw("\nChecking for $modname, version $version{$modname} or later... ");

  my $found = eval "require $modname";
  my $oldversion = eval "\$${modname}::VERSION";
  my $uptodate = ($oldversion >= $version{$modname});
  if (!$found or !$uptodate)
  {
    !$found ? printw(" Not found!\n") : printw(" Too old (You have '$oldversion')!\n");
    if ($auto or prompt("Do you wish to install at this time"))
    {
      # Do individual module thing here...
      my $mod = CPAN::Shell->expand("Module","$modname");
      if ($mod and $mod->uptodate and !$force_install)
      {
        printw(" Already up-to-date, no need to install...\n");
      }
      elsif ($mod)
      {
        printw("Installing.... \n");
        CPAN::Queue->new($mod->id);
        CPAN::Shell->force('install') if $force_install;
        CPAN::Shell->install();
	unless(eval "require $modname")
	{
	  printw(" INSTALLATION FAILED!\n");
	  push @notinstalled, $modname 
	} else {
	  printw(" Installation Succeeded!\n");
	}
      } else {
        printw("Uh oh, unable to find module $modname. Skipping!\n");
	push @notinstalled, $modname;
      }
    } else {
      printw(" Not installing.... \n");
      push @notinstalled, $modname;
    }
  } else {
    printw(" Found!\n");
  }
}

if (@notinstalled)
{
  printw(" Looks like some modules weren't installed.... They were:\n");
  map { printw("$_\n") } @notinstalled;
}




################################################

sub prompt
{
  my ($text) = @_;

  my $response = undef;
  do
  {
    printw("$text (y or n)? ");
    $response = <STDIN>;
    chomp($response);
    return if ($response =~ /^(n|no)$/i);
  } while ($response !~ /^(y|yes)$/i); # ???
  return $response;
}

sub printw
{
  my ($text) = @_;
  $Text::Wrap::columns = 80;
  my @content = ();
  while ($text =~ /(\n+)/)
  {
    my $wrap = Text::Wrap::wrap('','',$`);
    push @content, $wrap, $1;
    $text = $';
  }
  push @content, Text::Wrap::wrap('','',$text);

  print join("", @content);
}

