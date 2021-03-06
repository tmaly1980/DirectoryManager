# This is CPAN.pm's systemwide configuration file. This file provides
# defaults for users, and the values can be changed in a per-user
# configuration file. The user-config file is being looked for as
# ~/.cpan/CPAN/MyConfig.pm.

eval "require '$ENV{HOME}/.cpan/CPAN/MyConfig.pm'";

my $BASEDIR = $::BASEDIR;

my %config = (
  'build_cache' => q[10],
  'build_dir' => "$ENV{HOME}/.cpan/build",
  'cache_metadata' => q[1],
  'cpan_home' => "$ENV{HOME}/.cpan",
  'dontload_hash' => {  },
  'ftp' => q[/usr/bin/ftp],
  'ftp_proxy' => q[],
  'getcwd' => q[cwd],
  'gzip' => q[/bin/gzip],
  'http_proxy' => q[],
  'inactivity_timeout' => q[0],
  'index_expire' => q[1],
  'inhibit_startup_message' => q[0],
  'keep_source_where' => "$ENV{HOME}/.cpan/sources",
  'links' => q[],
  'make' => q[/usr/bin/make],
  'make_arg' => q[],
  'make_install_arg' => q[],
  'makepl_arg' => ($::LOCAL_INSTALL ? " -- INSTALLSITEARCH=$BASEDIR/modules/lib INSTALLSITELIB=$BASEDIR/modules/lib INSTALLSITEMAN1DIR=$BASEDIR/modules/man/man1 INSTALLSITEMAN3DIR=$BASEDIR/modules/man/man3 --defaultdeps" : ""),
  'ncftpget' => q[/usr/bin/ncftpget],
  'no_proxy' => q[],
  'pager' => q[/usr/bin/less],
  'prerequisites_policy' => q[ask],
  'scan_cache' => q[atstart],
  'shell' => q[/bin/bash],
  'tar' => q[/bin/tar],
  'term_is_latin' => q[1],
  'unzip' => q[/usr/bin/unzip],
  'urllist' => [q[ftp://cpan.cs.utah.edu/pub/CPAN/]],
  'wait_list' => [q[wait://ls6-www.informatik.uni-dortmund.de:1404]],
  'wget' => q[/usr/bin/wget],
);

foreach my $key (keys %config)
{
 $CPAN::Config->{$key} = $config{$key} if not exists $CPAN::Config->{$key};
}


1;
__END__
