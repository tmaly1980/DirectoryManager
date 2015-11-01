#!/usr/bin/perl

# Redirect to browse page

my $page = Index->new(PATH_INFO_KEYS=>[qw(tree)]);

package Index;
use lib "../lib";
use base "DMCGI";

sub process
{
  my ($self) = @_;
  $self->redirect("cgi-bin/Search.pl");
}
