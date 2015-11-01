#!/usr/bin/perl

# Redirect to browse page

my $page = ACLGroupCGI->new({SESSION_DEBUG=>0});

package ACLGroupCGI;
use lib "../lib";
use base "DMCGI";

sub process
{
  my ($self) = @_;
  my $auth_tree = $self->{GLOBAL}->{CONFIG}->get("AUTH_TREE");
  $self->set_path_info("tree", $auth_tree);
  $self->system_error("No Authentication Tree Configured.") unless $auth_tree;
  $self->login_page("Further Authorization Required") unless $self->{GLOBAL}->{CONFIG}->has_admin_access($auth_tree, 'aclgroup');
  $self->redirect("cgi-bin/Search.pl/$auth_tree/aclgroup");
}
