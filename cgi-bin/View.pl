#!/usr/bin/perl

my $page = View->new({form=>0,title=>"DirectoryManager View Entry",PATH_INFO_KEYS=>[qw/tree class filter/]});

package View;
use lib "../lib";
use base "DMCGI";
use DMLDAP;
use DMEntry;
#use User;
#use Group;
#use Photo;

sub process
{
  my ($self, $action) = @_;
  $self->set_path_info_default("class", "user");
  my $oc = $self->get_path_info("class");
  my $filter = $self->get_path_info("filter");
  my $mode = $self->{GLOBAL}->{MODE}; # From URL.

  my $ldap = DMEntry->new($oc);

  if ($oc eq 'photo')
  {
    if (not $filter or $filter =~ /=$/ or $filter =~ /^=/)
    {
      print "Content-type: text/plain\n\n";
      print "No user specified.\n";
      exit;
    }

    $ldap->search_cols(['jpegPhoto'], filter=>$filter);
    $self->user_error("No user (image) found.") unless $ldap->count;
    $ldap->display();
  }

  $self->user_error("No entry filter specified.") unless $filter;
  my @columns = $ldap->filter_columns();
  my $prikey = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};
  $ldap->search_cols([@columns, $prikey], filter=>$filter);
  $self->user_error("No entry found.") unless $ldap->count;
  my %oc_spec = ref $self->{GLOBAL}->{CLASSES}->{$oc} eq 'HASH' ?
    %{ $self->{GLOBAL}->{CLASSES}->{$oc} } : ();

  $self->template_display("view", MODE=>$mode, ENTRY=>$ldap->hashref, %oc_spec);
}

1;
