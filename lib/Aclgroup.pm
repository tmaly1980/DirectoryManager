package Aclgroup;

use base "DMLDAP";
use Data::Dumper;

sub subclass_init
{
  return ("aclgroup");
}

sub sync
{
  my ($self, %hash) = @_;
  my $members = $hash{MEMBER};
  my @members = ref $members eq 'ARRAY' ? @$members : ();
  @members = ($members) if not @members and $members;
  my $basedn = $self->{GLOBAL}->{CONFIG}->oc_basedn('user');

  my @real_members = ();
  foreach my $member (@members)
  {
    if ($member !~ /^uid=/) # Relative!
    {
      $member = "uid=$member,$basedn";
    } elsif ($member !~ /,/) {
      $member = "$member,$basedn";
    } elsif ($member !~ /$basedn$/i) {
      $self->user_error("Sorry, members must exist under '$basedn' DN. Member '$member' not allowed.");
    }
    push @real_members, $member;
  }
  print STDERR "WAS ($members)=".Dumper(\@members);
  print STDERR "REAL=".Dumper(\@real_members);
  $hash{MEMBER} = \@real_members;

  return %hash;
}

1;

