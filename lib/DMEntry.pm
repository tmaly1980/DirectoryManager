package DMEntry;
# Generic wrapper to handle whatever sort of object requested, as determined by arg to new()

use lib "../MalyCGI";
use DMConfig;
use DMLDAP;
use MalyMail;

our $MAIL = MalyMail->new();

sub new
{
  my ($this, $oc) = @_;
  my $class = ref($this) || $this;
  my $oc_class = ucfirst($oc);

  my $object = eval { $oc_class->new() if require "$oc_class.pm" } || DMLDAP->new($oc);
  return $object;
}

1;
