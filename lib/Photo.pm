package Photo;

use base "DMLDAP";

sub subclass_init
{
  return ("photo");
}

sub display
{
  my ($self) = @_;

  my $photo = $self->get("jpegPhoto");
  if (!$photo)
  {
    print "Content-type: text/plain\n\n";
    print "No image found.\n";
    exit;
  } 
  elsif ($photo =~ /^GIF/)
  {
    print "Content-Type: image/gif\n\n";
  } else {
    print "Content-Type: image/jpeg\n\n";
  }
  print $photo;
  exit;
}

1;

