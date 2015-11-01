package Address;

use base "DMLDAP";
use Net::LDAP;
use Data::Dumper;
use Group;
use Digest::SHA1; # userPassword generation
use MIME::Base64; # userPassword generation

sub subclass_init
{
  return ("address", "cn");
}

sub db2cgi
{
  my ($self) = @_;
  my %db2cgi = $self->SUPER::db2cgi();
  my ($oc) = $self->get_schema();
  my $tree = $self->{DBPARAMS}->[0];
  my $pri_key = $self->{GLOBAL}->{CLASSES}->{$oc}->{PRIMARY_KEY};

  return
  (
    %db2cgi,
    PHOTO_URL=>"cgi-bin/View.pl/$tree/photo/$pri_key=#$pri_key#",
  );
}

sub changed_password
{
  my ($self) = @_;
  ($self->getold("userPassword") ne $self->getnew("userPassword") and $self->getnew("userPassword"));
}

sub assertPassword
{
  my ($self, $p1, $p2) = @_;

  $p2 = $p1 if (@_ == 2); # Default, IF PARAMETER NOT PASSED, RATHER THAN UNDEF

  my $current_password = $self->getold("userPassword");

  # Will allow not setting password! For fake system accounts

  if ( ($p1 or $p2) and $p1 ne $p2)
  {
    $self->user_error("Passwords do not match.");
  } 
  elsif ($p1 and length $p1 < 4)
  {
    $self->user_error("Passwords must be 4 or more characters.");
  }
  elsif ($p1) # and $p1 eq $p2)
  {
    # Generate userPassword (SHA1)
    my $hash = Digest::SHA1->new()->add($p1)->digest();
    my $b64hash = encode_base64($hash, "");
    return "{SHA}$b64hash";
  }
  return undef;
}

sub sync  # Returns any information if its different from what it gets. Will not erase destincation data if the source data is not found.
{
  my ($self, %changes) = @_;
  my ($oc) = $self->get_schema();

  my @samba2attrs = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"SAMBA2ATTRS"});
  my @samba3attrs = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"SAMBA3ATTRS"});
  my %samba32map = $self->struct_get($self->{GLOBAL}->{CLASSES}->{$oc}->{"SAMBA23MAP"});
  my %samba23map = reverse %samba32map;

  #### CHECK PASSWORD ####
  #
  #

  if ($changes{USERPASSWORD1} || $changes{USERPASSWORD2})
  {
    $changes{USERPASSWORD} = $self->assertPassword($changes{USERPASSWORD1}, $changes{USERPASSWORD2});
  }
  # only erase if mentioned in CGI>!
  #### END PASSWORD ####




  #### JPEGPHOTO ####
  my $photo_meta = $changes{_UPLOAD}->{jpegPhoto_file};
  if ($photo_meta)
  {
    my $photo = $photo_meta->{data};
    my $info = $photo_meta->{info};
    if ($info)
    {
      my $type = $info->{'Content-Type'};
      $self->user_error("Invalid image type '$type'. Only JPEG/GIF allowed.") unless 
        ($type eq 'image/jpeg' or $type eq 'image/pjpeg' or $type eq 'image/gif');

      $changes{JPEGPHOTO} = $photo;
    }
  }

  # Removing jpeg.
  if ($changes{JPEGPHOTO_DELETE})
  {
    $changes{JPEGPHOTO} = undef;
  }

  #### END JPEGPHOTO ####


  #### MANAGER ####
  # Search by name if not in uid= format
  my @managers = ref $changes{MANAGER} eq 'ARRAY' ? @{ $changes{MANAGER} } : ($changes{MANAGER} || ());
  if (@managers)
  {
    my @manager_dn = ();
    foreach my $manager (@managers)
    {
      if ($manager =~ /^uid=/i)
      {
        push @manager_dn, $manager;
      } else {
        my $manager_dbo = User->search(["(|(uid=$manager)(cn=*$manager*))"]);
        if (not $manager_dbo->count)
        {
          $self->user_error("No such person '$manager'");
	} elsif ($manager_dbo->count > 1) {
	  my @mgr_text = ();
	  for($manager_dbo->first; $manager_dbo->more; $manager_dbo->next)
	  {
	    push @mgr_text, $manager_dbo->get("CN") . " (" . $manager_dbo->get("DN") . ")";
	  }
	  $self->user_error("Too many people containing '$manager' in name: <br>".
	    join("<br>\n", @mgr_text)
	  );
        } else {
          push @manager_dn, $manager_dbo->get("DN");
        }
      }
    }
    $changes{MANAGER} = \@manager_dn;
  }

  #### END MANAGER ####

  return %changes;
}

sub import
{
  my ($self, %hash) = @_;
  $self->SUPER::set(%hash);
}

sub macro_value
{
  my ($self, $macro) = @_;

  my ($oc) = $self->get_schema;

  my $value = $self->get($macro); # Default to name of attribute.
  # Other custom ones below:
  my $cn = $self->get("cn");
  my @cn = split(/\s+/, $cn);
  if ($macro eq 'ln') { $value = lc($cn[$#cn]); }
  elsif ($macro eq 'Ln') { $value = ucfirst(lc($cn[$#cn])); }
  elsif ($macro eq 'LN') { $value = uc($cn[$#cn]); }
  elsif ($macro eq 'li') { $value = lc(substr($cn[$#cn], 0, 1)); }
  elsif ($macro eq 'Li') { $value = uc(substr($cn[$#cn], 0, 1)); }

  elsif ($macro eq 'fi') { $value = lc(substr($cn[0], 0, 1)); }
  elsif ($macro eq 'Fi') { $value = uc(substr($cn[0], 0, 1)); }
  elsif ($macro eq 'Fn') { $value = ucfirst(lc($cn[0])); }
  elsif ($macro eq 'FN') { $value = uc($cn[0]); }
  elsif ($macro eq 'fn') { $value = lc($cn[0]); }
  elsif ($macro eq 'random_userPassword')
  {
    my @chars = ('a'..'z', 'A'..'Z', 0..9, 'a'..'z', 'A'..'Z');
    my @genpass = map { $chars[rand(scalar @chars)] } (0..7);
    my $genpass = join("", @genpass);
    $self->{USERPASSWORD_RANDOM} = $genpass;
    $value = $self->assertPassword($genpass, $genpass);
    # in post_insert(), notification will go out as to password.
    # Now, make sure that the involved parties find out about the password.
  }
  elsif ($macro eq 'company_domain')
  {
    my $company = $self->get("o");
    $self->user_error("Company required.") unless $company;
    my %domain_map = $self->{GLOBAL}->{CONFIG}->get("DOMAIN_MAP");
    my $domain = $domain_map{$company};
    $self->internal_error("Invalid company (must be predefined in configuration)!") unless $domain;
    $value = $domain;
    print STDERR "CJECKING FOR COMPANY_DOMAIN, COMP=$company, DOM=".Dumper(\%domain_map)."\n";
  }
  return $value;
}
1;
