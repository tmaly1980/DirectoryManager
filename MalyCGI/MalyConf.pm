package MalyConf;
# Handles I/O of configuration files (perl data structs)

use MalyVar;
use Data::Dumper;

our $ERROR = undef;

sub new # We MAY be writing to a file for the first time!
{
  my ($this, $src, $required) = @_;
  # $required = die on fatal file loading....
  my $class = ref($this) || $this;
  my $self = bless {DATA=>{}}, $class;

  # We can span multiple files and merge it in memory, then dump back to the original files
  $self->{SRC} = $src;
  $self->{MULTIFILE} = $src =~ m{/$};

  if ($self->{MULTIFILE}) # Directory with multiple files. File prefixes = hash keys.
  {
    my @files = <$src/*.conf>;
    for (my $i = 0; $i < @files; $i++)
    {
      my ($prefix) = $files[$i] =~ m{(\w+)[.]conf$};
      my $content = do $files[$i];
      if ($required)
      {
        die ("Unable to load $files[$i]: $@/$!") if not $content;
        die ("Unable to load $files[$i]: NOT a HASH reference!") if ref $content ne 'HASH';
      }
      $self->{DATA}->{$prefix} = $content;
    }
  } else {
    my $content = do $src;
    $self->{DATA} = $content;
    if ($required)
    {
      die ("Unable to load $src: $@/$!") if not $content;
      die ("Unable to load $src: NOT a HASH reference!") if ref $content ne 'HASH';
    }
  }

  $Data::Dumper::Maxdepth =50;
  #print STDERR "SETTING DATA TO=".Data::Dumper::Dumper($self->{DATA})."\n";

  return $self;
}

sub get
{
  my ($self, @args) = @_;
  $self->prefix_get($self->{PREFIX}, @args);
}

sub prefix_get 
{
  my ($self, $prefix, @args) = @_;
  if (not @args) # Get merged?
  {
    return $self->hash if wantarray;
    return $self->ref if defined wantarray;
  }

  my @values = ();
  if (@args == 1)
  {
    my $value = undef;
    my @prefices = ref $prefix eq 'ARRAY' ? @$prefix : ($prefix?($prefix):());
    if (@prefices)
    {
      foreach my $eachpref (@prefices)
      {
        $value = MalyVar->var_evaluate($self->{DATA}->{$eachpref}, $args[0]) ;
	last if defined($value);
      }
    } else {
      $value = MalyVar->var_evaluate($self->{DATA}, $args[0]);
    }
    if (wantarray and ref $value)
    {
      return %$value if ref $value eq 'HASH';
      return @$value if ref $value eq 'ARRAY';
    }
    if (wantarray)
    {
      return $value ? ($value) : ();
    } else {
      return $value;
    }
  } else {
    foreach my $arg (@args)
    {
      my $value = undef;
      my @prefices = ref $prefix eq 'ARRAY' ? @$prefix : ($prefix?($prefix):());
      if (@prefices)
      {
        foreach my $eachpref (@prefices)
        {
          $value = MalyVar->var_evaluate($self->{DATA}->{$eachpref}, $args[0]) ;
	  last if defined($value);
        }
      } else {
        $value = MalyVar->var_evaluate($self->{DATA}, $args[0]);
      }
      push @values, $value;
    }
    return @values if wantarray;
    return \@values if defined wantarray;
  }
}

sub keys
{
  my ($self) = @_;
  my @keys = ref $self->{DATA} eq 'HASH' ? keys %{ $self->{DATA} } : ();
  return @keys if wantarray;
  return \@keys if defined wantarray;
}

sub recursive_undef_delete_hash # For subvalues in complex struct, not first level....
{
  my (%in) = @_;
  my %out = ();
  foreach my $key (keys %in)
  {
    my $v = $in{$key};
    if (ref $v eq 'HASH')
    {
      $v = { recursive_undef_delete_hash(%$v) };
    } elsif (ref $v eq 'ARRAY') {
      $v = [ recursive_undef_delete_array(@$v) ];
    } elsif (ref $v eq 'SCALAR') { # Dunno...
      next if not defined($$v);
    } else { # value
      next if not defined($in{$key});
    }
    $out{$key} = $v;
  }
  return %out;
}

sub recursive_undef_delete_array
{
  my (@in) = @_;
  my @out = ();
  for (my $i = 0; $i < @in; $i++)
  {
    my $v = $in[$i];
    if (ref $v eq 'HASH')
    {
      $v = { recursive_undef_delete_hash(%$v) };
    } elsif (ref $v eq 'ARRAY') {
      $v = [ recursive_undef_delete_array(@$v) ];
    } elsif (ref $v eq 'SCALAR') { # Dunno...
      next if not defined($$v);
    } else { # value
      next if not defined($v);
    }
    push @out, $v;
  }
  return @out;
}

sub set
{
  my ($self, %hash) = @_;
  $self->prefix_set($self->{PREFIX}, %hash);
}

sub prefix_set # If keys in hash does not start with $self->{KEY}, put it there!
{
  my ($self, $prefix, %hash) = @_;
  # If $prefix specified, will set to last value in list.
  $prefix = $prefix->[0] if (ref $prefix eq 'ARRAY');

  if ($self->{UNDEF_DELETE})
  {
    #%hash = recursive_undef_delete_hash(%hash);
    # The malyvar structupdateundefdelete SHOULD
    # take care of things properly.

    if ($prefix)
    {
      $self->{DATA}->{$prefix} ||= {};
      MalyVar->struct_update_undef_delete($self->{DATA}->{$prefix}, undef, %hash);
    } else {
      MalyVar->struct_update_undef_delete($self->{DATA}, undef, %hash);
    }
  } else {
    if ($prefix)
    {
      $self->{DATA}->{$prefix} ||= {};
      MalyVar->struct_update($self->{DATA}->{$prefix}, undef, %hash);
    } else {
      MalyVar->struct_update($self->{DATA}, undef, %hash);
    }
  }
}

sub merge # Returns a hashref of more than one hashrefs....
{
  my ($self, @hashrefs) = @_;
  my %hash = ();
  for (my $i = 0; $i < @hashrefs; $i++)
  {
    my $hr = $hashrefs[$i];
    next unless ref $hr eq 'HASH';
    my %dh = %$hr;
    append_hash(\%hash, %dh);
  }
  return \%hash if defined wantarray;
  return %hash if wantarray;
}

sub deref_hash
{
  my (%in) = @_;
  my %out = ();
  foreach my $key (keys %in)
  {
    if (ref $in{$key} eq 'HASH')
    {
      my %derefed_hash = deref_hash(%{ $in{$key} });
      $out{$key} = \%derefed_hash;
    } elsif (ref $in{$key} eq 'ARRAY') {
      my @derefed_array = deref_array(@{ $in{$key} });
      $out{$key} = \@derefed_array;
    } elsif (ref $in{$key} eq 'SCALAR') {
      my $derefed_scalar = ${$in{$key}};
      $out{$key} = \$derefed_scalar;
    } else {
      $out{$key} = $in{$key};
    }
  }
  return %out;
}

sub deref_array
{
  my (@in) = @_;
  my @out = ();
  for(my $i = 0; $i < @in; $i++)
  {
    if (ref $in[$i] eq 'HASH')
    {
      my %derefed_hash = deref_hash(%{ $in[$i] });
      $out[$i] = \%derefed_hash;
    } elsif (ref $in[$i] eq 'ARRAY') {
      my @derefed_array = deref_array(@{ $in[$i] });
      $out[$i] = \@derefed_array;
    } elsif (ref $in[$i] eq 'SCALAR') {
      my $derefed_scalar = ${$in[$i]};
      $out[$i] = \$derefed_scalar;
    } else {
      $out[$i] = $in[$i];
    }

  }
  return @out;
}

sub append_hash
{
  my ($ref, %in) = @_;
  my %hash = deref_hash(%in);
  foreach my $key (keys %hash)
  {
    # References need to be dereferenced ENTIRELY, not just one level.
    if (ref $hash{$key} eq 'HASH')
    {
      if (exists $ref->{$key}) # Just what is different.
      {
        my $subref = ref $ref->{$key} eq 'HASH' ? $ref->{$key} : {};
        append_hash($subref, %{ $hash{$key} });
        $ref->{$key} = $subref;
      } else {
        $ref->{$key} = $hash{$key};
      }
    } else {
      $ref->{$key} = $hash{$key};
    }
  }
  return $ref if defined wantarray;
}

sub ref { my ($self, @args) = @_; $self->hashref(@args); }

sub hashref # Removes key, returns structure reference
{
  my ($self, $key) = @_;
  if (@_ < 2) # Not passed, take current one.
  {
    $key = $self->{PREFIX};
  } # Else, if passed key, give that. Otherwise, want base.

  if ($key)
  {
    if (ref $key eq "ARRAY")
    {
      my @data = reverse map { $self->{DATA}->{$_} } @$key;
      return $self->merge(@data);
      # First item is master, last is default. must reverse, as merge does other.
    } else {
      return $self->{DATA}->{$key};
    }
  } else {
    return $self->{DATA};
  }
}

sub hash { my ($self) = @_; $self->list; }

sub list # Removes key, returns as list (whether array or hash)
{ 
  my ($self) = @_;
  my $r = $self->ref;
  return %$r if ref $r eq 'HASH';
  return @$r if ref $r eq 'ARRAY';
  return $r; # Otherwise, i.e. scalar
}

sub save # Write ENTIRE struct to file(s)
{
  my ($self) = @_;
  if ($self->{MULTIFILE})
  {
    my @keys = ref $self->{DATA} eq 'HASH' ? keys %{$self->{DATA}} : ();
    foreach my $key (@keys)
    {
      if (not $self->{DATA}->{$key})
      {
        $self->delete($key);
        next;
      } else {
        $self->write("$self->{SRC}/$key.conf", $self->{DATA}->{$key});
      }
    }
  } else {
    $self->write($self->{SRC}, $self->{DATA});
  }
}

sub delete
{
  my ($self, $prefix) = @_;
  delete $self->{DATA}->{$prefix};
  unlink("$self->{SRC}/$prefix.conf");
}

sub write # Write a single struct to a single file
{
  my ($self, $protected, $prefix) = @_;

  $prefix ||= $self->{PREFIX} if @_ < 3;
  # To avoid $self->{PREFIX}, pass 'undef'. Otherwise, will default to PREFIX.
  my $struct = undef;
  my $file = undef;

  if ($prefix)
  {
    if (ref $prefix eq 'ARRAY')
    {
      $struct ||= $self->{DATA}->{$prefix->[0]};
      $file ||= "$self->{SRC}/$prefix->[0].conf";
    } else {
      $struct ||= $self->{DATA}->{$prefix};
      $file ||= "$self->{SRC}/$prefix.conf";
    }
  } else {
    $struct ||= $self->{DATA};
    $file ||= $self->{SRC};
  }



  # Make sure all parent directories exist
  my @parts = split("/", $file);
  my @dirs = map { join("/", @parts[0..$_]) } (0..$#parts-1);
  map { mkdir($_) unless -e $_ } @dirs;


  if (open(F, ">$file"))
  {
    $Data::Dumper::Terse = 1;
    $Data::Dumper::Purity = 1;
    $Data::Dumper::Deepcopy = 1;
    $Data::Dumper::Maxdepth = undef;
    print F Data::Dumper->Dump([$struct]);
    close(F);
    chmod(0660, $file) if $protected;
    return 0;
  } else {
    $ERROR = "Unable to save file '$file': $!";
print STDERR "UNABLE TO SAVE=$ERROR\n";
    return $ERROR;
  }
}

sub write_protected
{
 my ($self, $prefix) = @_;
 $prefix ||= $self->{PREFIX} if @_ < 2;
 my $error = $self->write(1, $prefix);
 return $error;
}

sub rename # Renames file
{
  my ($self, $newname) = @_;
  my $oldname = $self->{SRC};
  if ($self->{PREFIX}) # Just one file within dir...
  {
    $oldname = ref $self->{PREFIX} eq 'ARRAY' ? $self->{PREFIX}->[0] : $self->{PREFIX};
    $self->{DATA}->{$newname} = $self->{DATA}->{$oldname};
    delete $self->{DATA}->{$oldname};
    if (ref $self->{PREFIX} eq 'ARRAY')
    {
      $self->{PREFIX}->[0] = $newname;
    } else {
      $self->{PREFIX} = $newname;
    }
    rename("$self->{SRC}/$oldname.conf", "$self->{SRC}/$newname.conf");
  } else {
    if ($self->{SRC} =~ m{/} and ($newname !~ m{/} or $newname !~ m{[^/]/$})) 
      # Relative rename....
    {
      my @parts = split("/", $self->{SRC});
      if ($parts[$#parts] eq '') # Changing directory names....
      {
        $parts[$#parts-1] = $newname;
      } else {
        $parts[$#parts] = $newname;
      }
      $self->{SRC} = join("/", @parts);
    } else {
      $self->{SRC} = $newname;
    }
    # Move old file if there...
    rename($oldname, $self->{SRC});
  }
}

1;
