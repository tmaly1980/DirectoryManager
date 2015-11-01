#!/usr/bin/perl

my $page = ImportCGI->new(PATH_INFO_KEYS=>[qw/tree class filter/]);
# Handles both Search AND Browse functionality.

package ImportCGI;
use lib "../lib";
use base "DMCGI";
use DMLDAP;
use DMEntry;
use Data::Dumper;
use Net::LDAP::Filter;

sub process
{
  my ($self, $action) = @_;

  my $oc = $self->get_path_info("class");
  my $delim = $self->get("delim") || ":";
  my $filter = $self->get("filter");
  my $changemode = $self->get("changemode") || 'add';
  my $onerror = $self->get("onerror") || 'stop';

  $self->login_page('Administrator Access Required') unless $self->{GLOBAL}->{CONFIG}->has_admin_access();

  # LDIF, Import and Preview are ALL variants!
  if ($action eq 'Import' or $action eq 'Preview' or $action eq 'Generate LDIF')
  {
    my ($format) = split(":", $self->get("format"));

    $self->user_error("Must specify file format.") unless $format;
    my %format_metas = ();
    my @format_metas = $self->struct_get($self, "GLOBAL{CLASSES}{$oc}{IMPORT_FORMATS}");
    my ($format_meta) = grep { $_->{ABBREV} eq $format } @format_metas;
    my %multiple = ref $format_meta->{MULTIPLE} eq 'HASH' ?
      %{$format_meta->{MULTIPLE}} : ();
    %multiple = map { (uc($_), $multiple{$_}) } keys %multiple;

    my $defaults = $self->{GLOBAL}->{CLASSES}->{$oc}->{"IMPORT_DEFAULTS"};
    my @defaults = ref $defaults eq 'ARRAY' ? @$defaults : ();
    my %defaults = @defaults;
    my $i = 0; my @default_keys = grep { $i++ % 2 == 0 } @defaults;
    my @file = $self->get_file_data("content");

    $self->user_error("Must specify local file.") unless @file;

    print $self->{GLOBAL}->{TEMPLATE}->content_type("text/plain", 1);
    print "# Importing....\n" if $action eq 'Import';
    print "# Generating Preview....\n" if $action eq 'Preview';
    print "# Generating LDIF....\n";
    print "# Filtering criteria: $filter\n" if $filter;
    print "\n";

    $self->{GLOBAL}->{SKIP_HEADERS} = 1;
    $self->{GLOBAL}->{CONTENT_TYPE} = "text/plain";

    if ($format eq 'ldif')
    {
      my $tmpname = "/tmp/dmldif-".time().".$$";
      open(TMPF, ">$tmpname");
      map { print TMPF "$_\n"; } @file;
      close(TMPF);
      my $ldif = Net::LDAP::LDIF->new($tmpname, 'r', encode=>'base64');#,onerror=>undef);
      while (not $ldif->eof() )
      {
        my $entry = $ldif->read_entry();
	$self->system_error("Invalid LDIF entry.") unless $entry;
	my $entry_ldif = $ldif->current_lines();
	print "$entry_ldif\n";
        if ($action eq 'Import') # ACTUALLY do the import now !
	{
	  my $mesg = $entry->update($DMLDAP::LDAP);

  	  print "# Status: " . $mesg->error ."\n" if ref $mesg; # Even if success
  
  	  if (ref $mesg && $mesg->code && $onerror eq 'stop')
  	  {
  	    $self->system_error("Import Error: " . $mesg->error);
  	  }
	}
	print "\n\n";
      }
      $ldif->done();

      unlink($tmpname);
    } else {
      my @entry_types = $self->struct_get($self, "GLOBAL{CLASSES}{$oc}{ENTRY_TYPES}"); # From config
      my %entry_types = @entry_types;

      my @colnames = ();
      my @et = @entry_types ? (entry_type=>$self->get("entry_type")) : ();

      $self->user_error("Must specify delimiter.") unless $delim;

      if ($format eq 'otherfile')
      {
        @colnames = split($delim, shift @file);
        $self->user_error("Must specify columns in file.") unless @colnames;
      } else {
        @colnames = $self->get("cols");
        $self->user_error("Must specify columns.") unless @colnames;
      }

      # DO OTHER SANITY CHECKS TOO!!!
      $self->user_error("No column names provided!") unless @colnames;

      foreach my $line (@file)
      {
        my @cols = split($delim, $line);
	my %cols = ();
	# May have one or more names per column, i.e. sambaLMPassword,lmPassword
	for (my $i = 0; $i < @colnames; $i++)
	{
	  my @name = split(/[, ]+/, $colnames[$i]);
	  map { $cols{$_} = $cols[$i] } @name;
	}
        delete $cols{x}; # Get rid of...

	# Formulate lists...
	foreach my $col (keys %cols)
	{
	  if(my $delim = $multiple{uc $col})
	  {
	    $delim = ',' if $delim eq '1';
	    $cols{$col} = [ split(/$delim/, $cols{$col}) ];
	  }
	}
  
        # Formulate defaults...
        foreach my $col (@default_keys)
        {
  	  if (not $cols{$col} and $defaults{$col})
  	  {
            $cols{$col} = $cols{$defaults{$col}};
    	  }
        }

        if ($filter)
        {
          my $filter_eval = MalyVar->evaluate_content($filter, \%cols);
	  print "# Filter evaluated as: ($filter_eval) ...";
	  if (eval $filter_eval)
	  {
	    print " Keeping\n";
	  } else {
	    print " Skipping\n";
	    next;
	  }
        }

        my $entry = DMEntry->new($oc);
        #if ($changemode eq 'mixed' or $changemode eq 'modify')
        #{
        #  my $prikey = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};
        # $entry->search($prikey=>$cols{$prikey}) if ($cols{$prikey} ne '');
        #}
        $entry->import(%cols, @et);
        my $changetype = $changemode;
        my $ldif = $entry->generate_ldif($changetype);
        my %entry = $entry->hash;

        print "$ldif\n";
  
        if ($action eq 'Import') # ACTUALLY do the import now !
        {
  	  my $mesg = undef;
  
          if ($changemode eq 'add')
  	  {
  	    $mesg = $entry->insert_ldif();
  	  } elsif ($changemode eq 'modify') {
  	    $mesg = $entry->update_ldif();
  	  } elsif ($changemode eq 'mixed') {
  	    $mesg = ($entry->is_new ? $entry->update_ldif() : $entry->insert_ldif());
  	  }
  
  	  print "# Status: " . $mesg->error ."\n" if ref $mesg; # Even if success
  
  	  if (ref $mesg && $mesg->code && $onerror eq 'stop')
  	  {
  	    $self->system_error("Import Error: " . $mesg->error);
  	  }
        }
        print "\n\n";
      }

    }

    print "# LDIF Complete!\n";
    print "# Preview Complete!\n" if $action eq 'Preview';
    print "# Import Complete!\n" if $action eq 'Import';

    exit;
  } else {
    $self->template_display("import_form");
  }

}

