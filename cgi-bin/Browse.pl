#!/usr/bin/perl

my $page = Search->new(PATH_INFO_KEYS=>[qw/tree class filter/]);
# Handles both Search AND Browse functionality.

package Search;
use lib "../lib";
use base "DMCGI";
use DMLDAP;
use DMEntry;
use Data::Dumper;
use Net::LDAP::Filter;

sub process
{
  my ($self, $action) = @_;
  my $treename = $self->get_path_info("tree");
  my $oc = $self->get_path_info("class");
  my $filter = $self->get_path_info("filter");
  my $mode = $self->{GLOBAL}->{MODE}; # From URL.
  my $embedded = $self->get("embedded");

  my $bulkchange = 1 if ($self->get("ADVANCED") && $action && $self->{GLOBAL}->{DN_ME});
  my @records = ();
  my @all_records = ();
  my $prikey = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};

  my $explicit_filter = $self->get("explicit_filter");

  if ($embedded)
  {
    my %form = $self->hash;
    delete $form{ACTION};
    delete $form{EMBEDDED};
    map { delete $form{$_} if not $form{$_} } keys %form;
    $filter = "(&".join("", map { "(".lc($_)."=*$form{$_}*)" } keys %form) . ")";
    print STDERR ("EMBEDDED FILTER=$filter\n");
  }

  if ($explicit_filter)
  {
    my $filter_obj = Net::LDAP::Filter->new($explicit_filter);
    $self->user_error("Bad search filter, please refer to <a href='http://www.ietf.org/rfc/rfc2254.txt'>RFC 2254 HERE</a> for specifications.") unless $filter_obj;
    $filter = $explicit_filter;
  }

  my $value = $self->get("value");
  my @values = $self->get("values");
  my $regex = $self->get("regex");
  my $field = $self->get("field");

  my $extra_filter = $self->get("append_filter");
  my @columns = $self->get("SHOW_COLS");
  @columns = $self->struct_get($self->{GLOBAL}, "CLASSES{$oc}{SEARCH}") unless @columns;

  if ($action eq 'Commit Changes') 
  {
    my @entries = $self->get("entries");
    $self->user_error("No entries selected.") unless @entries;


    my @sets = $self->get("set");
    my @removes = $self->get("unset");

    # SETTING LOGIC...
    # If single-value, put in replace no matter what flag set to.
    # ONLY if multi-value, do replace if explicitly set, otherwise add
    #
    # maybe better to not bother messing with into hash?

    my @multiples = $self->struct_get($self, "GLOBAL{CLASSES}{$oc}{MULTIPLE}");
    my %multiples = map { ($_, 1) } @multiples;
    my %links = $self->struct_get($self, "GLOBAL{CLASSES}{$oc}{LINKS}");
    my %header = $self->struct_get($self, "GLOBAL{CLASSES}{$oc}{HEADER}");

    my $prikey = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};

    print STDERR "ENTRIES ($prikey)=".join(",", @entries)."\n";

    # Go through each entry.
    foreach my $prival (@entries)
    {
      my $entry = DMEntry->new($oc);
      $entry->search($prikey=>$prival);

      $self->user_error("No such entry matching $prikey=$prival") unless
        $entry->count;

      # *** TODO FIXME HOW DO WE TAKE CARE OF SUBRECS?
      # CANT GET EXISTING VALUE NORMALLY TO DO APPEND PROPERLY

      # Take care of sets
      foreach my $encattr (@sets)
      {
        my ($attr, $value, $all) = split(":", $encattr);
        print STDERR "SETTING ATTR=$attr, LA=$links{$attr}, VAL=$value, ALL=$all, MULT=$multiples{$attr}";
	if ($links{$attr}) # Sub record....
	{
	  # For sanity sake, IGNORE "replace all"....
          my @valkey = ref $links{$attr}->{VALKEY} eq 'ARRAY' ? @{ $links{$attr}->{VALKEY} } :
            ($links{$attr}->{VALKEY});
          my $destkey = $links{$attr}->{DESTKEY};
          my $destoc = $links{$attr}->{DESTOC};
          my @srckey = ref $links{$attr}->{SRCKEY} eq 'ARRAY' ? 
            @{ $links{$attr}->{SRCKEY} } : ($links{$attr}->{SRCKEY});

          next unless @valkey and $destkey and @srckey;

	  my $subrec = DMEntry->new($destoc);

          my @filter = map { "($_=$value)" } @valkey;
          my $filter = join("", @filter);
          $filter = "(|$filter)" if @filter > 1;

	  $subrec->search(filter=>$filter);
	  $self->user_error("No such entry '$value' for field '$header{$attr}'. Must exist prior to adding.") unless $subrec->count;

	  my @values = $subrec->get($destkey);
	  my $entry_value = $entry->get($srckey[0]);
	  push @values, $entry_value unless grep { $entry_value eq $_ } @values;
	  print STDERR "\n\nSETTING SUBREC $attr, $destkey=".join(", ", @values)."\n";
	  $subrec->set($destkey => \@values);
	  $subrec->commit();
	} 
	elsif ($multiples{$attr} and $all ne '1') # Only situation when we append.
	{
	  print STDERR ", APPENDING";

	  my @values = $entry->get($attr);
	  my $evaluated_value = $entry->macro_map($value); # Evaluate macros for final version!
	  print STDERR ", EVAL TO=$evaluated_value";
	  if (not grep { $evaluated_value eq $_ } @values)
	  {
	    $entry->bulk_set($attr, [@values, $value]);
	  } # Otherwise, already there! Skip.
	} else {
	  print STDERR ", REPLACING";
	  $entry->bulk_set($attr, $value);
	}
	print STDERR "\n";

      }

      # macro ${fn}.${ln}@malysoft.com broken
      # didnt do remove of .@malysoft.com properly!

      # Take care of removes
      foreach my $encattr (@removes)
      {
        my ($attr, $value) = split(":", $encattr);
        print STDERR "REMOVING ATTR=$attr, VAL=$value";
	if ($links{$attr} and $value ne '') # Sub record.... with a particular value...
	{
          my @valkey = ref $links{$attr}->{VALKEY} eq 'ARRAY' ? @{ $links{$attr}->{VALKEY} } :
            ($links{$attr}->{VALKEY});
          my $destkey = $links{$attr}->{DESTKEY};
          my $destoc = $links{$attr}->{DESTOC};
          my @srckey = ref $links{$attr}->{SRCKEY} eq 'ARRAY' ? 
            @{ $links{$attr}->{SRCKEY} } : ($links{$attr}->{SRCKEY});
          next unless @valkey and $destkey and @srckey;

	  my $subrec = DMEntry->new($destoc);
          my @filter = map { "($_=$value)" } @valkey;
          my $filter = join("", @filter);
          $filter = "(|$filter)" if @filter > 1;
	  $subrec->search(filter=>$filter);
	  $self->user_error("No such entry '$value' for field '$header{$attr}'. Must exist prior to adding.") unless $subrec->count;

	  my @values = $subrec->get($destkey);
	  my @entry_values = map { $entry->get($_) } @srckey;
	  my @filtered_values = ();
	  foreach my $v (@values)
	  {
	    push @filtered_values, $v if not grep { $v eq $_ } @entry_values;
	  }
	  print STDERR "REMOVING SINGLE from $attr, SUB $destkey=".join(", ", @filtered_values)."\n";
	  $subrec->set($destkey => \@filtered_values);
	  $subrec->commit();
	} 
	elsif ($links{$attr} and not $value) # Removing from ALL subrecords!
	{
          my @valkey = ref $links{$attr}->{VALKEY} eq 'ARRAY' ? @{ $links{$attr}->{VALKEY} } :
            ($links{$attr}->{VALKEY});
          my $destkey = $links{$attr}->{DESTKEY};
          my $destoc = $links{$attr}->{DESTOC};
          my @srckey = ref $links{$attr}->{SRCKEY} eq 'ARRAY' ? 
            @{ $links{$key}->{SRCKEY} } : ($links{$attr}->{SRCKEY});

	  my $subrec = DMEntry->new($destoc);
          my @filter = map { "($destkey=".$entry->get($_).")" } @srckey;
          my $filter = join("", @filter);
          $filter = "(|$filter)" if @filter > 1;
	  $subrec->search(filter=>$filter);
	  $self->user_error("No such entry '$value' for field '$header{$attr}'. Must exist prior to adding.") unless $subrec->count;

	  print STDERR "FOUND SUBREC #=".$subrec->count."\n";

	  for ($subrec->first; $subrec->more; $subrec->next)
	  {
	    my @values = $subrec->get($destkey);
	    my @entry_values = map { $entry->get($_) } @srckey;
	    my @filtered_values = ();
	    foreach my $v (@values)
	    {
	      push @filtered_values, $v if not grep { $v eq $_ } @entry_values;
	    }
	    print STDERR "REMOVING ALL from $attr, SUB $destkey=".join(", ", @filtered_values)."\n";
	    $subrec->set($destkey => \@filtered_values);
	    $subrec->commit();
	  }
	}
	elsif ($value && $multiples{$attr})
	{
	  print STDERR ", REMOVING VAL";
	  my @values = $entry->get($attr);
	  @values = grep { $value ne $_ } @values;
	  print STDERR ", NOW=".join(", ", @values)."\n";
	  $entry->set($attr, \@values);
	} else {
	  print STDERR ", REMOVING ALL VALUES\n";
	  $entry->set($attr, undef); # Remove ALL
	}
      }

      # Commit entry into LDAP
      $self->{GLOBAL}->{LOGGER}->{PREPEND} = "For entry '".$entry->get("dn")."':\n<br>";
      $entry->commit();
      $self->{GLOBAL}->{LOGGER}->{PREPEND} = undef;
    }

    $action = 'Search';
    $self->set(action=>$action);
  } 
  elsif ($action eq 'Delete Entries')
  {
    my @entries = $self->get("entries");
    $self->user_error("No entries selected.") unless @entries;

    # TODO

    foreach my $prival (@entries)
    {
      my $entry = DMEntry->new($oc);
      $entry->search($prikey=>$prival);
      $self->user_error("No such entry matching $prikey=$prival") unless
        $entry->count;

      $entry->delete();
    }

    $action = 'Search';
    $self->set(action=>$action);
  }

  if ($mode eq 'Browse')
  {
    my $key = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};
    $filter = "$key=*";
    $self->internal_error("Unable to retrieve primary key for module '$oc'.") unless $key;
  } elsif ($action eq 'Search' and $filter eq '') {
    if (@values)
    {
      $filter = "(|";
      foreach my $eachval (@values)
      {
        my $each_subst = $regex;
        $each_subst =~ s/X/$eachval/g;
        $each_subst ||= $eachval;
        $each_subst = '*' if (not $eachval);
	$filter .= "($field=$each_subst)";
      }
      $filter .= ")";
    } else { # Single value
      my $subst_regex = $regex;
      $subst_regex =~ s/X/$value/g;
      $subst_regex ||= $value;
      $subst_regex = '*' if (not $value);
      $filter = "$field=$subst_regex";
    }

    # CONFUSING! WILL THINK NO RESULTS!
    #if ($self->{GLOBAL}->{CONFIG}->get("ALPHABETICAL_LIST")) # Put in implicit key=A*
    #{
    #  $extra_filter ||= "$columns[0]=A*"; # Implicit!
    #}
  } elsif ($action eq "I'm Feeling Lucky") {
    if ($filter eq '')
    {
      my $subst_regex = $regex;
      $subst_regex =~ s/X/$value/g;
      $subst_regex ||= $value;
      $subst_regex = '*' if (not $value);
      $filter = "$field=$subst_regex";
    }
    $self->redirect("cgi-bin/View.pl/$treename/$oc/$filter");
  }

  $self->set_path_info(filter=>$filter); # Don't let append_filter affect path_info!

  if ($extra_filter)
  {
    $filter = $filter ? "(&($filter)($extra_filter))" : $extra_filter;
  }



  my $ldap = DMEntry->new($oc);
  my @enabled_columns = $ldap->filter_columns();

  my $sort = $self->get("sort");
  my %desc = ();

  #my @columns = $ldap->filter_columns($mode, $oc, $self->{GLOBAL}->{DN_ME});


  my $limit = undef;
  if(not $self->{GLOBAL}->{CONFIG}->get("ALPHABETICAL_LIST") and not $self->get("all"))
  {
    $limit = $self->get("ENTRIES_PER_PAGE") || $self->{GLOBAL}->{CONFIG}->get("ENTRIES_PER_PAGE");
  }
  $limit = undef if ($limit == -1); # All

  my $page = $self->get("page") || 0;
  my $offset = $self->get("offset") || ($page * $limit) || 0;

  #@columns = $ldap->filter_columns() if not @columns; # Default to all permitted ones.
  # Search has standard set of columns, has nothing to do with sections!


  if ($filter)
  {
    $ldap->search_cols([@columns, $prikey], filter=>$filter);#, offset=>$offset, limit=>$limit);
    @all_records = $ldap->records;
    $sort ||= $columns[0]; # Default to first column
    # Will do sort in HTML Template.
    @all_records = sort { record_sort($a, $b, uc $sort) } @all_records;
    my $desc = $self->get('desc');
    @all_records = reverse @all_records if $desc;
    $desc{$sort} = $desc ? 0 : 1;

    # Now, extract by offset/limit
    my $total = scalar(@all_records);
    $limit ||= $total;
    $total = $offset + $limit if ($offset + $limit < $total);
    @records = ();
    for (my $i = $offset; $i < $total; $i++)
    {
      push @records, $all_records[$i];
    }
  }

  my $record_count = $ldap->count;
  my $curr_page = $limit > 0 ? (int($offset / $limit)) : 0;
  my $page_count = $limit > 0 ? (
    int($record_count / $limit) +
    ($record_count % $limit ? 1 : 0)
  ) : 1;
  my $page_index = $page_count-1;

  my $search_fields = $self->{GLOBAL}->{CLASSES}->{$oc}->{"SEARCH_FIELDS"};
  my $query = { FIELD=>$field, REGEX=>$regex, VALUE=>$value };

  print STDERR "COUNT=$record_count, LIMIT=$limit, CURR_PAGE=$curr_page, OFFSET=$offset, PAGE_COUNT=$page_count\n";
  
  my $template = $self->get("export2csv") ? "export.tsv" : "search";
  $template = "embedded_search" if $embedded;

  my %oc_spec = ref $self->{GLOBAL}->{CLASSES}->{$oc} eq 'HASH' ?
    %{ $self->{GLOBAL}->{CLASSES}->{$oc} } : ();

  print STDERR "COLUMNS=".Dumper(\@columns)."\n";

  $self->template_display($template, RESULTS=>\@records, 
    ENABLED_COLUMNS=>\@enabled_columns,
    COLUMNS=>\@columns, %oc_spec, DESC=>\%desc,
    SEARCH_FIELDS=>$search_fields, QUERY=>$query, PAGE_INDEX=>$page_index,
    PAGE_COUNT=>$page_count, CURR_PAGE=>$curr_page, COUNT=>$record_count,
    ENABLED_SECTIONS=>[ $ldap->filter_sections('add') ],
    BULKCHANGE=>$bulkchange,
  );
}

sub record_sort
{
  my ($a, $b, $sort) = @_;
  return unless $sort;
  if (ref $a->{$sort} eq 'ARRAY' and ref $b->{$sort} eq 'ARRAY') {
    for (my $i = 0; $i <  (@{$a->{$sort}} > @{$b->{$sort}} ? @{$a->{$sort}} : @{$b->{$sort}}); $i++)
    {
      my $rc = lc($a->{$sort}->[$i]) cmp lc($b->{$sort}->[$i]);
      return $rc unless ($rc == 0);
    }
  } else {
    return lc($a->{$sort}) cmp lc($b->{$sort});
  }
  

}

1;
