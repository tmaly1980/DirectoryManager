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

  my $oc = $self->get_path_info("class");

  my $entry = DMEntry->new($oc);

  my %requests = $entry->get_requests('*', 1);

  my @columns = $self->struct_get($self, "GLOBAL{CLASSES}{$oc}{REQUEST}");
  @columns = $self->{GLOBAL}->{CLASSES}->{$oc}->{"SEARCH"} unless @columns;
  my %oc_spec = ref $self->{GLOBAL}->{CLASSES}->{$oc} eq 'HASH' ? %{ $self->{GLOBAL}->{CLASSES}->{$oc} } : ();

  $self->template_display("request", 
    MODE=>$self->{GLOBAL}->{MODE},
    REQUESTS=>\%requests, # DO we really wanna load ALL requests?
    # DO WE REALLY WANT TO SHOW COLUMNS? or just the filename?
    COUNT=>(scalar keys %requests),
    COLUMNS=>\@columns,
    %oc_spec,

  );
}

sub process_old
{
  my ($self, $action) = @_;

  my $oc = $self->get_path_info("class");
  my $filter = $self->get_path_info("filter");
  my $mode = $self->{GLOBAL}->{MODE}; # From URL.
  my @records = ();
  my @all_records = ();

  my $explicit_filter = $self->get("explicit_filter");
  if ($explicit_filter)
  {
    my $filter_obj = Net::LDAP::Filter->new($explicit_filter);
    $self->user_error("Bad search filter, please refer to <a href='http://www.ietf.org/rfc/rfc2254.txt'>RFC 2254 HERE</a> for specifications.") unless $filter_obj;
    $filter = $explicit_filter;
  }

  my $value = $self->get("value");
  my $regex = $self->get("regex");
  my $field = $self->get("field");

  my $extra_filter = $self->get("append_filter");
  my @columns = $self->struct_get($self, "GLOBAL{CLASSES}{$oc}{SEARCH}");

  if ($mode eq 'Browse')
  {
    my $key = $self->{GLOBAL}->{CLASSES}->{$oc}->{"PRIMARY_KEY"};
    $filter = "$key=*";
  } elsif ($action eq 'Search' and $filter eq '') {
    my $subst_regex = $regex;
    $subst_regex =~ s/X/$value/g;
    $subst_regex ||= $value;
    $subst_regex = '*' if (not $value);
    $filter = "$field=$subst_regex";

    # CONFUSING! WILL THINK NO RESULTS!
    #if ($self->{GLOBAL}->{CONFIG}->get("ALPHABETICAL_LIST")) # Put in implicit key=A*
    #{
    #  $extra_filter ||= "$columns[0]=A*"; # Implicit!
    #}
  }

  print STDERR "FILTER=$filter\n";


  $self->set_path_info(filter=>$filter); # Don't let append_filter affect path_info!

  if ($extra_filter)
  {
    $filter = $filter ? "(&($filter)($extra_filter))" : $extra_filter;
  }



  my $ldap = DMEntry->new($oc);

  my $sort = $self->get("sort");
  my %desc = ();

  #my @columns = $ldap->filter_columns($mode, $oc, $self->{GLOBAL}->{DN_ME});


  my $limit = $self->{GLOBAL}->{CONFIG}->get("ENTRIES_PER_PAGE") if not $self->{GLOBAL}->{CONFIG}->get("ALPHABETICAL_LIST");
  my $page = $self->get("page") || 0;
  my $offset = $self->get("offset") || ($page * $limit) || 0;

  if ($filter)
  {
    $ldap->search(filter=>$filter);#, offset=>$offset, limit=>$limit);
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
  my $page_count = $limit > 0 ? (int($record_count / $limit)+1) : 1;
  my $page_index = $page_count-1;

  my $search_fields = $self->{GLOBAL}->{CLASSES}->{$oc}->{"SEARCH_FIELDS"};
  my $query = { FIELD=>$field, REGEX=>$regex, VALUE=>$value };

  my $tmpl = $self->get("popup") ? "search_popup" : "search";
  my %oc_spec = ref $self->{GLOBAL}->{CLASSES}->{$oc} eq 'HASH' ? %{ $self->{GLOBAL}->{CLASSES}->{$oc} } : ();

  $self->template_display($tmpl, MODE=>$mode, RESULTS=>\@records, 
    COLUMNS=>\@columns, %oc_spec, DESC=>\%desc, 
    SEARCH_FIELDS=>$search_fields, QUERY=>$query, PAGE_INDEX=>$page_index,
    PAGE_COUNT=>$page_count, CURR_PAGE=>$curr_page, COUNT=>$record_count);
}

sub record_sort # BROKEN, OBSOLETE
{
  my ($a, $b, $sort) = @_;
  return unless $sort;
  if (ref $a->{$sort} eq 'ARRAY' and ref $b->{$sort} eq 'ARRAY') {
    for (my $i = 0; $i <  (@{$a->{$sort}} > @{$b->{$sort}} ? @{$a->{$sort}} : @{$b->{$sort}}); $i++)
    {
      my $rc = $a->{$sort}->[$i] cmp $b->{$sort}->[$i];
      return $rc unless ($rc == 0);
    }
  } else {
    return $a->{$sort} cmp $b->{$sort};
  }
  

}

1;
