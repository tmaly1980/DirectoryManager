#!/usr/bin/perl

my $page = Edit->new({form=>0,title=>"DirectoryManager Edit Entry", PATH_INFO_KEYS=>[qw/tree class filter/]});

package Edit;
use lib "../lib";
use base "DMCGI";
use DMLDAP;
#use User;
#use Group;
use DMEntry;
use Data::Dumper;

sub process 
{
  my ($self, $action) = @_;
  print STDERR "ABOUT TO PROCESS=".time()."\n";
  my $tree = $self->get_path_info("tree") or $self->user_error("No tree specified.");
  my $oc = $self->get_path_info("class") or $self->user_error("No object class specified.");

  my $filter = $self->get_path_info("filter"); # If none, we're Adding.
  my $mode = $self->{GLOBAL}->{MODE};
  $self->user_error("No filter specified.") if ($mode eq 'Edit' and not $filter);

  my $prikey = $self->{GLOBAL}->{CLASSES}->{$oc}->{$1};

  my $entry = DMEntry->new($oc);
	  
  if ($mode eq 'Edit')
  {
    # If SELF, should get extra columns for 'SELF' access. But don't know until AFTER search. So must pass SELF
    # columns no matter what!
    my @columns = $entry->filter_columns();
    print STDERR "SOUGHT COLS=".Dumper(\@columns)."\n";
    print STDERR "ABOUT TO SEARCH=".time()."\n";
    $entry->search_cols([@columns, $prikey], filter=>$filter);
    print STDERR "DONE SEARCH=".time()."\n";
    $self->user_error("No entry found.") unless $entry->count;
    $self->login("Further Authorization Required") unless $entry->is($self->{GLOBAL}->{DN_ME})
      or $self->{GLOBAL}->{CONFIG}->has_admin_access($oc) or $self->{GLOBAL}->{CONFIG}->has_request_access($oc);
  } 
  elsif ($mode eq 'Add')
  {
    $self->login("Further Authorization Required") unless $self->{GLOBAL}->{CONFIG}->has_admin_access($oc) or $self->{GLOBAL}->{CONFIG}->has_request_access($oc);
    $self->license_check();
  }

  my $default_filename = undef;

  print STDERR "TEMPLATE_LOAD\n";
  $entry->template_load($self->get("template")) if $mode eq 'Add' and not $action;
  # Don't load when actual submit, because all data needed is in form.
  # Also clobbers checkboxes when in template but not form.
  print STDERR "TEMPLATE_LOAD DONE\n";

  my $filename = $self->get("filename");
  if ($filename and $mode eq 'Add')
  {
    if ($filename)
    {
      $entry->request_load($filename) or $self->user_error("No such request.");
    }
  }

  if ($self->get("show_templates"))
  {
    # Get all in directory.
    my %requests = $entry->get_requests;
    $self->template_display("request_popup", REQUESTS=>\%requests);
  }

  if ($action eq 'Submit Request to Admins')
  {
    # !!! Need to avoid macro evaluation !!! ie move macro eval to set(), use set_unchecked below ...
    # better, formal debugging,
    # better design on macro evaluation, etc....
    $entry->set($self->get_smart_hash_with_uploads);
    if ($mode eq 'Add' and ($self->{GLOBAL}->{CONFIG}->has_request_access($oc) or $self->{GLOBAL}->{CONFIG}->has_admin_access($oc)))
    {
      my $from = $self->session_get("cn") || $self->{GLOBAL}->{DN_ME};
      $from = $from->[0] if ref $from eq 'ARRAY';
      $entry->request_submit($from);
      $self->redirect("cgi-bin/Search.pl/$self->{GLOBAL}->{TREE}/$self->{GLOBAL}->{OC}");
    } else {
      $self->user_error("Sorry, you do not have proper access.");
    }
  }
  elsif ($mode eq 'Add' and $action eq 'Save As Template')
  {
    $self->user_error("Unable to save template, not an account administrator.")
      if (not $self->{GLOBAL}->{CONFIG}->has_admin_access($oc));
    my $name = $self->get("template_name");
    $self->user_error("Unable to save template, no name provided.")
      unless $name;
    $entry->set($self->get_smart_hash_with_uploads);
    my $global = $self->get("GLOBAL_TEMPLATE");
    $entry->template_save($global);
    $self->set("template", $name);
  }
  elsif ($action eq 'Save' or $action eq 'Update Entry' or $action eq 'Add Entry')
  {
    $self->user_error("Unable to create entry, not an account administrator.")
      if (not $self->{GLOBAL}->{CONFIG}->has_admin_access($oc) and $mode eq 'Add');

    print STDERR "ENTRY SET\n";
    $entry->set($self->get_smart_hash_with_uploads);
    print STDERR "ENTRY HAS=".$entry->get("uid")."\n";

    # Seems that random password thing and getting vars uses template info
    # and not hash itself!
    # XXX TODO
    # We're trying to use a non-standard username.
    # Figure out view_url problem below.

    $entry->commit(); 

    $entry->request_complete if $mode eq 'Add'; # Assume might be request.
    # AND so we can refer to values purely by name, no need to constantly refer to ->[0]
    my $changed_password = ($entry->is($self->{GLOBAL}->{DN_ME}) and $entry->changed_password);
  
    if ($changed_password) 
    {
      my $next_url = $entry->get("VIEW_URL")."?action=Logout";
      $self->redirect($next_url); 
    }
    my $key = $self->{GLOBAL}->{CLASSES}->{$oc}->{$1};
    my $new_dn = $entry->has_changed($key);

    # I.e. password changed to X. Click to continue.
    my @msg = $entry->edit_msg_page($mode);

    if (@msg and $msg[0]) # Not getting undef
    # May or may not be anything, may skip.
    {
      $self->template_display(@msg);
    }

    #if ($mode eq 'Add') # For now, display template if possible.
    #{
      #my %entry = $entry->report_vars();
      #$self->maybe_template_display(["report/$oc", "report/default_$oc","add_report"], ENTRY=>\%entry);
    #} else { # Edit.
      #my %entry = $entry->report_vars();
      #$self->maybe_template_display("edit_report", ENTRY=>\%entry);
    #}

    #$Data::Dumper::Maxdepth = 5;
    #print STDERR "REC=".Dumper($entry->{RECORDS})."\n";
    #$Data::Dumper::Maxdepth = 2;
    my $pass = $entry->get("userPassword");
    print STDERR "userPass=$pass\n";
  
    if ($mode eq 'Add' or $new_dn)
    {
      $self->redirect($entry->get("VIEW_URL"));
    }
   
    # Reset form.
    $self->clear_form;
  } 
  elsif ($action eq 'Delete' and $mode eq 'Edit')
  {
    $entry->delete();
    $self->redirect("cgi-bin/Search.pl/$tree/$oc?action=Logout", "Your account has been deleted.")
      if ($entry->is($self->{GLOBAL}->{DN_ME}));
    $self->redirect("cgi-bin/Search.pl/$tree/$oc");
  } 

  #my @entry_columns = $entry->filter_columns;
  my @sections = $entry->filter_sections;

  $self->user_error("Sorry, there are no sections available for edit -- as '$self->{GLOBAL}->{DN_ME}'. Click on 'Continue' to log in as someone else.", "$self->{GLOBAL}->{PATHINFO_URL}?action=RequiredLogin") unless @sections;

  # Need way to FORCE login page! and not just accept current cookie!
  # action=RequiredLogin !!!

  my @templates = $entry->template_names;

  my $admin = $self->{GLOBAL}->{CONFIG}->has_admin_access($oc);
  my $requestor = $self->{GLOBAL}->{CONFIG}->has_request_access($oc);
  my $moderator = $self->{GLOBAL}->{CONFIG}->has_moderator_access($oc);

  my $oc_spec = $self->{GLOBAL}->{CLASSES}->{$oc};
  my %oc_spec = ref $oc_spec eq 'HASH' ? %$oc_spec : ();

  print STDERR "ABOUT TO TEMPLATE_DISPLAY=".time()."\n";

  $self->template_display("edit", MODE=>$mode, %oc_spec, ENTRY=>$entry->hashref, 
  ENABLED_SECTIONS=>\@sections,
  TEMPLATES=>\@templates,
  #ENTRY_COLUMNS=>\@entry_columns
  );

}

1;
