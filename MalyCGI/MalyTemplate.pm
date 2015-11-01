package MalyTemplate;

use Data::Dumper;
use MalyVar;
use MalyLog;
require HTML::TreeBuilder;
require HTML::Entities;
use UNIVERSAL qw(isa can);

# Accepts:
#
# TEMPLATE_DIR = Defaults to ../templates, where to find the templates.
# VARS = Hash ref of global variables.
#
# FYI, all text templates must have a tag around them!

# Remove evaluation from filenames.
#
# WORKS LIKE:
# 
# $t = MalyTemplate->new();
# $output = $t->render("template", %vars)
#
our @IGNORE_TAGS_BUT_NOT_CONTENT =
qw(
 widget-.*
);

our @NO_END_TAGS =
qw(
  hr
  input
  br
  base
  img
);

sub log
{
  my ($self, $msg) = @_;
  if ($self->{GLOBAL}->{LOGGER})
  {
    $self->{GLOBAL}->{LOGGER}->log($msg);
  } else {
    print STDERR "$msg\n";
  }
}

sub new
{
  my ($this, @vars) = @_;
  my $class = ref($this) || $this;
  my $self = {};
  if (@vars == 1)
  {
    $self->{GLOBAL} = $vars[0];
  } else {
    $self->{GLOBAL} = { @vars };
  }
  $self->{GLOBAL}->{LOGGER} ||= MalyLog->new();
  bless $self, $class;

  $self->{TEMPLATE_DIR} = $self->{GLOBAL}->{TEMPLATE_DIR} || "../templates"; # In code, NOT config file.
  # Don't want to change permanently, just per instance.

  $self->set_maly_callbacks();

  return $self;
}

sub render # render($file, $vars) OR render($file, %vars)
{
  my ($self, $tmpl, @vars) = @_;
  my %vars = ();
  if (@vars == 1 and ref $vars[0] eq 'HASH')
  {
    %vars = %{$vars[0]};
  } elsif (@vars > 1) {
    %vars = @vars;
  }

  if (ref $self->{GLOBAL}->{VARS} eq 'HASH')
  {
    my %gvars = %{ $self->{GLOBAL}->{VARS} };
    %vars = (%vars, %gvars);
  }

  my %uc_vars = map { (uc($_), $vars{$_}) } keys %vars;
  my $merged_content = join("", $self->load($tmpl, \%uc_vars));
  return unless $merged_content;
  $self->parse_template($merged_content, \%uc_vars);
}

sub save_render # Also happens to send back content if asked for.
{
  my ($self, $file, $tmpl, @vars) = @_;
  my $content = $self->render($tmpl, @vars);
  $self->save_content($file, $content);
}

sub assert_dir_of
{
  my ($self, $file, $perm) = @_;
  my @file = split("/", $file);
  map
  {
    my $f = join("/", @file[0..$_]);
    if (! -d $f)
    {
      mkdir($f, $perm||0755) || $self->{GLOBAL}->{LOGGER}->internal_error("Unable to create directory' $f'.");
    }
  } (0..$#file-1);
}

sub output_dir
{
  my ($self, $dir) = @_;
  $self->{OUTPUT_DIR} = $dir;
}

sub save_content
{
  my ($self, $file, $content) = @_;
  $file = "$self->{OUTPUT_DIR}/$file" if ($self->{OUTPUT_DIR});

  $self->assert_dir_of($file);
  if(open(FILE, ">$file"))
  {
    print FILE $content;
    close(FILE);
    return $content if defined wantarray;
  } else {
    $self->log("Unable to save to '$file'.\n");
    return undef;
  }

} 

sub set_master_template # ALL calls to print() will use respective file
{
  my ($self, $file, $tag) = @_;
  $self->set_callback_template_file($tag, $file) if $tag;
  my $template = $self->load($file);
  $self->{MASTER_TEMPLATE} = $template;
}

sub tag_print
{
  my ($self, $tag, $file, $content, %vars) = @_;
  $content = ["<$tag>", @$content, "</$tag>"] if ref $content eq 'ARRAY';
  $self->print($file, $content, %vars) = @_;
}

sub print
{
  my ($self, $file, $content, %vars) = @_;
  $vars{CURRENT_FILE} = $file;
  my $text_content = $content;
  my @content = ();
  if (ref $content eq 'ARRAY')
  {
    @content = @$content;
  } elsif (ref $content) {
    @content = ($content);
  }
  my @text_content = map { $self->evaluate_node($_, \%vars); } @content;
  $text_content = join("", @text_content);

  if ($self->{MASTER_TEMPLATE})
  {
    my $tmpl = $self->{MASTER_TEMPLATE};
    # SHOULD evaluate CONTENT, as may be conditional, etc...
    my $evaled_tmpl = $self->evaluate_text($tmpl, {%vars, CONTENT=>$text_content});
    $text_content = $evaled_tmpl;
    #$tmpl =~ s/#CONTENT#/$text_content/gi;
    #$text_content = $tmpl;
  }

  $file = "$file.html" if ($file !~ /[.]\w+$/);
  $self->save_content($file, $text_content);
}

sub set_callback_struct
{
  my ($self, $struct) = @_;
  return unless ref $struct eq 'HASH';
  foreach my $key (keys %$struct)
  {
    $self->set_callback($key, $struct->{$key});
  }
}

sub set_callback_template_file # 'Outer document' for given tag.
{
  my ($self, $tag, $infile) = @_;
  my $file_content = $self->load($infile) or die();
  $self->set_callback($tag, $file_content);
}

sub filename # If exists, gets filename. else, returns undef.
{
  my ($self, $tmpl, $basedir) = @_;

  my @templates = (ref $tmpl eq 'ARRAY' ? @$tmpl : $tmpl);

  foreach my $x_tmpl (@templates)
  {
    my @files = ();

    my @ext = (qw/xml txt html htm tmpl conf cnf csv/);

    #if (not grep { $x_tmpl =~ /[.]$_$/i } @ext) 
    if ($x_tmpl !~ /[.]\w+$/)
    # If doesn't already contain an extension, try standard ones.
    {
      push @files, map { "$x_tmpl.$_" } @ext;
    } else {
      push @files, $x_tmpl;
    }

    my @abs_files = ();

    for (my $i = 0; $i < @files; $i++)
    {
      if ($files[$i] !~ m{^[.]{0,2}[/]})
      # Prepend TEMPLATE_DIR if no ^/, ./ or ../ 
      # ('./foo.htm' will not get it appended)
      {
        push @abs_files, "$basedir/$files[$i]" if $basedir;
        push @abs_files, "$self->{TEMPLATE_DIR}/$files[$i]";
      } else {
        push @abs_files, $files[$i];
      }
    }

    #print STDERR "PWD=$cwd, FILES TRYING=".join(", ", @abs_files)."\n";
    if (my ($f) = grep { -f } @abs_files)
    {
      $tmpl = $f;
      last;
    }
  }
  return undef if (ref $tmpl or not -f $tmpl);
  return $tmpl;
}

sub load
{
  my ($self, $bare_tmpl, $vars, $basedir, $auxfile) = @_;
  # Template may be array ref. In that case, loop over. Use first one found in list.

  unless ($tmpl = $self->filename($bare_tmpl, $basedir))
  {
    $self->log("Unable to open template: '" . (ref $bare_tmpl eq 'ARRAY' ? join(", ", @$bare_tmpl) : $bare_tmpl) ."'");
    return undef;
  }
  #print STDERR "BARE=".Dumper($bare_tmpl)."\n";
  #print STDERR "FOUND=".Dumper($tmpl)."\n";
  if (not open(F, "<$tmpl"))
  {
    $self->log("Unable to open template: '$tmpl'");
    return undef;
  }

  if (not $auxfile)
  {
    $self->{TEMPLATE_FILENAME} = $tmpl;

    $self->{HTML_TEMPLATE} = ($tmpl =~ /[.](htm)[l]?$/i);
    $self->{CSV_TEMPLATE} = ($tmpl =~ /[.]csv$/i);
    $self->{TSV_TEMPLATE} = ($tmpl =~ /[.]tsv$/i);
    $self->{TEXT_TEMPLATE} = ($tmpl =~ /[.]txt$/i);
  }

  my @lines = <F>;
  close(F);
  #@lines = map { s/^#(.+?)[?](.+)$/<maly-if var="$1">$2<\/maly-if>/g; $_ } @lines; # foobars stuff!
  #
  # Translate (lines that start with '#' and contain a '?' (i.e., up to the first '?') BEFORE the end-of-line):
  # "#ServerName?ServerName #ServerName#"
  #   into:
  # "<maly-if var="ServerName">ServerName #ServerName#</maly-if>
  #
  # Simply for convenience.
  #
  my @tmpl_parts = split("/", $tmpl);
  my $my_basedir = join("/", @tmpl_parts[0..$#tmpl_parts-1]);
  my @content = map { /^#include (.*)$/ ? $self->load($1, $vars, $my_basedir, 1) : $_ } @lines;
  return (wantarray ? @content : join("", @content));
}

sub content_type
{
  my ($self, $type, $nl) = @_;
  return undef if $self->{GLOBAL}->{SKIP_HEADERS}; # Already did!
  $self->{GLOBAL}->{SKIP_HEADERS} = 1;
  $type ||= "text/plain";
  $type = "text/html" if ($self->{HTML_TEMPLATE});
  $type = "application/vnd.ms-excel" if ($self->{CSV_TEMPLATE});
  $type = "application/vnd.ms-excel" if ($self->{TSV_TEMPLATE});
  $type = "text/plain" if ($self->{CSV_TEMPLATE});
  $self->{GLOBAL}->{CONTENT_TYPE} = $type;
  $nl = "\n" if $nl;
  return "Content-Type: $type\n$nl";
}

sub content_disposition
{
  my ($self) = @_;
  my $filename = $self->{TEMPLATE_FILENAME} || $ENV{SCRIPT_NAME};
  $filename =~ s/^.*\//\1/;
  $filename =~ s/[.]tsv$/.csv/; # For Tab-delimited.
  return "Content-Disposition: inline; filename=$filename\n";
}

sub parse_content
{
  my ($self, $content) = @_;
  $content = HTML::Entities::encode_entities($content, '&');
  my $tree = HTML::TreeBuilder->new() or die("Unable to generate template tree: $@");
  $tree->ignore_unknown(0);
  $tree->xml_mode(1); # Allow for <foo /> style tags
  $tree->implicit_tags(0);
  $tree->unbroken_text(1);
  $tree->ignore_ignorable_whitespace(0);
  $tree->no_space_compacting(1);
  $tree->store_comments(1);
  $tree->parse($content);
  $tree->warn(1);
  $tree->eof();
  $tree->objectify_text(); # To avoid having to re-setting an element's children since now reference.
  return $tree if defined wantarray;
  $self->{TREE} = $tree; # If we don't ask for it back.
}

sub set_maly_callbacks
{
  my ($self) = @_;

  # Set defaults for callbacks...
  $self->set_callback_default("maly-if", \&maly_if);
  $self->set_callback_default("maly-set", \&maly_set);
  $self->set_callback_default("maly-loop", \&maly_loop);
  $self->set_callback_default("maly-text", \&maly_text);
  $self->set_callback_default("maly-comment", \&maly_comment);
  $self->set_callback_default("maly-load", \&maly_load);
  $self->set_callback_default("maly-cutws", \&maly_cutws);
  $self->set_callback_default("maly-print", \&maly_print);
  $self->set_callback_default("maly-literal", \&maly_literal);
  $self->set_callback_default("~text", \&text);
  $self->set_callback_default("~comment", \&comment);
}

sub parse_template
{
  my ($self, $content, $vars, %callbacks) = @_; # Allows callbacks for this specific run only.
  $self->parse_content($content);

  my $global_vars = {};

  foreach my $key (keys %callbacks)
  {
    $self->set_callback($key, $callbacks{$key});
  }

  my @guts = $self->{TREE}->guts();
  my @evaluated_guts = map { $self->evaluate_node($_, $vars, $global_vars) } @guts;
  my $final_content = join("", @evaluated_guts);
  return undef unless $final_content;
  #$final_content->deobjectify_text();
  #
  return $final_content;

  #if ($self->{TEXT_TEMPLATE})
  #{
  #  return $final_content->as_text();
  #} else {
  #  return $final_content->as_HTML('&');
  #}
}

sub set_callback
{
  my ($self, %tag_func_hash) = @_;
  foreach my $tag (keys %tag_func_hash)
  {
    $self->{CALLBACK}->{$tag} = $tag_func_hash{$tag};
  }
}

sub set_callback_default
{
  my ($self, %tag_func_hash) = @_;
  foreach my $tag (keys %tag_func_hash)
  {
    $self->{CALLBACK}->{$tag} ||= $tag_func_hash{$tag};
  }
}

sub get_node_attrs
{
  my ($self, $node, $vars, $eval) = @_;
  return () if not ref $node;
  my @attr_names = $node->all_external_attr_names;
  my %attrs = ();
  foreach my $attr (@attr_names)
  {
    if ($attr eq 'text' or $attr =~ /^maly-/ or not $eval) 
    { 
      $attrs{$attr} = $node->attr($attr);
    } else {
      $attrs{$attr} = MalyVar->evaluate_content($node->attr($attr), $vars, undef, 1);
    }

  }
  return %attrs;
  #my %attrs = map { ($_, MalyVar->evaluate_content($node->attr($_), $vars)) } $node->all_external_attr_names;
}

sub has_ancestors
{
  my ($self, $node, @tags) = @_;
  my $prevtag = pop @tags;
  if ($prevtag and $node->is_inside($prevtag))
  {
    return @tags ? $self->has_ancestors($node, @tags) : 1;
  } else {
    return undef;
  }
}

sub evaluate_text
{
  my ($self, $text, $vars) = @_;
  my $node = $self->parse_content($text, $vars);
  my @guts = $node->guts();
  my @evaluated_guts = map { $self->evaluate_node($_, $vars) } @guts;
  my $final_content = join("", @evaluated_guts);
}

sub evaluate_children
{
  my ($self, $children, $vars) = @_;
  my @children = ref $children eq 'ARRAY' ? @$children : ();
  my @evaluated_children = map { $self->evaluate_node($_, $vars) } @children;
  my $sub_content = join("", @evaluated_children);
}

sub evaluate_node
{
  my ($self, $node, $vars) = @_;

  my $content = "";
  my $node_name = $node->tag;

  my %vars = ref $vars eq 'HASH' ? %$vars : ();

  my @children = $node->content_list;
  # Callback can be regex defined too!
  my $callback = undef;

  # Figure out what '$callback' should be.
  if (ref $self->{CALLBACK} eq 'HASH')
  {
    # We need to implement a check of superior tags, if necessary.
    my @tags = split("/", $key);
    my $node_key = pop @tags;
    
    my @callbacks = sort { scalar(split("/", $b)) <=> scalar(split("/", $a)) }
      grep { $_ =~ m{/$node_name$}i || $_ =~ /^$node_name$/i } 
      keys %{ $self->{CALLBACK} };

    foreach my $callname (@callbacks)
    {
      my @tags = split("/", $callname);
      my $key = pop @tags;

      if (@tags and $self->has_ancestors($node, @tags))
      {
        $callback = $self->{CALLBACK}->{$callname};
        last;
      } elsif (not @tags) {
        $callback = $self->{CALLBACK}->{$callname};
        last;
      }
    }
  }


  if (ref $callback eq 'CODE')
  {
    my %attrs = $self->get_node_attrs($node, $vars, undef); # WE MUST EXPLICITLY RUN EVALCONTENT ON ATTR VALUES !!!
    my @content = $callback->($self, $node_name, \%attrs, \@children, $vars);
    $content = join("", @content);

  } elsif (ref $callback eq 'SCALAR') { # Literal text, don't EVALUTE!
    my %attrs = $self->get_node_attrs($node, $vars, 1);
    # MOST likely cuz it just takes the tag and does some modification to attrs!
    # We want to avoid an infinite loop!
    my $text = $$callback;
    $vars->{ATTR} = \%attrs;
    $content = MalyVar->evaluate_content($text, $vars);
  } elsif ($callback and not ref $callback) { 
    my %attrs = $self->get_node_attrs($node, $vars, 1);
    # ??? # IMPLEMENT TAKING FROM XML MAP FILE AND PUTTING IN CALLBACKS

    # Read from text!

    $vars->{ATTR} = \%attrs;
    my $sub_content = $self->evaluate_children(\@children, $vars);
    my $text = $self->evaluate_text($callback, {%vars, CONTENT=>$sub_content, TAG=>$node_name, ATTR=>\%attrs});


    #$text =~ s/#TAG#/$node_name/ig;
    # As this is a one-to-one mapping, there won't be a case where we want only SOME of the content.
    #if ($text =~ /#CONTENT#/i)
    #{
    #  my @evaluated_children = map { $self->evaluate_node($_, { %vars, ATTR=>\%attrs}) } @children;
    #  my $sub_content = join("", @evaluated_children);
    #  $text =~ s/#CONTENT#/$sub_content/gi;
    #}
    # Else, handle every other macro as attributes.
    $content = MalyVar->evaluate_content($text, \%attrs);
  } else { # Keep as is, evaluate children. Save as content.
    my %attrs = $self->get_node_attrs($node, $vars, 1);
    $content = $self->default_evaluate($node_name, \%attrs, \@children, $vars);
  }
  return $content;
}

sub get_end_tag
{
  my ($self, $node_name, $attrs, $vars) = @_;
  my %attrs = ref $attrs eq 'HASH' ? %$attrs : ();
  my $end_tag = "";
  if ( not grep { $node_name eq lc($_) } @NO_END_TAGS and 
    (not grep { $node_name =~ /^$_$/i } @IGNORE_TAGS_BUT_NOT_CONTENT or $vars->{_KEEPIGNORE}) 
    )
  {
    $end_tag = "</$node_name>";
  }

  return $end_tag;
}

sub get_start_tag
{
  my ($self, $node_name, $attrs, $vars) = @_;
  my %attrs = ref $attrs eq 'HASH' ? %$attrs : ();
  my $attrs_text = "";

  $attrs_text .= join(" ", map { "$_=\"$attrs{$_}\"" } sort keys %attrs);

  if ($attrs_text =~ /\w/)
  {
    $attrs_text = " $attrs_text";
  } else {
    $attrs_text = "";
  }
  my $start_tag = "";
  if (not grep { $node_name =~ /^$_$/i } @IGNORE_TAGS_BUT_NOT_CONTENT
    or $vars->{_KEEPIGNORE})
  {
    $start_tag = "<$node_name$attrs_text>";
  }

  return $start_tag;
}

sub default_evaluate
{
  my ($self, $node_name, $attrs, $children, $vars) = @_;
  my %attrs = ref $attrs ? %$attrs : ();

  my $start_tag = $self->get_start_tag($node_name, $attrs, $vars);
  my $end_tag = $self->get_end_tag($node_name, $attrs, $vars);

  my $content = $start_tag;

  if (ref $children)
  {
    foreach my $child (@$children)
    {
      $content .= $self->evaluate_node($child, $vars);
    }
  }
  $content .= $end_tag;
  return $content;
}

# For setting variables.
sub set_vars # Assumes global var setting.
{
  my ($self, $vars, $local, %values) = @_;
  if ($local)
  {
    return { (ref $vars eq 'HASH' ? %$vars : ()), %values };
  } else { # GLOBAL
    # USE STRUCT_UPDATE!!!
    MalyVar->struct_update($vars, undef, %values);
    #foreach my $key (keys %values)
    #{
    #  $vars->{$key} = $values{$key};
    #}
  }
  return $vars;
}

#################################################################
#
sub text
{
  my ($self, $node_name, $attrs, $children, $vars) = @_;
  my $t = $attrs->{text};
  my $value = MalyVar->evaluate_content($attrs->{text}, $vars);
  return $value;
}

sub comment
{
  my ($self, $node_name, $attrs, $children, $vars) = @_;
  my $value = MalyVar->evaluate_content($attrs->{text}, $vars);
  return "<!-- $value -->";
}

sub maly_comment # Actually removes content!
{
  my ($self, $node_name, $attrs, $children, $vars) = @_;
  return "";
}

sub maly_load # Conditional loading of template. If can't load, display content inside instead.
{
  # <maly-load if="conditional" file="file_to_load">if can't load file, or not content, display this</maly-load>
  # <maly-load file="unconditional_file_to_load">other content</maly-load>
  # 
  my ($self, $node_name, $attrs, $children, $vars) = @_;
  # Get all children, evaluate.

  my @files = split(",", $attrs->{"file"});

  my @files = map { MalyVar->evaluate_content($_, $vars) } split(",", $attrs->{"file"});
  my $eval = $attrs->{"eval"};
  my $file_content = undef;
  # if is false, run. if is true, check $if is true.

  my $render = $self->new($self->{GLOBAL});
  $render->{SILENT} = 1; # Don't verbally complain.
  my $conditions_met = 1;
  my $if = MalyVar->evaluate_content($attrs->{if}, $vars);
  if (defined $attrs->{if} and not ( $eval ? eval $if : $if) )
  {
    $conditions_met = 0;
  }

  foreach my $file (@files)
  {
    if ($render->filename($file) and $conditions_met)
    {
      return $render->render($file, $vars);
    }
  }

  my @content = ref $children eq 'ARRAY' ? @$children : ();
  return map { $self->evaluate_node($_, $vars) } @content;
}

sub node_as_text
{
  my ($self, $node, $vars) = @_;
  return $self->children_as_text([$node], $vars);
}

sub children_as_text
{
  my ($self, $children, $vars) = @_;
  my @children = ref $children eq 'ARRAY' ? @$children : ($children);
  my $content = "";
  foreach my $child (@children)
  {
    my $child_content = "";
    if (not ref $child)
    {
      $child_content = $child;
    } else {
      my $child_tag = $child->tag;
      if ($child_tag eq '~text')
      {
        $child_content = $child->attr("text");
      } else {
        $child->deobjectify_text;
        $child_content = $child->as_HTML();
      }
    }
    $content .= $child_content;
  }
  #my $content = join("", map { $_->as_HTML() } @children);
  return $content;
}

sub evaluate_attrs
{
  my ($self, $attrs, $vars) = @_;
  my %raw_attrs = ref $attrs eq 'HASH' ? %$attrs : ();

  my %attrs = ();
  my $old_keep_escapes = $vars->{_KEEP_ESCAPES};
  $vars->{_KEEP_ESCAPES} = 1;
  foreach my $key (keys %raw_attrs)
  {
    $attrs{$key} = MalyVar->evaluate_content($raw_attrs{$key}, $vars);
    #print STDERR "KEY=$key, VAL=$raw_attrs{$key}, NOW=$attrs{$key}\n";
  }
  $vars->{_KEEP_ESCAPES} = $old_keep_escapes;

  return %attrs;
}

sub maly_literal # No xml interpretation, no var subst (DOESNT QUITE WORK, NEEDS extra \'s!)
{
  my ($self, $node, $attrs, $children, $vars) = @_;
  my $content = $self->children_as_text($children, $vars);
  return $content;
}

sub maly_print # Just takes contents and prints out, with no xml interpretation (vars are substituted, tho)
{
  my ($self, $node, $attrs, $children, $vars) = @_;

  my $content = "";

  if ($attrs->{text}) # Print THAT instead.
  {
    $content = $attrs->{text};
  } else {
    $content = $self->children_as_text($children, $vars);
  }

  $content = MalyVar->evaluate_content($content, $vars);
  return $content;
}

sub maly_cutws # Just like maly_text, but ignores newlines inside.
{
  my ($self, $node, $attrs, $children, $vars) = @_;
  
  my @content = ref $children ? (map { $self->evaluate_node($_, $vars) } @$children) : ();
  my $content = join("", @content);
  $content =~ s/\n{2,}/\n/g;
  #$content =~ s/\s{2,}/ /g;
  $content =~ s/^\s+//g;
  $content =~ s/\s+$//g;
  return $content;
}

sub maly_text # Removes maly-text tags, for plain text display templates.
{
  my ($self, $node, $attrs, $children, $vars) = @_;
  
  return ref $children ? (map { $self->evaluate_node($_, $vars) } @$children) : ();
}

sub num_or_text_a_b { return num_or_text($a, $b); }

sub multikey_sort
{
  my ($x, $y, $pseudo, @keys) = @_;
  foreach my $key (@keys)
  {
    my $xv = MalyVar->evaluate_content("#$key#", $x, $pseudo);
    my $yv = MalyVar->evaluate_content("#$key#", $y, $pseudo);
    my $rv = num_or_text($xv, $yv);
    return $rv if ($rv != 0);
  }
}

sub num_or_text 
# FYI,
# If one is a number and the other one is the empty string, put the number first!!!!!
{ 
  my ($x, $y) = @_;
  my $xn = $x =~ /^\d+$/;
  my $yn = $y =~ /^\d+$/;
  return -1 if ($xn and $y eq '');
  return 1 if ($yn and $x eq '');
  return ($xn && $yn) ? ($x <=> $y) : (lc($x) cmp lc($y));
} 

sub maly_loop
{
  my ($self, $node_name, $attrs, $children, $vars) = @_;
  my @content = ref $children ? @$children : ();

  # <maly-loop var="HASH{KEY}ofArrayHASHES" name=HASH> Iteration Number #MALYITER# of total #MALYLOOPLENGTH# ...
  # 
  # <maly-loop var="ARRAY[index]ofArrayHASHES" name="FOO"> #FOO{KEYinHASH}# or #KEYinHASH# ...
  #
  # <maly-loop split="1,2,3,4,5,6,7" at="," name=NUMBER> #NUMBER# ...
  #
  # <maly-loop var=HASH hash=1> #KEY# = #VALUE# </maly-loop>
  # 
  # <maly-loop var="ARRAYofHASH" noset=1> just for looping purposes, no variables created ...
  #
  # <maly-loop var="ARRAYofSCALARS" name=ITEM> item #ITEM# <maly-loop>
  #
  # <maly-loop name=VALUE from=1 to=20> #VALUE# </maly-loop> , from defaults to 0 if omitted.
  #
  # <maly-loop name=VALUE from=1 to=20 by=10> #VALUE# </maly-loop> , from defaults to 0 if omitted. Loops in units of 10
  #
  # <maly-loop var="ARRAY" plus=3> ... </maly-loop> , to have 3 extra iterations, typically blank.
  #
  # <maly-loop var="ARRAY" sort=1> Default sorted </maly-loop>
  #
  # <maly-loop var="ARRAY" sort="COLUMN"> Sort by COLUMN within ARRAY's hashrefs </maly-loop>
  
  # <maly-loop var="ARRAY" sort="ARBITRARY EXPR USING $a, $b"> Arbitrary sort </maly-loop>
  #
  # <maly-loop var="ARRAY" sort=1> Default sorted </maly-loop>
  #
  # <maly-loop var="ARRAY" where="VAR"> Done only on those who meet condition, i.e., while if VAR defined, or using evaled content if not just alphanumeric </maly-loop>
  #
  # <maly-loop loopiter="FOOITER" var="ARRAY"> ... </maly-loop>
  #
  # <maly-loop name="GROUPNAME" var="ARRAY" group_count=4> Every 4 elements in ARRAY is put in the array GROUPNAME </maly-loop>
  #
  # *** IF A LOOP ITERATION DOESNT SET A VALUE, BUT THE PREVIOUS ONE DID, using top-level
  # variable declaration, then the value will be the old iteration's. ie., one must use 
  # the <maly-loop name=FOO var="BAR"> syntax to make sure the variables get cleared 
  # every iteration. ***
  #
  my $var = $attrs->{"var"};
  my $from = eval MalyVar->evaluate_content($attrs->{"from"}, $vars) || 0;
  #my $name = $attrs->{"name"} || "LOOPVAR";
  my $name = $attrs->{"name"};
  my $split = MalyVar->evaluate_content($attrs->{"split"}, $vars);
  my $at = $attrs->{"at"} || ",";
  my $hash = $attrs->{"hash"};
  my ($keyname, $valuename) = split(":", $name||"KEY:VALUE") if $hash;
  my $reverse = MalyVar->evaluate_content($attrs->{"reverse"}, $vars);
  my $sort = MalyVar->evaluate_content($attrs->{"sort"}, $vars);
  my $noset = $attrs->{"noset"}; # If set, don't actually set record.
  my $plus = MalyVar->evaluate_content($attrs->{plus}, $vars) || 0;
  my %hash = ();
  ###my $to = eval $self->evaluate_content($attrs->{"to"}, $vars);
  my $to = eval MalyVar->evaluate_content($attrs->{"to"}, $vars);
  my $by = eval MalyVar->evaluate_content($attrs->{"by"}, $vars) || 1;
  my $group_count = eval MalyVar->evaluate_content($attrs->{group_count}, $vars);
  my $itervar = $attrs->{loopvar} || "MALYITER";
  my $iternum = $attrs->{loopvarnum} || "MALYITERNUM";
  my @records = ();
  my $value = undef;
  my $dbo = undef;
  my $pseudo = undef;
  my $where = $attrs->{"where"}; # grep of key being defined or eval statement if not just \w
  my $eval = $attrs->{"eval"};
  my $fuck = $attrs->{fuck};

  $value = MalyVar->var_evaluate($vars, $var, undef);

  if ($split)
  {
    @records = split $at, $split;
  } elsif ($to ne '') { 
    for (my $x = $from; $x <= $to; $x+=$by)
    {
      push @records, int($x);
    }
  } else {
    my $ref = ref $value;
    if ($ref eq 'ARRAY')
    {
      @records = @{$value};
    } 
    # REMOVING; IF WE WANT TO ITERATE OVER A HASH, We'll use hash=1. Makes no sense why key/value pairs would all of the sudden become equivalent data (indices)
    # We are re-enabling this because we sometimes have hashrefs to maly-loop over.
    # We don't want ot use hashes to loop over, as we lose ordering. We should save it in memory as a list, then use hash appropriatey if needed.
    #elsif ($ref eq 'HASH')
    #{
    #  #@records = %$value;
    #  %hash = %$value;
    #  @records = keys %hash;
    #}
    elsif ($ref eq 'HASH' and $hash)
    {
      @records = %$value;
    }
    elsif ($ref and isa($value, "UNIVERSAL") and $value->can("records")) # Translate db object to array of hashrefs
    {
      @records = $value->records();
      $dbo = $value;
      $pseudo = $dbo->get_pseudo_meta;
    }
    elsif ($ref eq 'HASH' and $value ne '') # Just one record! And is set. Could have hashref internally.
    {
      @records = ($value);
    } 
    elsif (not $ref and $value) # scalar, just one. and not undefined!
    {
      @records = ($value);
    }
  }


  # Needs to pass objects back, so data calculation is on-the-fly.
  # BUT THIS COMPLETELY BREAKS EVERYTHING ELSE!!!!
  # Maybe we can do a records(), getting the FIRST dimension of stuff mapped. !!!!

  # Interpret record as separate entity from list
  # Interpret statusmap as same entity as list


  # ADD IMPLICIT _DBO_INDEX TO RECORDS(), SO WE CAN, AFTER SORT, USE AT_INDEX(x) DURING LOOP GET THE RIGHT ONE EACH ITER.


  my @out = ();
  my @new_content = ();

  if ($sort)
  {
    # Will sort by hash key unless explicitly something else.
    if ($sort eq '1' and not $hash)
    {
      # Pass pseudo along.
      @records = sort num_or_text_a_b @records;
    } elsif ($hash and ($sort =~ /^KEY$/ or $sort eq '1')) {
      my %hash = @records;
      my $i = 0;
      my @keys = grep { $i++ % 2 == 0 } @records;
      my @sorted_keys = sort num_or_text_a_b @keys;
      @records = map { ($_, $hash{$_}) } @sorted_keys;
    } elsif ($sort =~ /^VALUE$/ and $hash) {
      my %hash = @records;
      my @encap_records = map { {KEY=>$_, VALUE=>$hash{$_}} } keys %hash;
      @records = map { ($_->{KEY}, $_->{VALUE}) } sort { multikey_sort($a, $b, $pseudo, 'VALUE') } @encap_records;
    } elsif ($sort =~ /^\w+$/) { # Hash key
      #@records = sort { num_or_text($a->{$sort}, $b->{$sort}) } @records;
      @records = sort { multikey_sort($a, $b, $pseudo, $sort) } @records;
    } elsif ($sort =~ /^[\S,]+$/) { # MULTIPLE Hash keys (can have pseudo keys mentioned)
      my @sort_keys = split(",", $sort);
      @records = sort { multikey_sort($a, $b, $pseudo, @sort_keys) } @records;
    } else { # Arbitrary expression
      @records = eval "sort { $sort } @records";
    }
  }


  if ($hash)
  {
    %hash = @records;
    @records = grep { $i++ % 2 == 0 } @records; # Only get keys.
  }

  @records = reverse @records if $reverse; # Don't want to screw up hash keys, so will do after.

  # Should append empty ones AFTER sorted ones!
  for (my $i = 1; $i <= $plus; $i++)
  {
    if ($to ne '')
    {
      push @records, int($to+$i*$by);
    } else {
      push @records, undef;
    }
  }

  # !!! MALYITER STARTS FROM 0 no matter what!

  if ($group_count > 0)
  {
    my @original_records = @records;
    @records = ();
    for (my $i = 0; $i < @original_records; $i+=$group_count)
    {
      my $max_ix = $i+$group_count-1 > $#original_records ? $#original_records : $i+$group_count-1;
      push @records, [ @original_records[$i..$max_ix] ];
    }
  }

  my $length = @records;
  my $lastiter = $#records;
  my $loopiter = 0;

  my @old_loop_keys = ();

  my %old_vars = ref $vars eq 'HASH' ? %$vars : ();

  foreach my $record (@records)
  {
    my %metavars = ($itervar=>$loopiter++, $iternum=>$loopiter, MALYLOOPLENGTH=>$length, MALYLASTITER=>$lastiter);
    # These numbers are going to be innacurate if there is a where clause in the loop. The loopiter is ok, tho.
    if ($dbo) # So we can reference $self in any pseudo data functions properly
    {
      my $index = $record->{"_DBO_INDEX"};
      if ($index ne '')
      {
        $dbo->at_index($index);
      } else { # hmmm, just ->next
        $dbo->next;
      }
    }
    my $iter_vars = undef;
    my @hash = ();
    if ($hash)
    {
      $iter_vars = $self->set_vars($vars, undef, %metavars, $keyname=>$record, $valuename=>$hash{$record});
    } 
    elsif (ref ($record) eq 'HASH')
    {
      if ($name)
      {
        $iter_vars = $self->set_vars($vars, undef, $name=>$record, %metavars);
	@old_loop_keys = ($name);
      } else {
        my %record = $noset ? () : (%{$record});
        $iter_vars = $self->set_vars($vars, undef, %record, %metavars);
	@old_loop_keys = keys %record;
      }
    } else {
      my %record = ($name||"LOOPVAR", $record) unless $noset;
      @old_loop_keys = keys %record;
      $iter_vars = $self->set_vars($vars, undef, %record, %metavars);
	# name='foo' allows array of scalars, as well as anything else.
    }
    my $where_ok = undef;

    if ($where)
    {
      if ($where =~ /^\w+$/) # Just key to check for value
      {
        $where_ok = MalyVar->var_evaluate($record, $where);
      } else { # Expression
        $where_ok = MalyVar->evaluate_content($where, $iter_vars);
	$where_ok = eval $where_ok;# if $eval;
      }
    }

    if ($where_ok or $where eq '')
    {
      my @nct = map { $self->evaluate_node($_, $iter_vars) } @content;
      push @new_content, @nct;
    } else {
      $loopiter--;
    }

    $self->set_vars($vars, undef, map { ($_, $old_vars{$_}) } @old_loop_keys); # Reset loop vars.
  }
  # Need to reset FOO if name=FOO is given.
  $self->set_vars($vars, undef, $name, undef) if $name;
  return @new_content;
}

# Perhaps force all variables to be GLOBAL, unless explicit <maly-set local=1> set?

sub maly_set
{
  my ($self, $node_name, $attrs, $children, $vars) = @_;
  my @children = ref $children ? @$children : ();
  # <maly-set var=NAME> VALUE THAT IS NOT EVALUATED, KEPT LITERAL </maly-set>
  # <maly-set var=NAME value="SCALAR_TEXT_VALUE"/>
  # <maly-set var=NAME from="SOME_OTHER_VARIABLE_PRESERVING_HASHNESS_OR_ARRAYNESS"/>
  # <maly-set var=NAME scalar=1 from="SOME_OTHER_VARIABLE_PRESERVING_HASHNESS_OR_ARRAYNESS"/>
  # <maly-set var=NAMEtoGIVE eval=1 value="literal perl that needs to be evaluated, not just a value"/>
  # <maly-set var=NAME array=NAMEofARRAY i=n> #NAME# is the n'th in NAMEofARRAY </maly-set>
  # <maly-set var=ARRAY list="a,b,c,d,e,f"/>
  # <maly-set var=ARRAY list=1 split=":">one:Won:When\ntwo:Too:To\n...</maly-set> Turns into arrays of arrays, each line split at delim
  # <maly-set var="BLAH" value="123" if="EVAL"/>
  # <maly-set var=HASH map="a=b,c=d,e=f"/>
  # <maly-set var=HASH map="1">a=b\nc=d\ne=f</maly-set>
  # <maly-set var=HASH hash="1">a=b\nc=d\ne=f</maly-set>
  # <maly-set var=NAME eval="'#VAR#' % 2 == 0 ? 'data1' : 'data2' "/>
  # <maly-set var=NAME literal=1 value="#FOOBAR#"/> Preserves text as it is, no variable interpretation at all.
  # <maly-set var=FOO from="STRUCT1,STRUCT2" as="ARRAY"/> Merges two structs to become FOO. If ref types vary, use 'as' to force other than first found.
  # <maly-set var=FOO value="BLAH" default=1/> only set FOO to BLAH if it's not set to anything already.

  # Note that we can refer to the current var stack via '$vars' hashref

  my $var = $attrs->{var} || $attrs->{name};
  $var = MalyVar->evaluate_content($var, $vars); # Translate #XXX#
  my $eval = MalyVar->evaluate_content($attrs->{"eval"}, $vars);
  my $array = MalyVar->evaluate_content($attrs->{array}, $vars);
  my $list = MalyVar->evaluate_content($attrs->{list}, $vars);
  my $map = MalyVar->evaluate_content($attrs->{"map"}||$attrs->{"hash"}, $vars);
  my $from = MalyVar->evaluate_content($attrs->{from}, $vars);
  my $if = MalyVar->evaluate_content($attrs->{"if"}, $vars);
  my $split = MalyVar->evaluate_content($attrs->{"split"}, $vars);
  my $literal = $attrs->{literal};
  my $default = $attrs->{default};
  my $scalar = $attrs->{"scalar"};
  my $comment = $attrs->{"comment"};

  # If value="" is omitted, and eval is set, take from eval!
  if ($eval ne '' and $eval ne '1' and not exists $attrs->{value})
  {
    $attrs->{value} = $eval;
    $eval = 1;
  }

  my $content = undef;
  if ($array)
  {
    my $i = $attrs->{i};
    $content = $vars->{$array}->[$i];
  } elsif ($list) {
    if ($list eq '1')
    {
      my @child_content = map { $self->evaluate_node($_, $vars) } @children;
      my $child_content = join("", @child_content);
      my @parts = split(/\n/, $child_content);
      @parts = grep { $_ ne '' } @parts; #Skip blank lines
      if ($split)
      {
	$content = [ map { [ split(/$split/, $_) ] } @parts ];
      } else {
        $content = \@parts;
      }
    } else {
      my @list = split(",", $list);
      $content = \@list;
    }
  } elsif ($map) {
    my @parts = ();
    if ($map eq '1')
    {
      my @child_content = map { $self->evaluate_node($_, $vars) } @children;
      my $child_content = join("", @child_content);
      @parts = split(/\n/, $child_content);
      @parts = grep { $_ ne '' } @parts; #Skip blank lines
    } else {
      @parts = split(",", $map);
    }
    my @hash = map { ($a,$b) = split(/=/, $_); ($a,$b) } @parts;
    $content = \@hash;
  } elsif ($from) {
    my @from = split(",", $from);
    my @from_content = ();
    my $as = $attrs->{as};

    $content = undef;

    foreach my $eachfrom (@from)
    {
      my $from_content = MalyVar->var_evaluate($vars, $eachfrom, undef, ($as eq 'ARRAY'));
      $as ||= ref $from_content if (ref $from_content eq 'ARRAY' or ref $from_content eq 'HASH');
      $as ||= "ARRAY"; # Otherwise assume array.

      $content = MalyVar->eval_concatenate_struct($content, $as, $from_content);
    }

    $content = scalar(ref $content eq 'ARRAY' ? @$content : () ) if $scalar;
  } else {
    if (exists $attrs->{value} and $literal)
    {
      $content = $attrs->{value}; # DONT TOUCH!
    } elsif (exists $attrs->{value}) {
      ($content) = MalyVar->evaluate_content($attrs->{value}, $vars);
    } elsif (@children) { # Evaluate children (ALL)!!!
      my @child_content = map { $self->evaluate_node($_, $vars) } @children;
      $content = join("", @child_content);
      #($content) = MalyVar->evaluate_content($children[0]->attr('text'), $vars) if (not $content and ref $children[0]);
    } elsif (not exists $attrs->{value}) {  # Just set to 1 (i.e., it's a flag). value="" MUST NOT BE THERE.....
      $content = 1;
    }
  }

  my $old_value = MalyVar->var_evaluate($vars, $var);
  if ($default and (
    (ref $old_value eq 'ARRAY' and @$old_value != 0) or
    (isa($old_value, "MalyDBOCore") and $old_value->count) or
    (not ref $old_value and $old_value ne '')
    ))
  {
    return (); # Already has value!
  }

  my $content_value = $attrs->{"eval"} ? eval ($content||$eval) : $content;
  return () if ($attrs->{"if"} ne '' and not eval $if);
  $self->set_vars($vars, undef, $var, $content_value);

  if ($comment)
  {
    if ($comment eq 'js')
    {
      return "/* SET $var TO $content_value */";
    } else { #HTML
      return "<!-- SET $var TO $content_value -->";
    }
  } else {
    return ();
  }

  # This may be put where javascript is expected, but this is html comment syntax.

  return ();
}

sub quote_map
{
  my ($str) = @_;
  my $left = 1;
  my $new_str = "";
  while ($str =~ /['"]/)
  {
    my $before = $`;
    my $after = $';
    my $match = $&;
    $new_str .= $before;
    if ($before =~ /\\$/) # Ignore, it's escaped.
    {
      $new_str .= $match;
    } else { # Replace. 
      if ($left)
      {
        $new_str .= "qq{";
        $left = 0;
      } else {
        $new_str .= "}";
        $left = 1;
      }

    }
    $str = $after;
  }
  $new_str .= $str; # The end.
  return $new_str;
}

sub if_evaluate
{
  my ($self, $attrs, $vars) = @_;
  # Need to escape ' and " from var substitutions.
  # ACK, THIS IS ALREADY SUBSTITUTED
  my $eval = MalyVar->evaluate_content($attrs->{"eval"}, $vars);
  #$self->log("VALUE IS ($value), EVALSTRING=$evalstring");
  my $rc = undef;
  if (defined $eval)
  {
    $rc = eval $eval;
  } else {
    my $var = $attrs->{"var"};
    #my $value = $vars->{$var};
    $var = MalyVar->evaluate_content($var, $vars); # translate #XXX#
    my $value = MalyVar->var_evaluate($vars, $var); # use var_evaluate, since no #'s
    # Get raw value, no interpretation to scalars/text. (SINCE we use that below!)
    my $flat_value = MalyVar->get_ref_or_value($value);

    my $in = MalyVar->evaluate_content($attrs->{in}, $vars);
    my $delim = $attrs->{delim};
    my $defined = $attrs->{"defined"};
    my $ref = $attrs->{"ref"};
    my $eq = MalyVar->evaluate_content($attrs->{"eq"}, $vars);
    my $ne = MalyVar->evaluate_content($attrs->{"ne"}, $vars);
    my $grep = MalyVar->evaluate_content($attrs->{"grep"}, $vars);
    my $gt = MalyVar->evaluate_content($attrs->{"gt"}, $vars);
    my $lt = MalyVar->evaluate_content($attrs->{"lt"}, $vars);
    my $ge = MalyVar->evaluate_content($attrs->{"ge"}, $vars);
    my $le = MalyVar->evaluate_content($attrs->{"le"}, $vars);
    my $regex = $attrs->{"regex"};

    # If array or hash ref, also verify that has elements.
    if ($ref)
    {
      if ($ref eq '1')
      {
        $rc = ref $value;
      } else {
        $rc = (ref $value eq $ref); # Given a specific type to check
      }
    }

    if (defined $gt) {
      $rc = ($flat_value > $gt)
    } elsif (defined $ge) {
      $rc = ($flat_value >= $ge);
    } elsif (defined $lt) {
      $rc = ($flat_value < $lt);
    } elsif (defined $le) {
      $rc = ($flat_value <= $le);
    } elsif (defined $eq) {
      $rc = ($flat_value eq $eq);
    } 
    elsif (defined $regex)
    {
      $rc = eval "'$flat_value' =~ /$regex/";
    }
    elsif (defined $ne) 
    {
      $rc = ($flat_value ne $ne);
    }
    elsif (defined $in) 
    {
      my @list = ();
      my $in_ref = MalyVar->var_evaluate($vars, $in, undef, 1); # FIXED!
      if (ref $in_ref eq 'ARRAY')
      {
        @list = @{$in_ref};
      } elsif ($in_ref and not ref $in_ref) {
        $delim ||= "[,; ]";
        @list = split(/$delim/, $in_ref);
      } elsif ($in) { # Try just literal string.
        $delim ||= "[,; ]";
        @list = split(/$delim/, $in);
      }
      $rc = grep { /^$flat_value$/i } @list;
    }
    elsif (ref $value eq 'ARRAY')
    {
      $rc = scalar @{$value};
    } 
    elsif (ref $value eq 'HASH')
    {
      $rc = scalar keys %{$value};
    } 
    elsif (isa($value, "MalyDBOCore"))
    {
      $rc = $value->count;
    } else {
      # THIS IS CHANGED 12/10/2003, SO WE ONLY BE TRUE ON NON-FALSE (i.e., '0' is STILL false). If we want to say '0' is true, set defined=1 in the maly-if
      $rc = $defined ? (defined $value) : ($value);
      #$rc = $defined ? (defined $value) : ($value ne '');
    }
  }
  $rc = !$rc if ($attrs->{"not"});
  return $rc;
}

sub maly_if
{  
  my ($self, $node_name, $attrs, $children, $vars) = @_;
  my @children = ref $children eq 'ARRAY' ? @$children : ();

  # <maly-if eval='something to evaluate in perl'>
  # print this content if true
  # <maly-else/>
  # print this content if false.
  # </maly-if>
  #
  # <maly-if var=foo> content if foo is not false </maly-if>
  #
  # <maly-if defined=1 var=foo> content if foo is DEFINED </maly-if>
  #
  # <maly-if var=bar eq="10"> content if bar is 10 </maly-if>
  #
  # <maly-if var=FOO ref=ARRAY> If FOO is an ARRAY REF </maly-if>
  #
  # <maly-if var=FOO ref=1> If FOO is a reference (TO ANYTHING) </maly-if>
  #
  # <maly-if var=perlarrayref> content to print if var is array ref and has values </maly-if>
  #
  # <maly-if var=hashref> content to print if var is hash ref and has values </maly-if>
  #
  # <maly-if not=1 var=foo> Content if foo is false </maly-if>
  # 
  # <maly-if var=foo regex="^Something"> Content if foo matches regex </maly-if>
  # 
  # <maly-if var=foo in="list" delim=','> Found foo in LIST (STRING or ARRAY) (DELIM defaults to ',: ') </maly-if>
  #
  # <maly-if eval="PERL CODE">...</maly-if> BE CAREFUL TO NOT HAVE MACROS WHICH MAY SUBSTITUTE AND CAUSE SYNTAX ERRORS.
  #
  # <maly-if ...> TRUE CONTENT <maly-else/> FALSE CONTENT </maly-if>
  # 
  # <maly-if ...> CONTENT 1 <maly-elsif .../> CONTENT 2 </maly-if>
  #
  #

  my $rc = undef;

  if ($node_name eq 'maly-else')
  {
    $rc = 1; # If we hit here, we ALWAYS will want it.
  } else { # maly-if or maly-elsif
    $rc = $self->if_evaluate($attrs, $vars);
  }

  # Either way, get stuff up until next maly-else/elsif tag.

  my @true_content = ();
  while(my $child = $children[0])
  {
    if ($child->tag =~ /^maly-els(e|if)$/) # Marks new block
    {
      last;
    } else { # ok, put on true_content;
      push @true_content, shift @children;
    }
  }

  if ($rc)
  {
    my @evaluated_children = map { $self->evaluate_node($_, $vars) } @true_content;
    return join("", @evaluated_children);
  } elsif (@children and ref $children[0]) { # Skip to next block, call again.
    my $new_node = shift @children;
    my $new_node_name = $new_node->tag;
    my %new_attrs = $self->get_node_attrs($new_node, $vars);
    $self->maly_if($new_node_name, \%new_attrs, \@children, $vars);
  } else { # Didnt find
    return "";
  }
}

sub get
{
  my (@params) = @_;
  return MalyVar->get(@params);
}


1;
