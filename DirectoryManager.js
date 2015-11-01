function cross_reference_view(sel, tree, oc)
{
  var dn;
  if (!sel.type)
  {
    dn = sel; // It's already a string!
  } else {
    dn = new String(get_field_value(sel));
  }
  if (!dn || dn == '') { return; }
  // NOW, must assert in DN format.
  // Otherwise, complain.
  // THEN, can extract RDN to generate query.
  var dn_parts = dn.match(/^([^,]+)/);
  if (!dn_parts || dn_parts.length == 0)
  {
    alert("Cannot cross reference, MUST be in LDAP DN format.");
    return;
  }
  var rdn = dn_parts[0];

  windowOpen('cgi-bin/View.pl/'+tree+'/'+oc+'/'+rdn+'?popup=1', 'view');
}

function link_search(tree, oc, key, vals)
{
  var filter = vals.length > 1 ? "(|" : "";
  for(var i = 0; i < vals.length; i++)
  {
    filter = filter + "(" + key + "=" + vals[i] + ")";
  }
  if (vals.length > 1)
  {
    filter = filter + ")";
  }
  windowOpen('cgi-bin/Search.pl/'+tree+'/'+oc+'/'+filter+'?action=Search&popup=1', 'link_search_'+oc);

}

function link_view(tree, oc, key, val)
{
  windowOpen('cgi-bin/View.pl/'+tree+'/'+oc+'/'+key+'='+val+'?popup=1', 'link_view_'+oc);

}

function helpPopup(page)
{
  windowOpen('docs/'+page, 'help_popup', 400, 400);
}
