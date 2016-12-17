package DJabberd::Plugin::Privacy;

use warnings;
use strict;
use base 'DJabberd::Plugin';

use constant {
	PRIVACY => "jabber:iq:privacy",
	BLOCKING => "urn:xmpp:blocking"
};

our $logger = DJabberd::Log->get_logger();

=head1 NAME

DJabberd::Plugin::Privacy - Implements XEP-0016 Privacy Lists

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Implements XEP-0016 Privacy Lists - a part of XMPP Advanced Server specification.

    <VHost mydomain.com>
	<Plugin DJabberd::Plugin::Privacy />
	<Plugin DJabberd::... other delivery plugins: Local, S2S, Offline />
    </VHost>

The base implementation will merely advertise feature and respond to basic management
commands. Not being able to store the list it will never filter. Use storage-enabled
overriden implementation instead.

Make sure privacy is the first delivery plugin ever. It registers delivery hook
and according to XEP-0016 it MUST the very first delivery rule [2.2.4].

=cut

=head2 register($self, $vhost)

Register the vhost with the module.

=cut

use Data::Dumper;
sub register {
    my ($self,$vhost) = @_;
    my $manage_cb = sub {
	my ($vh, $cb, $iq) = @_;
	if($iq->isa("DJabberd::IQ") && !$iq->to) {
	    if ($iq->signature eq 'get-{'.PRIVACY.'}query') {
		$logger->debug("Privacy Query: ".$iq->as_xml);
		$self->query_privacy($iq,$vh);
		$cb->stop_chain;
		return;
	    } elsif ($iq->signature eq 'set-{'.PRIVACY.'}query') {
		$logger->debug("Privacy Modify: ".$iq->as_xml);
		$self->set_privacy($iq,$vh);
		$cb->stop_chain;
		return;
	    } elsif($iq->signature eq 'get-{'.BLOCKING.'}blocklist') {
		$logger->info("Blocking Query: ".$iq->as_xml);
		$self->query_blocking($iq,$vh);
		$self->{blkiq}->{$iq->from} = 1; # remember this one - block list user
		$cb->stop_chain;
	    } elsif($iq->signature eq 'set-{'.BLOCKING.'}block' or $iq->signature eq 'set-{'.BLOCKING.'}unblock') {
		$logger->info("Blocking/Unblocking: ".$iq->as_xml);
		$self->set_blocking($iq,$vh);
		$cb->stop_chain;
	    }
	}
	$cb->decline;
    };
    my $filter_cb = sub {
	my ($vh, $cb, $iq) = @_;
	if(($iq->isa("DJabberd::IQ") || $iq->isa("DJabberd::Presence") || $iq->isa("DJabberd::Message")) and defined $iq->from) {
	    $logger->debug("Checking privacy for ".$iq->element_name);
	    if(my $jid = $self->match_inflight_stanza($vh,$iq)) {
		$self->block($vh,$iq,$jid);
		$cb->stop_chain;
		return;
	    }
	}
	$cb->decline;
    };
    my $cleanup_cb = sub {
	my ($vh, $cb, $conn, $pres) = @_;
	# Remove active lists for closing sessions - if any
	if($conn->isa("DJabberd::Connection::ClientIn")) {
	    my $jid = $conn->bound_jid;
	    if($jid && ref($jid) && $jid->isa("DJabberd::JID")) {
		my $jids = $jid->as_string;
		# Active list - if any
		delete $self->{lists}->{$jids} if(exists $self->{lists}->{$jids});
		# Block List User
		delete $self->{blkiq}->{$jids} if(exists $self->{blkiq}->{$jids});
	    } else {
		$logger->debug("No bound jid".Dumper($conn));
	    }
	} else {
	    $logger->debug("Not a connection".Dumper($conn));
	}
	$cb->decline;
    };
    $vhost->register_hook("deliver",$filter_cb);
    $vhost->register_hook("switch_incoming_client",$manage_cb);
    $vhost->register_hook("AlterPresenceUnavailable",$cleanup_cb);
    $vhost->register_hook("ConnectionClosing",$cleanup_cb);
    $vhost->add_feature(PRIVACY);
    $vhost->add_feature(BLOCKING);
}

sub fail {
    my $self =   shift;
    my $stanza = shift;
    my $subj =   shift || "bad-request";
    my $error =  shift || "cancel";
    my $text =   shift || '';
    if(!$stanza || !$stanza->isa("DJabberd::Stanza")) {
	$logger->error("Privacy error: $error$subj$text");
    }
    $stanza->send_error(
	'<error type="'.$error.'">'
	.'<'.$subj.' xmlns="urn:ietf:params:xml:ns:xmpp-stanzas"'.(($text)?">$text</$subj>":' />')
	.'</error>'
    );
}

sub query_privacy {
    my $self = shift;
    my $iq = shift;
    my $jid = $iq->connection->bound_jid;
    my @kids = grep {ref($_) && $_->element_name eq 'list'} $iq->first_element->children;
    if(@kids) {
	if($#kids) {
	    $self->fail($iq,0,'modify');
	} else {
	    my $name = $kids[0]->attr('{}name');
	    my $list = $self->get_priv_list($jid,$name);
	    if(ref($list)) {
		    my $xml = '<query xmlns="'.PRIVACY.'">';
		    $xml .= '<list name="'.$name.'"';
		    if(@{$list->{items}}) {
			$xml .= '>';
			foreach my $item(@{$list->{items}}) {
			    $xml .= '<item';
			    foreach my $att(keys(%{$item})) {
				$xml .= (" $att=\"".$item->{$att}.'"') unless(!$item->{$att} or ref($item->{$att}));
			    }
			    if(exists $item->{element} and ref($item->{element}) eq 'HASH') {
				$xml .= '>';
				foreach my$element(keys(%{$item->{element}})) {
				    $xml .= "<$element/>" if($item->{element}->{$element});
				}
				$xml .= '</item>';
			    } else {
				$xml .= '/>';
			    }
			}
			$xml .= '</list>';
		    } else {
			$xml .= '/>';
		    }
		    $xml .= '</query>';
		$iq->send_result_raw($xml);
	    } else {
		$self->fail($iq,'item-not-found');
	    }
	}
    } else {
	my @lists = $self->get_priv_lists($jid);
	my $default = $self->get_default_priv_list($jid);
	my $active = $self->get_active_priv_list($jid);
	$active = ((ref($active) eq 'HASH' && exists $active->{name})?'name="'.$active->{name}.'"':'');
	$default = ((ref($default) eq 'HASH' && exists $default->{name})?'name="'.$default->{name}.'"':'');
	my $xml = '<query xmlns="'.PRIVACY.'">';
	$xml .= "<active $active/>";
	$xml .= "<default $default/>";
	foreach my $list(@lists) {
	    $xml .= ('<list name="'.$list->{name}.'"/>');
	}
	$xml .= '</query>';
	$iq->send_result_raw($xml);
    }
}

sub is_blocking_item {
    my $item = shift;
    # Type: JID; Action: Deny; Stanzas: All - that one is proper blocklist item. Anything else - does not comply, living in privacy list space only
    return (exists $item->{type} && $item->{type} eq 'jid' && $item->{action} eq 'deny' && !($item->{elements} && ref($item->{elements}) eq 'HASH' && %{$item->{elements}}));
}
sub query_blocking {
    my $self = shift;
    my $iq = shift;
    my $vhost = shift;
    my $jid = $iq->connection->bound_jid;
    my $bloxml;
    my $list = $self->get_default_priv_list($jid);
    if($list && ref($list) eq 'HASH' && exists $list->{name}) {
	$logger->debug("Using default list ".$list->{name}." as blocklist");
	foreach my $item(@{$list->{items}}) {
	    if(is_blocking_item($item)) {
		$bloxml = ($bloxml || "").'<item jid="'.$item->{value}.'"/>';
	    }
	}
    }
    $iq->send_result_raw($bloxml);
}

# TODO: XEP-0016 2.10 says we need to send presence unavailable to the client which just blocked incoming presence
# tracking this though is a bit tough - user may set it right in active list or he may activate preset list
sub set_privacy {
    my $self = shift;
    my $iq = shift;
    my $vhost = shift;
    my $jid = $iq->connection->bound_jid;
    my @kids = grep {ref($_) && $_->element_name =~ /^(?:list|active|default)$/} $iq->first_element->children;
    if($#kids == 0) {
	my $el = $kids[0];
	if($el->element_name eq 'active' or $el->element_name eq 'default') {
	    my $name = $el->attr('{}name');
	    my $list;
	    if($name) {
		$list = $self->get_priv_list($jid,$name);
		if(!$list || ref($list) ne 'HASH') {
		    $self->fail($iq,'item-not-found');
		    return;
		}
	    }
	    if($el->element_name eq 'active') {
		# Active is single-use, no dependencies
		$self->set_active_priv_list($jid,$list);
	    } elsif($el->element_name eq 'default') {
		my $def = $self->get_default_priv_list($jid);
		# If default list is defined and differs from this one
		if($def && ref($def) eq 'HASH' && $def->{name} ne $name) {
		    # Need to check for conflicts - don't change default in use by other connected users (silly)
		    foreach my $c($vhost->find_conns_of_bare($jid)) {
			# basically we're checking if other resources having own(active) list or rely on default
			my $bj=$c->bound_jid->as_string;
			next if(exists $self->{$bj} && ref($self->{$bj}) eq 'HASH'); # this one has active, skip
			# no active list, client is using default, hence conflict
			$self->fail($iq,'conflict');
			return;
		    }
		    $self->set_default_priv_list($jid,$list);
		}
	    }
	    $iq->send_result;
	    return;
	} elsif($el->element_name eq 'list') {
	    my $name = $el->attr('{}name');
	    if($name) {
		my $list = {name => $name};
		if($el->children) {
		    my @items;
		    # a list submission - parse and map
		    foreach my$ce ($el->children) {
			if($ce->element_name eq 'item') {
			    # First of all only item elements are allowed
			    my $item = {};
			    my %att = %{$ce->attrs};
			    # Optional attributes validation
			    if(!exists $att{'{}type'}
				    or ($att{'{}type'} eq 'jid' || $att{'{}type'} eq 'subscription' || $att{'{}type'} eq 'group'
				    and exists $att{'{}value'})) {
				# Mandatory attribute validation
				if(exists $att{'{}order'} && $att{'{}order'} >= 0 and exists $att{'{}action'} && $att{'{}action'} =~ /allow|deny/) {
				    if(exists $att{'{}type'}) {
					$item->{type} = $att{'{}type'};
					$item->{value} = $att{'{}value'};
					# Group should be pre-validated. However one may delete it later, so who cares.
				    }
				    $item->{order} = $att{'{}order'};
				    $item->{action} = $att{'{}action'};
				    if($ce->children) {
					# Optional stanza type elements
					$item->{element} = {map{$_->element_name=>1}$ce->children};
				    }
				    if(!grep{!/(iq|message|presence-in|presence-out)/}keys(%{$item->{element} || {}})) {
					# Final check that we didn't assign some trash to the elements
					push(@items,$item);
					next;
				    }
				}
			    }
			}
			# If everything is good we never reach this point but switching by next statement above
			$self->fail($iq);
			return;
		    }
		    # sort according to the order and add to the list
		    $list->{items} = [ sort{$a->{order} <=> $b->{order}}@items ];
		} else {
		    # List removal. Check for conflicts - if it's in use as default or active
		    # ... Strange that it's not required for list modifications.
		    # First check whether it is default list
		    my $def = $self->get_default_priv_list($jid);
		    $def=($def && $def->{name} eq $name);
		    # Then check other online resources
		    foreach my $c($vhost->find_conns_of_bare($jid)) {
			my $bj=$c->bound_jid->as_string;
			# If uses our list as active OR doesn't use active but our is default - it's a conflict
			if((exists $self->{$bj} && ref($self->{$bj}) eq 'HASH' && $self->{$bj}->{name} eq $name)
			    or ((!exists $self->{$bj} || !$self->{$bj}) && $def)) {
			    $self->fail('conflict');
			    return;
			}
		    }
		}
		# Try to store list
		if(my$sr=$self->set_priv_list($jid,$list)) {
		    if($sr>0) {
			# Broadcast modified list name to all connected resources (XEP-0016 2.6)
			my $piq = DJabberd::IQ->new('','iq',{type=>'set'},[],'<query xmlns="'.PRIVACY.'"><list name="'.$name.'" /></query>');
			foreach my $c ($vhost->find_conns_of_bare($jid)) {
			    next if($c->bound_jid->as_string eq $jid->as_string);
			    $piq->set_to($c->bound_jid);
			    $piq->deliver($c);
			}
		    }
		    $iq->send_result();
		} else {
		    # happens
		    $self->fail('service-unavailable');
		}
		return;
	    }
	}
    }
    $self->fail($iq,0,'modify');
}

sub set_blocking {
    my $self = shift;
    my $iq = shift;
    my $vhost = shift;
    my $jid = $iq->connection->bound_jid;
    my $op = $iq->first_element->element_name;
    my @kids = grep {ref($_) && $_->element_name eq 'item'} $iq->first_element->children;
    my $list = $self->get_default_priv_list($jid);
    # If list is not set or defined - we need to auto-create it
    my $active;
    my @presence;
    if($list && ref($list) eq 'HASH' && exists $list->{name}) {
	$active = 1;
    } else {
	$list = { name => 'autoblocklist', items => []};
    }
    if($#kids >= 0) {
	# We cannot unblock someone in empty list
	if($op eq 'unblock' and !$active) {
	    $logger->error("Selective unblock on empty list: ".$iq->as_xml);
	    $self->fail($iq);
	    return;
	}
	# Blocking elements should have higher precedence hence prepend them
	foreach my $kid(@kids) {
	    my $jid = DJbberd::JID->new($kid->attr('{}jid'));
	    if($jid && ref($jid)) {
		my $pst;
		if($op eq 'block') {
		    # prepend blocking items to the list
		    unshift(@{$list->{items}},{type=>'jid',value=>$jid->as_string,action=>'deny'});
		    # add unavailable presence for blocked contacts
		    $pst = DJabberd::Presence->unavailable_stanza();
		} else {
		    # pull the needle from the haystack - very inefficicent
		    $list->{items} = [ grep{!(is_blocking_item($_) && $_->{value} eq $jid->as_string)}@{$list->{items}} ];
		    # add available presence for unblocked contacts
		    $pst = DJabberd::Presence->available_stanza();
		}
		$pst->set_to($jid);
		push(@presence,$pst);
	    } else {
		$self->fail($iq,'jid-malformed','modify');
		return;
	    }
	}
    } else {
	# Unblock could be selective or (un)cover-all, block must be specific
	if($op eq 'unblock') {
	    if($active) {
		# we have some list applied, let clean it up
		my @items = @{$list->{items}};
		$list->{items} = [];
		# We need to iterate through the list since it may contain privacy items
		foreach my$item(@items) {
		    if(is_blocking_item($item)) {
			my $pst = DJabberd::Presence->available_stanza();
			$pst->set_to(DJabberd::JID->new($item->{value}));
			push(@presence,$pst);
		    } else {
			# Return Privacy List item to the list
			push(@{$list->{items}},$item);
		    }
		}
	    }
	} else {
	    $self->fail($iq);
	    return;
	}
    }
    # And yes, XEP-0191 allows updating list which is in use, just notify users
    $self->set_default_priv_list($jid,$list);
    # Even if we fail to persistently store it - list will still be cached and hence active, so let's ack it
    $iq->send_result;
    # Broadcast modifications to all connected resources
    # Those which requested block list - receive original change [XEP-0191 3.3.8], others - priv.list name [XEP-0016 2.6]
    $iq->set_from;
    my $piq = DJabberd::IQ->new('','iq',{type=>'set'},[],'<query xmlns="'.PRIVACY.'"><list name="'.$list->{name}.'" /></query>') if($active);
    foreach my $c ($vhost->find_conns_of_bare($jid)) {
	next if($c->bound_jid->as_string eq $jid->as_string);
	if($self->{blkiq}->{$c->bound_jid->as_string}) {
	    $iq->set_to($c->bound_jid);
	    $iq->deliver($c);
	} elsif($piq) {
	    # I wonder how these guys would react to someone updating list in use
	    $piq->set_to($c->bound_jid);
	    $piq->deliver($c);
	}
    }
    # send presence to all affected blocks (if they are subscribed)
    # TODO: get roster and check presence subscription
    foreach my $pst(@presence) {
	$pst->deliver($vhost);
    }
}

sub set_active_priv_list {
    my $self = shift;
    my $jid = shift;
    my $list = shift;
    $self->{lists}->{$jid->as_bare_string} = $list;
}
sub get_active_priv_list {
    my $self = shift;
    my $jid = shift;
    # Active list is session-bound hence runtime-only parameter
    return $self->{lists}->{$jid->as_bare_string} if(exists $self->{lists}->{$jid->as_bare_string} && ref($self->{lists}->{$jid->as_bare_string}));
    return undef;
}
sub is_cached_priv_list {
    my $self = shift;
    my $jids = shift;
    my $name = shift;
    return (exists $self->{lists}->{$jids} && ref($self->{lists}->{$jids}) eq 'HASH' && exists $self->{lists}->{$jids}->{name} && $self->{lists}->{$jids}->{name} eq $name);
}

sub set_default_priv_list {
    my $self = shift;
    my $jid = shift;
    my $list = shift;
    return undef unless($list && ref($list));
    $list->{default} = 1;
    $self->{lists}->{$jid->as_bare_string} = $list;
    return $self->store_priv_list($jid,$list);
}
sub get_default_priv_list {
    my $self = shift;
    my $jid = shift;
    my $bjid = $jid->as_bare_string;
    return $self->{lists}->{$bjid} if($self->{lists}->{$bjid} && ref($self->{lists}->{$bjid}) eq 'HASH');
    my $list = $self->get_priv_list($jid,undef,1);
    $self->{lists}->{$jid->as_bare_string} = $list if($list && ref($list) eq 'HASH');
    return $list;
}

sub set_priv_list {
    my $self = shift;
    my $jid = shift;
    my $list = shift;
    $self->set_active_priv_list($jid,$list) if($self->is_cached_priv_list($jid->as_string,$list->{name}));
    if($self->is_cached_priv_list($jid->as_bare_string,$list->{name})) {
	return $self->set_default_priv_list($jid,$list);
    } else {
	return $self->store_priv_list($jid,$list);
    }
}

sub get_priv_lists {
    my $self = shift;
    my $jid = shift;
    $logger->error("Not Implemented: Must Override");
    return ();
}

sub store_priv_list {
    my $self = shift;
    my $jid = shift;
    my $list = shift;
    $logger->error("Not Implemented: Must Override");
    return undef;
}

sub get_priv_list {
    my $self = shift;
    my $jid = shift;
    my $name = shift;
    my $def = shift;
    $logger->error("Not Implemented: Must Override");
    return undef;
}

# One may override it with cache-able call but then need to invalidate on roster updates
sub get_ritem {
    my $self = shift;
    my $vhost = shift;
    my $jidu = shift;
    my $jido = shift;
    my $d = shift;
    if($jidu && $jido) {
	$vhost->run_hook_chain(phase => "RosterLoadItem", args => [$jidu,$jido], methods => {
	    error => sub {
		$logger->error("RosterLoadItem failed: ".$_[0]);
	    },
	    set => sub {
		my ($cb,$ri) = @_;
		#$logger->debug("Retrieved RosterItem ".$ri->name." <".$ri->jid.">(".join(',',$ri->groups).")".$ri->subscription->as_string);
		${$d} = $ri || 0;
	    }
	});
    }
    $logger->debug("Returning with ".${$d});
    return ${$d};
}

my %submap = ('none'=>0, 'to' => 1, 'from' => 2, 'both' => 3);
sub ritem_match {
    my $ritem = shift;
    my $item = shift;
    # If user is on roster - check attributes
    if($ritem && ref($ritem)) {
	# For subscription pending states are ignored, only facts matter
	return 1 if($item->{type} eq 'subscription' and ($ritem->subscription->as_bitmask & 3) == $submap{$item->{value}});
	return 1 if($item->{type} eq 'group' && grep {$_ eq $item->{value}} $ritem->groups);
    } elsif($item->{type} eq 'subscription' and $item->{value} eq 'none') {
	# 'none' subsciption applies to unknown users (not in the roster) - XEP-0016 2.1
	return 1;
    }
    return 0;
}

sub jid_match {
    my ($jid,$str) = @_;		# To follow XEP-0016 2.1 we need to compare in following order
    return $jid->as_string eq $str	# <user@domain/resource> (only that resource matches)
	|| $jid->as_bare_string eq $str	# <user@domain> (any resource matches)
	|| (!$jid->is_bare && $jid->domain.'/'.$jid->resource eq $str)	# <domain/resource> (only that resource matches)
	|| $jid->domain eq $str;	# <domain> (the domain itself matches, as does any user@domain or domain/resource)
}

sub match_priv_list {
    my $self = shift;
    my $list = shift;
    my $stanza = shift;
    my $vhost = shift;
    my $dir = shift || 'in';
    my $jidu = (($dir eq 'in')?$stanza->to_jid:$stanza->from_jid); # user's jid
    my $jido = (($dir eq 'in')?$stanza->from_jid:$stanza->to_jid); # other's jid
    my $ritem;
    return 0 unless(exists $list->{items} && ref($list->{items}));
    $logger->debug("Checking ".scalar(@{$list->{items}})." privacy rules");
    # Iterate through all rules. Assume they are sorted already according to order attribute
    foreach my $item (@{$list->{items}}) {
	# Rules could be stanza-specific or typeless (match-all)
	if(ref($item->{element}) eq 'HASH' && %{$item->{element}}) {
	    # Check if rule is typed - for specific stanza types
	    #$logger->debug("Checking elements: ".join(',',keys(%{$item->{element}})));
	    if($stanza->isa("DJabberd::Presence") && exists$item->{element}->{"presence-$dir"}) {
		# XEP-0016 2.10, 2.11 - only ignore presence state, not probe/subscription
		next if($stanza->type && $stanza->type ne 'unavailable');
	    } else {
		# skip this rule, it's typed but stanza type is different, or it's outbound
		next if($dir eq 'out' or !$item->{element}->{$stanza->element_name});
	    }
	}
	# Either untyped rule or with matching type, check conditions
	# Conditions could be attribute specific or empty (match-any)
	if(exists $item->{type} && $item->{type}) {
	    #$logger->debug("Checking conditions: ".$item->{type}."=".$item->{value});
	    if($item->{type} eq 'group' or $item->{type} eq 'subscription') {
		# Group and subscription need to expand user's roster to check group membership or status
		# However roster loading process could be timely, so either we need to preload rosters or
		# we'd rather ignore group filters if none of the users is online. No harm unless we support XEP-0012
		$ritem = $self->get_ritem($vhost,$jidu,$jido,\$ritem) unless(defined $ritem);
		if(ritem_match($ritem,$item)) {
		    $logger->debug("Roster match: ".$item->{type}."/".$item->{value}.", action ".$item->{action});
		    return $item->{action} eq 'deny';
		}
	    } elsif($item->{type} eq 'jid') {
		if(jid_match($jido,$item->{value})) {
		    $logger->debug("JID[".$item->{value}."] match, action ".$item->{action});
		    return $item->{action} eq 'deny';
		}
	    }
	} else {
	    # Unconditional match - catch-all
	    $logger->debug("Catch-all match, action ".$item->{action});
	    return $item->{action} eq 'deny';
	}
    }
    return 0;
}
sub match_inflight_stanza {
    my $self = shift;
    my $vhost = shift;
    my $stanza = shift;
    my $from = $stanza->from_jid;
    my $to = $stanza->to_jid;
    my $ret;
    my $list;
    # Specification explicitly denies blocking cross-resource stanzas, even if explicit list item is defined.
    return 0 if($from->as_bare_string eq $to->as_bare_string);
    # First check inbound stanzas - recipient's list if recipient is local
    $list = ($self->get_active_priv_list($to) || $self->get_default_priv_list($to)) if($vhost->handles_jid($to));
    # If we have a list - user wants to filter something
    if(ref($list) eq 'HASH' and exists $list->{name}) {
	$logger->debug("Matching incoming traffic for ".$to->as_string." with ".$list->{name});
	$ret = $to if($self->match_priv_list($list,$stanza,$vhost));
    }
    # Now user may want to filter outbound as well. We have explicit presence-out case
    # Plus XEP-0016 2.13 clarifies that typeless rules also apply to any outgoing stanzas
    if(!$ret && $vhost->handles_jid($from)) {
	#$logger->debug("Outgoing check for ".$from->as_string);
	$list = ($self->get_active_priv_list($from) || $self->get_default_priv_list($from));
	if(ref($list) eq 'HASH' and exists $list->{name}) {
	    # Sender list exists - hence need to apply
	    $logger->debug("Matching outgoing traffic for ".$from->as_string." with ".$list->{name});
	    $ret = $from if($self->match_priv_list($list,$stanza,$vhost,'out'));
	}
    }
    return $ret;
}

sub block {
    my $self = shift;
    my $vhost = shift;
    my $stanza = shift;
    my $owner = shift;
    $logger->info("BOOM! Stanza is blocked: ".$stanza->as_xml);
    # Be polite and compliant - send responses as perscribed in XEP-0016 2.14
    # Presence - ignore (drop)
    return if($stanza->isa("DJabber::Presence"));
    # Message and IQ{get|set} - error <service-unavailable/>, drop others
    if(($stanza->isa("DJabber::Message") and $stanza->type ne 'groupchat')
	or ($stanza->isa("DJabberd::IQ") and $stanza->type eq 'get' || $stanza->type eq 'set'))
    {
	my $err;
	if($owner && $stanza->from_jid->as_bare_string eq $owner->as_bare_string && $stanza->isa("DJabber::Message")) {
	    # XEP-0191 mandates to inform blocker with other error type as well as app-specific blocking condition
	    $err = $stanza->make_error_response(503,'cancel','not-acceptable');
	    my @err = grep{$_->element_name eq 'error'}$err->children;
	    $err[0]->push_child(DJabberd::XMLElement->new(BLOCKING.':errors','blocked',{},[]));
	} else {
	    $err = $stanza->make_error_response(503,'cancel','service-unavailable');
	}
	$err->deliver;
    }
}

=head1 AUTHOR

Ruslan N. Marchenko, C<< <me at ruff.mobi> >>

=head1 COPYRIGHT & LICENSE

Copyright 2016 Ruslan N. Marchenko, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of DJabberd::Plugin::Privacy
# vim:sts=4:
