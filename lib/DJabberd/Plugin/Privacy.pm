package DJabberd::Plugin::Privacy;

use warnings;
use strict;
use feature 'current_sub';
use base 'DJabberd::Plugin';

use POSIX qw(strftime);

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
	    }
	}
	$cb->decline;
    };
    my $filter_cb = sub {
	my ($vh, $cb, $iq) = @_;
	if(($iq->isa("DJabberd::IQ") || $iq->isa("DJabberd::Presence") || $iq->isa("DJabberd::Message")) and defined $iq->from) {
	    $logger->debug("Checking privacy for ".$iq->element_name);
	    if($self->match_inflight_stanza($vh,$iq)) {
		$self->block($vh,$iq);
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
	    my $jid = $conn->bound_jid->as_string;
	    delete $self->{lists}->{$jid} if(exists $self->{lists}->{$jid});
	}
	$cb->decline;
    };
    $vhost->register_hook("deliver",$filter_cb);
    $vhost->register_hook("switch_incoming_client",$manage_cb);
    $vhost->register_hook("AlterPresenceUnavailable",$cleanup_cb);
    $vhost->add_feature(PRIVACY);
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
	$active = (ref($active)?'name="'.$active->{name}.'"':'');
	$default = (ref($default)?'name="'.$default->{name}.'"':'');
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

# TODO: XEP-0016 2.10 says we need to send presence unavailable to the client which just blocked incoming presence
# tracking this though is a bit tough - user may set it right in active list or he may activate preset list
sub set_privacy {
    my $self = shift;
    my $iq = shift;
    my $vhost = shift;
    my $jid = $iq->connection->bound_jid;
    my @kids = grep {ref($_) && $_->element_name =~ /list|active|default/} $iq->first_element->children;
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
    return (exists $self->{lists}->{$jids} && ref($self->{lists}->{$jids}) eq 'HASH' && $self->{lists}->{$jids}->{name} eq $name);
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
    my $d = { ritem => undef };
    if($jidu && $jido) {
	$vhost->run_hook_chain(phase => "RosterLoadItem", args => [$jidu,$jido], methods => {
	    error => sub {
		$logger->error("RosterLoadItem failed: ".$_[0]);
	    },
	    set => sub {
		$d->{rtiem} = $_[0];
	    }
	});
    }
    return $d->{ritem};
}

sub match_ritem {
    my $ritem = shift;
    my $item = shift;
    if($ritem && ref($ritem)) {
	return 1 if($item->{type} eq 'subscription' and $ritem->subscription eq $item->{value});
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
    return 0 unless(exists $list->{items} && ref($list->{items}));
    # Iterate through all rules. Assume they are sorted already according to order attribute
    foreach my $item (@{$list->{items}}) {
	# Rules could be stanza-specific or typeless (match-all)
	if(ref($item->{element}) eq 'HASH' && @{$item->{element}}) {
	    # Check if rule is typed - for specific stanza types
	    if($stanza->isa("DJabberd::Presence") && exists$item->{element}->{"presence-$dir"}) {
		# XEP-0016 2.10, 2.11 - only ignore presence state, not probe/subscription
		next if($stanza->type && $stanza->type ne 'unavailable');
	    } else {
		# skip this rule, it's typed but stanza type is different, or it's outbound
		next if($dir eq 'out' or exists$item->{element}->{$stanza->element_name});
	    }
	}
	# Either untyped rule or with matching type, check conditions
	# Conditions could be attribute specific or empty (match-any)
	if(exists $item->{type} && $item->{type}) {
	    if($item->{type} eq 'group' or $item->{type} eq 'subscription') {
		# Group and subscription need to expand user's roster to check group membership or status
		# However roster loading process could be timely, so either we need to preload rosters or
		# we'd rather ignore group filters if none of the users is online. No harm unless we support XEP-0012
		if(ritem_match($self->get_ritem($vhost,$jidu,$jido),$item)) {
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
    my $ret = 0;
    my $list;
    # First check inbound stanzas - recipient's list if recipient is local
    $list = ($self->get_active_priv_list($to) || $self->get_default_priv_list($to)) if($vhost->handles_jid($to));
    # If we have a list - user wants to filter something
    if(ref($list) eq 'HASH' and exists $list->{name}) {
	$logger->debug("Matching incoming traffic for ".$to->as_string." with ".$list->{name});
	$ret = $self->match_priv_list($list,$stanza,$vhost);
    }
    # Now user may want to filter outbound as well. We have explicit presence-out case
    # Plus XEP-0016 2.13 clarifies that typeless rules also apply to any outgoing stanzas
    if(!$ret && $vhost->handles_jid($from)) {
	$logger->debug("Outgoing check for ".$from->as_string);
	$list = ($self->get_active_priv_list($from) || $self->get_default_priv_list($from));
	if(ref($list) eq 'HASH' and exists $list->{name}) {
	    # Sender list exists - hence need to apply
	    $logger->debug("Matching outgoing traffic for ".$from->as_string." with ".$list->{name});
	    $ret = $self->match_priv_list($list,$stanza,$vhost,'out');
	}
    }
    return $ret;
}

sub block {
    my $self = shift;
    my $vhost = shift;
    my $stanza = shift;
    $logger->info("BOOM! Stanza is blocked: ".$stanza->as_xml);
    # Be polite and compliant - send responses as perscribed in XEP-0016 2.14
    # Presence - ignore (drop)
    return if($stanza->isa("DJabber::Presence"));
    # Message and IQ{get|set} - error <service-unavailable/>, drop others
    if(($stanza->isa("DJabber::Message") and $stanza->type ne 'groupchat')
	or ($stanza->isa("DJabberd::IQ") and $stanza->type eq 'get' || $stanza->type eq 'set'))
    {
	my $err = $stanza->make_error_response(503,'cancel','service-unavailable');
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
