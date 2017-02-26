package DJabberd::Plugin::Privacy;

use warnings;
use strict;
use base 'DJabberd::Plugin';

use constant {
	PRIVACY => "jabber:iq:privacy",
	BLOCKING => "urn:xmpp:blocking",
	INVISNS0 => "urn:xmpp:invisible:0",
	INVISNS1 => "urn:xmpp:invisible:1",
};

our $logger = DJabberd::Log->get_logger();

=head1 NAME

DJabberd::Plugin::Privacy - Privacy Lists [XEP-0016], Invisible Command
[XEP-0186, XEP-0126] and Blocking Commands [XEP-0191]

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Implements XEP-0016 Privacy Lists, XEP-0186 Invisible Command and XEP-0191
Blocking Command - a part of XMPP Advanced Server [2010, 2016] specification.

Interoperability between XEP 0016 and 0191 is performed according to XEP-0191
recommendations. That is - when 0016 Privacy List is set as default - it's used
for blocking commands, where blocks are represented as
C<E<lt>item type='jid' value='node@domain/resource' action='deny' /E<gt>>.
Interoperability between XEP-0016 and 0186 is implemented according to XEP-0126

    <VHost mydomain.com>
	<Plugin DJabberd::Plugin::Privacy />
	<Plugin DJabberd::... other delivery plugins: Local, S2S, Offline />
    </VHost>

The base implementation will merely advertise feature and respond to basic
management commands. Not being able to store the list it will never filter.
Use storage-enabled overriden implementation instead.

In cotrast Blocking Command [XEP-0191] uses simplistic list management hence
even storageless bare implementation will use in-memory cache for blocking.

Make sure privacy is the first delivery plugin ever. It registers delivery hook
and according to XEP-0016 it MUST the very first delivery rule [2.2.4].
=cut
=head1 METHODS

Most of the methods defined here are object methods requireing object context.
Only small number of small utilitary calls are static class methods.

=cut

=head2 run_before()

Static class method indicating this hook should run before attempt to deliver
the stanza either locally or via s2s. Namely returns a list containing modules
'DJabberd::Delivery::Local' and 'DJabberd::Delivery::S2S'.

=cut
sub run_before {
    return qw(DJabberd::Delivery::Local DJabberd::Delivery::S2S);
}

=head2 register($self, $vhost)

Registers the vhost with the module. Installs hooks in client-connection
incoming processing chain for the management, connection tear-down chain
for cache purging and delivery chain for actual blocking/filtering.

Additionally adds server features for the implemented XEPs: jabber:iq:privacy
and urn:xmpp:blocking

=cut

my %callmap = (
    'get-{'.PRIVACY.'}query' => \&query_privacy,
    'set-{'.PRIVACY.'}query' => \&set_privacy,
    'get-{'.BLOCKING.'}blocklist' => \&query_blocking,
    'set-{'.BLOCKING.'}block' => \&set_blocking,
    'set-{'.BLOCKING.'}unblock' => \&set_blocking,
    'set-{'.INVISNS0.'}visible' => \&set_visibility,
    'set-{'.INVISNS0.'}invisible' => \&set_visibility,
    'set-{'.INVISNS1.'}visible' => \&set_visibility,
    'set-{'.INVISNS1.'}invisible' => \&set_visibility,
);
#use Data::Dumper;
sub register {
    my ($self,$vhost) = @_;
    my $manage_cb = sub {
	my ($vh, $cb, $iq) = @_;
	if($iq->isa("DJabberd::IQ") && !$iq->to) {
	    if(exists $callmap{$iq->signature}) {
		$logger->debug("Privacy handler ".$iq->signature);
		$callmap{$iq->signature}->($self,$iq);
		return $cb->stop_chain;
	    }
	} elsif(($iq->isa("DJabberd::IQ") || $iq->isa("DJabberd::Presence") || $iq->isa("DJabberd::Message")) and $iq->to) {
	    $logger->debug("I:Checking privacy for ".$iq->element_name);
	    if(my $jid = $self->match_inflight_stanza($iq,'I')) {
		$self->block($iq,$jid);
		$cb->stop_chain;
		return;
	    }
	}
	$cb->decline;
    };
    my $filter_cb = sub {
	my ($vh, $cb, $gt) = @_;
	my $iq = $gt->();
	if($iq->connection->isa('DJabberd::Connection::ClientIn') && ($iq->isa("DJabberd::IQ") || $iq->isa("DJabberd::Presence") || $iq->isa("DJabberd::Message")) and defined $iq->from) {
	    $logger->debug("O:Checking privacy for ".$iq->element_name);
	    if(my $jid = $self->match_inflight_stanza($iq,'O')) {
		$self->block($iq,$jid);
		$cb->stop_chain;
		return;
	    }
	}
	$cb->decline;
    };
    my $deliver_cb = sub {
	my ($vh, $cb, $iq) = @_;
	return $self unless($vh);
	if(($iq->isa("DJabberd::IQ") || $iq->isa("DJabberd::Presence") || $iq->isa("DJabberd::Message")) && defined $iq->from && defined $iq->to) {
	    $logger->debug("D:Checking privacy for ".$iq->element_name);
	    if(my $jid = $self->match_inflight_stanza($iq)) {
		$self->block($iq,$jid);
		$cb->stop_chain;
		return;
	    }
	}
	$cb->decline;
    };
    my $cleanup_cb = sub {
	my ($vh, $cb, $conn) = @_;
	# Remove active lists for closing sessions - if any
	if($conn->isa("DJabberd::Connection::ClientIn")) {
	    my $jid = $conn->bound_jid;
	    if($jid && ref($jid) && $jid->isa("DJabberd::JID")) {
		my $jids = $jid->as_string;
		# Active list - if any
		delete $self->{lists}->{$jids} if(exists $self->{lists}->{$jids});
		# Block List User
		delete $self->{blkiq}->{$jids} if(exists $self->{blkiq}->{$jids});
	    #} else {
		#$logger->debug("No bound jid".Dumper($conn));
	    }
	#} else {
	#    $logger->debug("Not a connection".Dumper($conn));
	}
	$cb->decline;
    };
    $self->{vhost} = $vhost;
    Scalar::Util::weaken($self->{vhost});
    # Hook used mostly for default list and s2s delivery
    $vhost->register_hook("deliver",$deliver_cb);
    # Hook used mostly for active list inbound filtering
    $vhost->register_hook("pre_stanza_write",$filter_cb);
    # Hook used for management and outbound filtering
    $vhost->register_hook("switch_incoming_client",$manage_cb);
    # Hooks used to clean up any associated cached elements
    $vhost->register_hook("ConnectionClosing",$cleanup_cb);
    $vhost->add_feature(PRIVACY);
    $vhost->add_feature(BLOCKING);
    $vhost->add_feature(INVISNS0);
    $vhost->add_feature(INVISNS1);
}

sub vhost {
    return $_[0]->{vhost};
}

=head2 fail($self, $stanza, $subject, $error, $text)

The call used internally to generate error response for management commands.

=over

=item
$stanza - is origignal stanza which triggerred an error.

=item
$subject - is child element of type urn:ietf:params:xml:ns:xmpp-stanzas,
default is 'bad-request'

=item
$error is error type, default is 'cancel'

=item
$text is optional text payload describing the error condition.

=back

=cut

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

=head2 query_privacy($self, $iq)

This method is called for privacy lists query IQ. IQ may request a list of lists
or details of some specific named list. Will fail if query contains more than
one element (eg. multiple lists). Also when requested list does not exist.

Empty request will list all lists.

=cut

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
    return (exists $item->{type} && $item->{type} eq 'jid' && $item->{action} eq 'deny' && !($item->{element} && ref($item->{element}) eq 'HASH' && %{$item->{element}}));
}

sub is_invis_item {
    my ($i) = @_;
    return (exists $i->{element} && ref($i->{element}) eq 'HASH' && scalar(keys(%{$i->{element}})) == 1 && $i->{element}->{'presence-out'} && $i->{action} eq 'deny'
	    && !(exists $i->{type} && $i->{type}) && !(exists $i->{value} && $i->{value}));
}

sub is_invis_probe {
    my ($i) = @_;
    return (exists $i->{element} && ref($i->{element}) eq 'HASH' && scalar(keys(%{$i->{element}})) == 1 && $i->{element}->{'presence-out'} && $i->{action} eq 'deny'
	    && exists $i->{type} && $i->{type} && $i->{type} eq 'probe' && !(exists $i->{value} && $i->{value}));
}

=head2 query_blocking($self,$iq)

This method is called for Blocking Command query IQ. IQ may only request a list
of currently installed blocking commands.

Should be empty although this method ignores any child elements.

=cut

sub query_blocking {
    my $self = shift;
    my $iq = shift;
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
    $self->{blkiq}->{$iq->from} = 1; # remember this one - block list user
}

=head2 set_privacy($self,$iq)

used as a handler for privacy list modification IQ stanzas.

May be used to:

=over

=item
create new or overwrite existing list.

=over

Full list specification should be provided hence these operations are equal.
If the list in question is set as either active or default for active session
- returns E<lt>conflict/E<gt> error.

=back

=item
remove the list.

=over

Submitting empty list specification removes the list. Same conditions as for
list modification apply.

=back

=item
set active list.

=over

List should exist. Active list is having highest priority but is used only for
the time of the session. If list attribute is empty - deactivates a list for
current session.

=back

=item
set default list.

=over

List should exist. Default list is used for all sessions with no active list
set. Moreover, it's used even for offline delivery. If list attribute is empty
- detaches a list from default filter.

=back

=back

=cut

sub set_privacy {
    my $self = shift;
    my $iq = shift;
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
		$self->chk_presence($list,$jid);
		$self->set_active_priv_list($jid,$list);
	    } elsif($el->element_name eq 'default') {
		my $def = $self->get_default_priv_list($jid);
		# If default list is defined and differs from this one - check for conflicts
		if($def && ref($def) eq 'HASH' && $def->{name} && (!$name || $def->{name} ne $name)) {
		    # Need to check for conflicts - don't change default in use by other connected users (silly)
		    foreach my $c($self->vhost->find_conns_of_bare($jid)) {
			# basically we're checking if other resources having own(active) list or rely on default
			my $bj=$c->bound_jid->as_string;
			next if($bj eq $jid->as_string); # skip self
			next if(exists $self->{$bj} && ref($self->{$bj}) eq 'HASH'); # this one has active, skip
			# no active list, client is using default, hence conflict
			$self->fail($iq,'conflict');
			return;
		    }
		}
		if($list) {
		    $self->chk_presence($list,$jid);
		    $self->set_default_priv_list($jid,$list);
		} else {
		    $logger->debug("Detaching default list for ".$jid->as_bare_string);
		    $self->set_default_priv_list($jid,{});
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
				if(exists $att{'{}order'} && $att{'{}order'} >= 0 and 
				    exists $att{'{}action'} && $att{'{}action'} =~ /allow|deny/)
				{
				    if(exists $att{'{}type'}) {
					$item->{type} = $att{'{}type'};
					$item->{value} = $att{'{}value'};
					# Group should be pre-validated. However one may delete it later, so who cares.
				    }
				    $item->{order} = $att{'{}order'};
				    $item->{action} = $att{'{}action'};
				    # Optional stanza type elements
				    $item->{element} = {map{$_->element_name=>1}$ce->children};
				    if(!grep{!/(iq|message|presence-in|presence-out)/}keys(%{$item->{element}})) {
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
		    $def=($def && ref($def) && $def->{name} && $def->{name} eq $name);
		    # Then check other online resources
		    foreach my $c($self->vhost->find_conns_of_bare($jid)) {
			my $bj=$c->bound_jid->as_string;
			# If uses our list as active OR doesn't use active but our is default - it's a conflict
			if((exists $self->{$bj} && ref($self->{$bj}) eq 'HASH' && $self->{$bj}->{name} eq $name)
			    or ((!exists $self->{$bj} || !$self->{$bj}) && $def)) {
			    $self->fail($iq,'conflict');
			    return;
			}
		    }
		}
		# Try to store list
		if(my$sr=$self->set_priv_list($jid,$list)) {
		    # first ack result back to editor
		    $iq->send_result();
		    if($sr>0) {
			# Then broadcast modified list name to all connected resources (XEP-0016 2.6)
			$self->bcast_list_update($jid,$name);
		    }
		    # Now update active or default and emit presence if it is
		    if($self->is_default_list($jid,$list)) {
			# Collect all active users of the default list
			my @jids = ();
			foreach my$c($self->vhost->find_conns_of_bare($jid)) {
			    my $l = $self->get_active_priv_list($c->bound_jid);
			    push(@jids,$c->bound_jid->as_string) if(!$l || $l->{name} eq $name);
			}
			# And distribute presence according to filters
			$self->chk_presence($jid,$list,0,{},{},@jids);
		    } elsif($self->is_active_list($jid,$list)) {
			$self->chk_presence($list,$jid);
		    }
		} else {
		    # happens
		    $self->fail($iq,'service-unavailable');
		}
		return;
	    }
	}
    }
    $self->fail($iq,0,'modify');
}
sub bcast_list_update {
    my ($self,$jid,$name)=@_;
    my $lq = "<query xmlns='".PRIVACY."'><list name='$name' /></query>";
    foreach my $c ($self->vhost->find_conns_of_bare($jid)) {
	# Need to follow roster push way as initial presence might not yet be sent
	my $id = $c->new_iq_id;
	my $to = $c->bound_jid->as_string;
	my $xml = "<iq type='set' to='$to' id='$id'>$lq</iq>";
	$c->log_outgoing_data($xml);
	$c->write(\$xml);
    }
}
# XEP-0016 2.10 says we need to send presence unavailable to the client which just blocked incoming presence
# also when we blocked presence to someone else - we should send to him unavailable presence
sub chk_presence {
    my $self = shift;
    my $list = shift;
    my $jid = shift;
    my $roster = shift;
    my $pi = shift || {};
    my $po = shift || {};
    my @fj = @_;
    my @pi = grep {(!%{$_->{element}} || $_->{element}->{'presence-in'})  && $_->{action} eq 'deny'} @{$list->{items}};
    my @po = grep {(!%{$_->{element}} || $_->{element}->{'presence-out'}) && $_->{action} eq 'deny'} @{$list->{items}};
    foreach my$i(@pi) {
	if($i->{type} && $i->{type} eq 'jid') {
	    # explicit meh, just send it
	    $pi->{$i->{value}} = 1;
	} else {
	    # Walk the roster and unavail all/matching
	    if(!$roster) {
		$self->vhost->run_hook_chain(phase => "RosterGet", args => [ $jid ],
		    methods => {
			set_roster => sub {
			    $self->chk_presence($list,$jid,$_[0],$pi,$po,@fj);
			}
		    }
		);
		return;
	    }
	    foreach my$ri($roster->to_items) {
		if(!$pi->{$ri->jid->as_string} && (!$i->{type} or ritem_match($ri,$i))) {
		    $pi->{$ri->jid->as_string} = 1;
		}
	    }
	}
    }
    foreach my$i(@po) {
	if($i->{type} && $i->{type} eq 'jid') {
	    $po->{$i->{value}} = 1;
	} else {
	    if(!$roster) {
		$self->vhost->run_hook_chain(phase => "RosterGet", args => [ $jid ],
		    methods => {
			set_roster => sub {
			    $self->chk_presence($list,$jid,$_[0],$pi,$po,@fj);
			}
		    }
		);
		return;
	    }
	    foreach my$ri($roster->from_items) {
		if(!$po->{$ri->jid->as_string} && (!$i->{type} or ritem_match($ri,$i))) {
		    $po->{$ri->jid->as_string} = 1;
		}
	    }
	}
    }
    my $p = DJabberd::Presence->unavailable_stanza;
    foreach my$j(keys(%{$pi})) {
	if(@fj) {
	    foreach my$fj(@fj) {
		$p->set_from($j);
		$p->set_to($fj);
		$p->deliver($self->vhost);
	    }
	} else {
	    $p->set_from($j);
	    $p->set_to($jid->as_string);
	    $p->deliver($self->vhost);
	}
    }
    foreach my$j(keys(%{$po})) {
	if(@fj) {
	    foreach my$fj(@fj) {
		$p->set_from($fj);
		$p->set_to($j);
		$p->deliver($self->vhost);
	    }
	} else {
	    $p->set_from($jid->as_string);
	    $p->set_to($j);
	    $p->deliver($self->vhost);
	}
    }
    return $roster;
}

=head2 set_visibility($self,$iq)

This method handles XEP-0186 Invisible Commands.

It uses underlying Privacy List engine in accordance with XEP-0126 to implement
presence filtering for invisibility. XEP mandates invisibility to be applicable
only to the session, hence invisible command operates only on active list.

When list does not exist it creates one, named 'invisible' (as Telepathy does).

For C<visible> command it tries to remove C<presence-out> list items and if
resulting list is empty it just deactivates it. Otherwise it modifies and stores
the list, keeping it active with remaining items.

=cut

sub set_visibility {
    my $self = shift;
    my $iq = shift;
    my $op = $iq->first_element->element_name;
    my $jid = $iq->connection->bound_jid;
    my $list = $self->get_active_priv_list($jid);
    my %invis;
    if($list && ref($list) eq 'HASH' && exists $list->{name}) {
	%invis = map{$_->{order} => $_}grep {is_invis_item($_)} @{$list->{items}};
    } else {
	$list = { name => 'invis-'.$iq->id, items => [], temp=>1};
    }
    if($op eq 'invisible' && !%invis) {
	# Ignore if we have some active list which blocks presence
	$logger->debug("Inserting pres-out block to ".$list->{name});
	if(@{$list->{items}} && $list->{items}->[0]->{order} <= 1) {
	    # Renumber order value to allow new 1
	    foreach my$i(1..(scalar(@{$list->{items}}))) {
		$list->{items}->[$i-1]->{order} = $i+1;
	    }
	}
	my $item = {action=>'deny',element=>{'presence-out' => 1}, order=>1};
	$item->{type} = 'probe' unless($iq->first_element->attr('{}probe'));
	unshift(@{$list->{items}}, $item);
	$self->set_active_priv_list($jid,$list);
	# Now need to broadcast unavailable presence - if we're past initial presence
	if($iq->connection->is_available) {
	    my $pres = DJabberd::Presence->unavailable_stanza;
	    $pres->broadcast_from($iq->connection);
	}
	$self->bcast_list_update($jid,$list->{name})
	    if(!$list->{temp} && $self->set_priv_list($jid,$list));
    } elsif($op eq 'visible' && %invis) {
	# Ignore unless presence is blocked by active list
	my @items = grep{!exists$invis{$_->{order}}}@{$list->{items}};
	if(@items && !$list->{temp}) {
	    # Something is left there, need to modify and keep
	    $logger->debug("Removing presence filters from list ".$list->{name});
	    $list->{items} = [@items];
	    $self->set_active_priv_list($jid,$list);
	    $self->bcast_list_update($jid,$list->{name}) if($self->set_priv_list($jid,$list));
	} else {
	    # Pure visibility list, just discard active list
	    $logger->debug("Deactivating visibility list ".$list->{name});
	    $self->set_active_priv_list($jid);
	}
    # Let's catch a case when only probe state is changing
    } elsif($op eq 'invisible' && %invis && $iq->first_element->attr('{}probe') && !grep{is_invis_probe($_)}values(%invis)) {
	$logger->debug("Enabling probe filtering on list ".$list->{name});
	foreach(@{$list->{items}}) {
	    $_->{type}='probe' if(is_invis_item($_));
	}
	$self->set_active_priv_list($jid,$list);
    } elsif($op eq 'invisible' && %invis && !$iq->first_element->attr('{}probe') && grep{is_invis_probe($_)}values(%invis)) {
	$logger->debug("Disabling probe filtering on list ".$list->{name});
	foreach(@{$list->{items}}) {
	    delete $_->{type} if(is_invis_probe($_));
	}
	$self->set_active_priv_list($jid,$list);
    } else {
	$logger->debug("Nothing to be done, everything is as requested: ".$list->{name}."/".join(', ',keys(%invis)));
    }
    my $to = $iq->from || $iq->connection->bound_jid->as_string;
    my $xml = "<iq type='result' id='".$iq->id."' to='$to'/>";
    $iq->connection->log_outgoing_data($xml);
    $iq->connection->write(\$xml);
}

=head2 set_blocking($self,$iq)

The method is used as a handler for Blocking list management.

In contrast to privacy lists - blocking command allows partial modification of
the list - to add or remove blocking elements.
Since the plugin is used for both privacy and blocking list - blocking sits on
top of privacy. Privacy list allows more granular control, with blocking being
a subset of privacy. Hence this handler will attempt to modify default privacy
list, or will autocreate one for addition command.

The handler attempts to not interfere with list elements which do not conform
to blocking commands. This is checked by L<is_blocking_item> call.

The method will generate error response for attempts to remove elements from an
empty list, or to add empty elements, or to block wrongly formatted JIDs.

=cut

sub set_blocking {
    my $self = shift;
    my $iq = shift;
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
	$list = { name => 'block', items => []};
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
    # Even if we fail to persistently store it - list will still be cached and hence active, so let's ack it
    $iq->send_result;
    # send presence to all affected blocks (if they are subscribed)
    # TODO: get roster and check presence subscription
    foreach my $pst(@presence) {
	$pst->deliver($self->vhost);
    }
    $self->set_default_priv_list($jid,$list);
    # Broadcast modifications to all connected resources
    # Those which requested block list - receive original change [XEP-0191 3.3.8], others - priv.list name [XEP-0016 2.6]
    $iq->set_from;
    my $piq = DJabberd::IQ->new('','iq',{type=>'set'},[],'<query xmlns="'.PRIVACY.'"><list name="'.$list->{name}.'" /></query>') if($active);
    foreach my $c ($self->vhost->find_conns_of_bare($jid)) {
	next if($c->bound_jid->as_string eq $jid->as_string); # skip self, 0191 does not need that
	if($self->{blkiq}->{$c->bound_jid->as_string}) {
	    $iq->set_to($c->bound_jid);
	    $iq->deliver($c);
	} elsif($piq) {
	    # I wonder how these guys would react to someone updating list in use
	    $piq->set_to($c->bound_jid);
	    $piq->deliver($c);
	}
    }
}

=head2 set_active_priv_list($self,$jid,$list)

The method is activating given list for the given JID.

The JID is DJabberd::JID object and should be fully qualified
(node@domain/resource). Method installs the list in memory cache.
The cache will be purged by tear-down hooks.

The list is represented by HASH reference as specified above.

=cut

sub set_active_priv_list {
    my $self = shift;
    my $jid = shift;
    my $list = shift;
    $self->{lists}->{$jid->as_string} = $list;
}

=head2 get_active_priv_list($self,$jid)

returns active privacy list for the given JID.

The JID is DJabberd::JID object and should be fully qualified
(node@domain/resource). Method checks for existance in memory cache. Returns
undef if active list is not set for the session (represented by full jid).

=cut

sub get_active_priv_list {
    my $self = shift;
    my $jid = shift;
    # Active list is session-bound hence runtime-only parameter and for fully qualified JID
    return $self->{lists}->{$jid->as_string} if(exists $self->{lists}->{$jid->as_string} && ref($self->{lists}->{$jid->as_string}));
    return undef;
}

sub is_cached_priv_list {
    my $self = shift;
    my $jids = shift;
    my $name = shift;
    return (exists $self->{lists}->{$jids} && ref($self->{lists}->{$jids}) eq 'HASH' && exists $self->{lists}->{$jids}->{name} && $self->{lists}->{$jids}->{name} eq $name);
}
sub is_default_list {
    return $_[0]->is_cached_priv_list($_[1]->as_bare_string,$_[2]);
}

sub is_active_list {
    return $_[0]->is_cached_priv_list($_[1]->as_string,$_[2]);
}

=head2 set_default_priv_list($self,$jid,$list)

installs given list as default for given JID.

The $jid should be DJabberd::JID and $list a hash ref - either empty or normal.
The list is installed in memory cache, then flagged as default and stored to
persistent storage.

=cut

sub set_default_priv_list {
    my $self = shift;
    my $jid = shift;
    my $list = shift;
    return undef unless($list && ref($list));
    $list->{default} = 1;
    $self->{lists}->{$jid->as_bare_string} = $list;
    return $self->store_priv_list($jid,$list) if(exists $list->{name} && $list->{name});
    return $list;
}

=head2 get_default_priv_list($self,$jid)

returns default privacy list for the given JID.

The $jid is DJabberd::JID object. If default list is pre-cached - returns it
straight from there. Otherwise queries persistent storage to retrieve any
list which is marked as default for given JID.

Storage call may return empty hash ref to stop querying itself.

=cut

sub get_default_priv_list {
    my $self = shift;
    my $jid = shift;
    my $bjid = $jid->as_bare_string;
    return $self->{lists}->{$bjid} if($self->{lists}->{$bjid} && ref($self->{lists}->{$bjid}) eq 'HASH');
    my $list = $self->get_priv_list($jid,undef,1);
    $self->{lists}->{$jid->as_bare_string} = $list if($list && ref($list) eq 'HASH');
    return $list;
}

=head2 set_priv_list($self,$jid,$list)

Stores the list into persistent storage for given JID.

The JID must be DJabberd::JID object and the list a hashref. If the list with
this name is cached as active or default - will also update the cache.

If the hashref's {items} element is empty or missing - indicates removal of the
list.

=cut

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

=head2 get_priv_lists($self,$jid,$name)

directly calls persistent storage to fetch all jid's lists

MUST OVERRIDE. Base class will just print an error message.
$jid is DJabberd::JID object for which the list of privacy lists is fetched.

Returns array of the hashrefs.

=cut

sub get_priv_lists {
    my $self = shift;
    my $jid = shift;
    $logger->error("Not Implemented: Must Override");
    return ();
}

=head2 store_priv_list($self,$jid,$list)

directly calls persistent storage to store the list

MUST OVERRIDE. Base class will just print an error message.
$jid is DJabberd::JID object and $list is hashref. The call is used to push
the list to the storage backend, used in other methods which are checking for
cache. This one is only storing. Or removing - if hashref has no items.

Returns stored list hashref if succeeded, undef otherwise.

=cut

sub store_priv_list {
    my $self = shift;
    my $jid = shift;
    my $list = shift;
    $logger->error("Not Implemented: Must Override");
    return undef;
}

=head2 get_priv_list($self,$jid,$name,$def)

directly calls persistent storage to fetch the named list for given jid.

MUST OVERRIDE. Base class will just print an error message.
$jid is DJabberd::JID object for which the list with name $name is fetched.

Optional boolean $def may be used to filter by default flag instead of name.
$name is ignored in this case and call effectively returns default list only,
if it exists.

The call should return empty hash ref to indicate negative search result which
could be cached. returned undef would indicate storage failure.

=cut

sub get_priv_list {
    my $self = shift;
    my $jid = shift;
    my $name = shift;
    my $def = shift;
    $logger->error("Not Implemented: Must Override");
    return undef;
}

=head2 get_ritem($self,$user,$contact,$out)

returns RosterItem for the contact from user's Roster

The call is used to fetch DJabberd::RosterItem from $user's Roster for the given
$contact. $user and $contact are both DJabberd::JID objects.

Since it uses RosterLoadItem hook with callback it needs external variable to
prevent closure to localize the variable. Hence $out param is passed as var ref
to set the resulting RosterItem, however it still returns that item in the end.

One may override it with cache-able call but then need to invalidate on roster
updates.

=cut

sub get_ritem {
    my $self = shift;
    my $jidu = shift;
    my $jido = shift;
    my $d = shift;
    if($jidu && $jido) {
	$self->vhost->run_hook_chain(phase => "RosterLoadItem", args => [$jidu,$jido], methods => {
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

=head2 match_priv_list($self,$list,$stanza,$dir)

applies the list to the stanza to find matches for the give direction

This is the main matching _engine_ used for privacy list filtering.
The $list should be a hashref which was identified as an active or default
list applicable to the delivered $stanza - a DJabberd::Stanza or derived
object. The contact's RosterItem will be fetched from user's roster if list
contains roster-dependent filters (subscription or group). $dir is a string
saying whether we're checking inbound ('in' - default) or outbound ('out')
direction.

Returns boolean which indicates whether the list directs to deny (true) or
allow (false) the stanza.

Note: default (no-match) action for privacy list is allow, so false means
ether explicit allow-match or no-match.

=cut

sub match_priv_list {
    my $self = shift;
    my $list = shift;
    my $stanza = shift;
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
		# XEP-0186 3.1 however suggests to optionally block outgoing 'probe' as well
		return $item->{action} eq 'deny'
		    if(is_invis_probe($item) && $stanza->type && $stanza->type eq 'probe');
		next if($stanza->type && $stanza->type ne 'unavailable');
		# XEP-0186 also allows passing directed presence, so... presence is directed if
		# it has to(is directed), it's from client connection where from_jid=bound_jid,
		# it's presence state. And the filter is catch-all, not target-specific
		next if($dir eq 'out' && $jido && $stanza->connection && !$stanza->connection->is_server
			&& $stanza->connection->bound_jid && $stanza->connection->bound_jid->eq($jidu)
			&& !(exists $item->{type} && $item->{type})
		    );
		# So <presence/> won't be filtered bcz on switch_incoming_client we require <to>
		# directed will pass the filter but will hit the above condition and be excluded
		# in the delivery phase broadcasted reflected pres have no connection - no match
		# but directed will keep its connection and hence will match the above exclusion
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
		$ritem = $self->get_ritem($jidu,$jido,\$ritem) unless(defined $ritem);
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

=head2 match_inflight_stanza($self,$stanza,$dir)

The method represents a hook injected by L<register> method into delivery chains

called for each and every stanza which requires delivery. Additionally checks
client connections for incoming and outgoing stanzas - to apply active list.
First it tries to identify privacy list for recipient and apply the list for
inbound direction. If no deny found, it then attempts to identify list for the
sender and apply found list in outbound direction.

Optional $fdir parameter is used to enforce direction and to/from jid - this is
used when filtering c2s connection.

If neither of matches returns deny condition - the chain continues. Otherwise
the delivery is stopped and L<block> method is called to drop the stanza or
reject it wth an error.

=cut

sub match_inflight_stanza {
    my $self = shift;
    my $stanza = shift;
    my $fdir = shift || "";
    my $from = ($fdir eq 'I') ? $stanza->connection->bound_jid : $stanza->from_jid;
    my $to =   ($fdir eq 'O') ? $stanza->connection->bound_jid : $stanza->to_jid;
    my $ret;
    my $list;
    # Specification explicitly denies blocking cross-resource stanzas, even if explicit list item is defined.
    return 0 if($from->as_bare_string eq $to->as_bare_string);
    # First check inbound stanzas - recipient's list if recipient is local
    $list = ($self->get_active_priv_list($to) || $self->get_default_priv_list($to)) if($fdir ne 'I' && $self->vhost->handles_jid($to));
    # If we have a list - user wants to filter something
    if(ref($list) eq 'HASH' and exists $list->{name}) {
	$logger->debug("Matching incoming traffic for ".$to->as_string." with ".$list->{name});
	$ret = $to if($self->match_priv_list($list,$stanza));
    }
    # Now user may want to filter outbound as well. We have explicit presence-out case
    # Plus XEP-0016 2.13 clarifies that typeless rules also apply to any outgoing stanzas
    if(!$ret && $fdir ne 'O' && $self->vhost->handles_jid($from)) {
	#$logger->debug("Outgoing check for ".$from->as_string);
	$list = ($self->get_active_priv_list($from) || $self->get_default_priv_list($from));
	if(ref($list) eq 'HASH' and exists $list->{name}) {
	    # Sender list exists - hence need to apply
	    $logger->debug("Matching outgoing traffic for ".$from->as_string." with ".$list->{name});
	    $ret = $from if($self->match_priv_list($list,$stanza,'out'));
	}
    }
    return $ret;
}

=head2 block($self,$stanza,$owner)

Handles block action when privacy list or block command directs deny action.

The method should provide proper rejection mechanism as per XEP-0016 and
XEP-0191 to apply deny action for matched list. $stanza is blocked $stanza
object of DJabberd::Stanza or derived class which matched the privacy list
with deny action. $owner is DJabberd::JID object whose privacy list generated
deny action.

=cut

sub block {
    my $self = shift;
    my $stanza = shift;
    my $owner = shift;
    $logger->info("BOOM! Stanza is blocked: ".$stanza->as_xml);
    # Be polite and compliant - send responses as perscribed in XEP-0016 2.14
    # Presence - ignore (drop)
    return if($stanza->isa("DJabberd::Presence"));
    # Message and IQ{get|set} - error <service-unavailable/>, drop others
    if(($stanza->isa("DJabberd::Message") and $stanza->type ne 'groupchat')
	or ($stanza->isa("DJabberd::IQ") and $stanza->type eq 'get' || $stanza->type eq 'set'))
    {
	my $err;
	if($owner && $stanza->from_jid->as_bare_string eq $owner->as_bare_string && $stanza->isa("DJabberd::Message")) {
	    # XEP-0191 mandates to inform blocker with other error type as well as app-specific blocking condition
	    $err = $stanza->make_error_response(503,'cancel','not-acceptable');
	    my @err = grep{$_->element_name eq 'error'}$err->children;
	    $err[0]->push_child(DJabberd::XMLElement->new(BLOCKING.':errors','blocked',{},[]));
	} else {
	    $err = $stanza->make_error_response(503,'cancel','service-unavailable');
	}
	$err->deliver($self->vhost);
    }
}

=head1 INTERNALS

Internally list structure is represented as HASH reference with following layout


  {
    name => 'listname',
    items => [
      { # item 1
	action => '<allow|deny>',
	type => '<jid|group|subscription>', value => '<value>', # optional
	element => {		# optional, with any combination of below
	  iq => 1,
	  message => 1,
	  'presence-in' => 1,
	  'presence-out' => 1
	}
      },
      # ... item 2, ..., n
    ],
    default => 1  # optional flag for default list
  }

Blocking Command being subset of privacy list will then be shortened to

  {
    name => 'listname',
    items => [
      {
	action => 'deny',
	type => 'jid',
	value => '<jid>'
      }
    ]
  }

with all fields in list item being mandatory to comply with blocking command.
List may contain any mix of both, but only later will be visible in blocking
query, while full list will be visible to privacy query.

=cut

=head1 AUTHOR

Ruslan N. Marchenko, C<< <me at ruff.mobi> >>

=head1 COPYRIGHT & LICENSE

Copyright 2016 Ruslan N. Marchenko, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of DJabberd::Plugin::Privacy
# vim:sts=4:
