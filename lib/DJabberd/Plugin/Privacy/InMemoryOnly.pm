# vim: ai sts=4:
package DJabberd::Plugin::Privacy::InMemoryOnly;
use strict;
use base 'DJabberd::Plugin::Privacy';
use warnings;

our $logger = DJabberd::Log->get_logger();

sub get_priv_lists {
    my $self = shift;
    my $jid = shift;
    $logger->debug("Fetching lists for ".$jid->as_string);
    return values(%{$self->{mem}->{$jid->as_bare_string}});
}

sub store_priv_list {
    my $self = shift;
    my $jid = shift;
    my $list = shift;
    if(exists $list->{items} && ref($list->{items}) eq 'ARRAY' && @{$list->{items}}) {
	$logger->debug("Storing list ".$list->{name}." for user ".$jid->as_string);
	return $self->{mem}->{$jid->as_bare_string}->{$list->{name}} = $list;
    } else {
	$logger->debug("Removing list ".$list->{name}." for user ".$jid->as_string);
	return delete $self->{mem}->{$jid->as_bare_string}->{$list->{name}};
    }
}

sub get_priv_list {
    my $self = shift;
    my $jid = shift;
    my $name = shift;
    my $def = shift;
    $logger->debug("Retrieving list ".($name ? $name : '').($def ? ' <default>':'')." for user ".$jid->as_string);
    if($def) {
	foreach my$l($self->get_priv_lists($jid)) {
	    return $l if(exists $l->{default} && $l->{default});
	}
	return {}; # make negative cache entry
    } else {
	return $self->{mem}->{$jid->as_bare_string}->{$name};
    }
}

