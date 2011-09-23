#!/usr/bin/perl
# Simple regression script

use strict;
use IO::Socket;
use LWP::Simple;
use Test::More tests => 44;

$main::thrasher = IO::Socket::INET->new('localhost:1972');

use constant {
TYPE_THRESHOLD_v1 => 0,
TYPE_REMOVE       => 1,
TYPE_INJECT       => 2,
TYPE_THRESHOLD_v2 => 3,
TYPE_THRESHOLD_v3 => 4
};

sub thrasher_query_v1 {
my ($address, $host, $uri) = @_;

    my $addr = inet_aton($address);
    my $data = pack("Ca*nna*a*", TYPE_THRESHOLD_v1, $addr, length($host), length($uri), $host, $uri);
    $main::thrasher->syswrite($data);
    $main::thrasher->read(my $buf, 1, 0);
    return unpack("C", $buf);
}

sub thrasher_add {
my ($address) = @_;

    my $addr = inet_aton($address);
    my $data = pack("Ca*", TYPE_INJECT, $addr);
    $main::thrasher->syswrite($data);
}

sub thrasher_remove {
my ($address) = @_;

    my $addr = inet_aton($address);
    my $data = pack("Ca*", TYPE_REMOVE, $addr);
    $main::thrasher->syswrite($data);
}

sub thrasher_query_v2 {
my ($address) = @_;

    my $addr = inet_aton($address);
    my $data = pack("Ca*", TYPE_THRESHOLD_v2, $addr);
    $main::thrasher->syswrite($data);
    $main::thrasher->read(my $buf, 1, 0);
    return unpack("C", $buf);
}

sub thrasher_query_v3 {
my ($identifier, $address, $host, $uri) = @_;

    my $addr = inet_aton($address);
    my $data = pack("CNa*nna*a*", TYPE_THRESHOLD_v3, $identifier, $addr, length($host), length($uri), $host, $uri);
    $main::thrasher->syswrite($data);
    $main::thrasher->read(my $buf, 5, 0);
    my ($id, $permit) = unpack("NC", $buf);
    die "$id != $identifier" if ($id != $identifier && $identifier != 0);
    return $permit;
}

sub thrasherd_http_holddowns {
    my %holddowns;
    my $content = get("http://localhost:1979/holddowns");
    foreach my $line (split(/\n/, $content)) {
        next if ($line =~ /Blocked/);
        chomp $line;
        my ($ip, $trigger, $count) = split(/ +/, $line);
        $holddowns{$ip}->{trigger} = $trigger;
        $holddowns{$ip}->{count} = $count;
    }
    return %holddowns;
}

# First test adding ips to holddown
thrasher_add("10.10.10.10");
thrasher_add("1.2.3.4");

is (thrasher_query_v1("10.10.10.10", "host", "/"), 1);
is (thrasher_query_v1("1.2.3.4", "host", "/"), 1);
is (thrasher_query_v1("4.3.2.1", "host", "/"), 0);
is (thrasher_query_v2("10.10.10.10", "host", "/"), 1);
is (thrasher_query_v2("1.2.3.4", "host", "/"), 1);
is (thrasher_query_v2("4.3.2.1", "host", "/"), 0);
is (thrasher_query_v3(1, "10.10.10.10", "host", "/"), 1);
is (thrasher_query_v3(2, "1.2.3.4", "host", "/"), 1);
is (thrasher_query_v3(3, "4.3.2.1", "host", "/"), 0);

my %holddowns = thrasherd_http_holddowns();

is($holddowns{"1.2.3.4"}->{count}, 3);
is($holddowns{"1.2.3.4"}->{trigger}, "255.255.255.255");
is($holddowns{"10.10.10.10"}->{count}, 3);
is($holddowns{"10.10.10.10"}->{trigger}, "255.255.255.255");
is($holddowns{"4.3.2.1"}, undef);

# Remove added ips and make sure holddown goes away
thrasher_remove("1.2.3.4");
thrasher_remove("10.10.10.10");

sleep(1);

%holddowns = thrasherd_http_holddowns();
is($holddowns{"1.2.3.4"}, undef);
is($holddowns{"10.10.10.10"}, undef);
is($holddowns{"4.3.2.1"}, undef);

is (thrasher_query_v1("10.10.10.10", "host", "/"), 0);
is (thrasher_query_v1("1.2.3.4", "host", "/"), 0);
is (thrasher_query_v1("4.3.2.1", "host", "/"), 0);
is (thrasher_query_v2("10.10.10.10", "host", "/"), 0);
is (thrasher_query_v2("1.2.3.4", "host", "/"), 0);
is (thrasher_query_v2("4.3.2.1", "host", "/"), 0);
is (thrasher_query_v3(1, "10.10.10.10", "host", "/"), 0);
is (thrasher_query_v3(2, "1.2.3.4", "host", "/"), 0);
is (thrasher_query_v3(3, "4.3.2.1", "host", "/"), 0);

sleep(1);
%holddowns = thrasherd_http_holddowns();
is($holddowns{"1.2.3.4"}, undef);
is($holddowns{"10.10.10.10"}, undef);
is($holddowns{"4.3.2.1"}, undef);

#Create hold downs thru query interface
for (my $i = 0; $i < 100; $i++) {
    thrasher_query_v1("10.10.10.10", "host", "/");
    thrasher_query_v1("1.2.3.4", "host", "/");
    thrasher_query_v2("10.10.10.10", "host", "/");
    thrasher_query_v2("1.2.3.4", "host", "/");
    thrasher_query_v3(1, "10.10.10.10", "host", "/");
    thrasher_query_v3(2, "1.2.3.4", "host", "/");
}

sleep(1);
%holddowns = thrasherd_http_holddowns();
is($holddowns{"1.2.3.4"}->{count}, 289);
is($holddowns{"1.2.3.4"}->{trigger}, "127.0.0.1");
is($holddowns{"10.10.10.10"}->{count}, 289);
is($holddowns{"10.10.10.10"}->{trigger}, "127.0.0.1");
is($holddowns{"4.3.2.1"}, undef);

is (thrasher_query_v1("10.10.10.10", "host", "/"), 1);
is (thrasher_query_v1("1.2.3.4", "host", "/"), 1);
is (thrasher_query_v1("4.3.2.1", "host", "/"), 0);
is (thrasher_query_v2("10.10.10.10", "host", "/"), 1);
is (thrasher_query_v2("1.2.3.4", "host", "/"), 1);
is (thrasher_query_v2("4.3.2.1", "host", "/"), 0);
is (thrasher_query_v3(1, "10.10.10.10", "host", "/"), 1);
is (thrasher_query_v3(2, "1.2.3.4", "host", "/"), 1);
is (thrasher_query_v3(3, "4.3.2.1", "host", "/"), 0);


# Cleanup
thrasher_remove("10.10.10.10");
thrasher_remove("1.2.3.4");
thrasher_remove("4.3.2.1");
sleep(1);

# Make sure a 0 v3 identifier closes the connection, needs to be last
is (thrasher_query_v3(0, "10.10.10.10", "host", "/"), undef);
