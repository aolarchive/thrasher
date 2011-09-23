#!/usr/bin/perl
# Simple regression script

use strict;
use IO::Socket;
use LWP::Simple;
use Test::More tests => 62;
#use Data::Dumper;

$main::thrasher = IO::Socket::INET->new('localhost:1972');
$main::sockport = $main::thrasher->sockport();

use constant {
TYPE_THRESHOLD_v1 => 0,
TYPE_REMOVE       => 1,
TYPE_INJECT       => 2,
TYPE_THRESHOLD_v2 => 3,
TYPE_THRESHOLD_v3 => 4
};

sub max ($$) { $_[$_[0] < $_[1]] }
sub trim {
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    return $string;
}

sub thrasher_query_v1($$$) {
my ($address, $host, $uri) = @_;

    my $addr = inet_aton($address);
    my $data = pack("Ca*nna*a*", TYPE_THRESHOLD_v1, $addr, length($uri), length($host), $uri, $host);
    $main::thrasher->syswrite($data);
    $main::thrasher->read(my $buf, 1, 0);
    return unpack("C", $buf);
}

sub thrasher_add($) {
my ($address) = @_;

    my $addr = inet_aton($address);
    my $data = pack("Ca*", TYPE_INJECT, $addr);
    $main::thrasher->syswrite($data);
}

sub thrasher_remove($) {
my ($address) = @_;

    my $addr = inet_aton($address);
    my $data = pack("Ca*", TYPE_REMOVE, $addr);
    $main::thrasher->syswrite($data);
}

sub thrasher_query_v2($) {
my ($address) = @_;

    my $addr = inet_aton($address);
    my $data = pack("Ca*", TYPE_THRESHOLD_v2, $addr);
    $main::thrasher->syswrite($data);
    $main::thrasher->read(my $buf, 1, 0);
    return unpack("C", $buf);
}

sub thrasher_query_v3($$$$) {
my ($identifier, $address, $host, $uri) = @_;

    my $addr = inet_aton($address);
    my $data = pack("CNa*nna*a*", TYPE_THRESHOLD_v3, $identifier, $addr, length($uri), length($host), $uri, $host);
    $main::thrasher->syswrite($data);
    $main::thrasher->read(my $buf, 5, 0);
    my ($id, $permit) = unpack("NC", $buf);
    die "$id != $identifier" if ($id != $identifier);
    return $permit;
}

sub thrasherd_http_holddowns {
    my %holddowns;
    my $content = get("http://localhost:1979/holddowns");
    #print $content;
    foreach my $line (split(/\n/, $content)) {
        next if ($line =~ /Blocked/);
        chomp $line;
        my ($ip, $trigger, $count, $timeout, $recentto) = split(/ +/, $line);
        $holddowns{$ip} = {trigger => $trigger, count => $count, timeout => $timeout, recentTimeout => $recentto};
    }
    return %holddowns;
}

sub thrasherd_http_config {
    my %config;
    my $content = get("http://localhost:1979/config");
    #print $content;
    foreach my $line (split(/\n/, $content)) {
        next if ($line !~ /:/);
        chomp $line;
        my ($key, $value) = split(/:/, $line);
        $config{trim($key)} = trim($value);
    }
    return %config;
}

sub thrasherd_http_connections {
    my %connections;
    my $content = get("http://localhost:1979/connections");
    #print $content;
    foreach my $line (split(/\n/, $content)) {
        next if ($line !~ /^\d/);
        chomp $line;
        my ($ip, $port, $requests, $conn, $last) = split(/  +/, $line);
        $connections{"$ip:$port"} = {requests => $requests, connDate => $conn, lastDate => $last};
    }
    return %connections;
}

sub thrasherd_http_addrs {
    my %addrs;
    my $content = get("http://localhost:1979/addrs");
    #print $content;
    foreach my $line (split(/\n/, $content)) {
        next if ($line !~ /^\d/);
        chomp $line;
        my ($ip, $connections, $timeout) = split(/ +/, $line);
        $addrs{$ip} = {connections => $connections, timeout => $timeout};
    }
    return %addrs;
}

sub thrasherd_http_uris {
    my %uris;
    my $content = get("http://localhost:1979/uris");
    #print $content;
    foreach my $line (split(/\n/, $content)) {
        next if ($line !~ /^\d/);
        chomp $line;
        my ($ip, $connections, $timeout, $uri) = split(/ +/, $line);
        $uris{"$ip:$uri"} = {connections => $connections, timeout => $timeout};
    }
    return %uris;
}

sub thrasherd_http_hosts {
    my %hosts;
    my $content = get("http://localhost:1979/hosts");
    #print $content;
    foreach my $line (split(/\n/, $content)) {
        next if ($line !~ /^\d/);
        chomp $line;
        my ($ip, $connections, $timeout, $host) = split(/ +/, $line);
        $hosts{"$ip:$host"} = {connections => $connections, timeout => $timeout};
    }
    return %hosts;
}

# Check if things have cleared out, don't want failed tests
my %addrs = thrasherd_http_addrs();
my %uris = thrasherd_http_uris();
if (exists $addrs{"4.3.2.1"} || exists $uris{"4.3.2.1:/"}) {
    die "Some tests are going to fail, restart thrashd OR wait " . 
        max($addrs{"4.3.2.1"}->{timeout}, $uris{"4.3.2.1:/"}->{timeout}) . 
        " seconds and try again";
}

# Get config information for tests
%main::config = thrasherd_http_config();
my $softtimeout = $main::config{"Soft block timeout"};
$main::config{"ADDR block ratio"} =~ /(\d+) hits over (\d+) seconds/;
my $addrtimeout = $2;

# Check our connection stats
my %connections = thrasherd_http_connections();
is ($connections{"127.0.0.1:$main::sockport"}->{requests}, 0);
is ($connections{"127.0.0.1:$main::sockport"}->{lastDate}, "N/A");
ok (exists $connections{"127.0.0.1:$main::sockport"}->{connDate});
$main::connDate = $connections{"127.0.0.1:$main::sockport"}->{connDate};

# First test adding ips to holddown
thrasher_add("10.10.10.10");
thrasher_add("1.2.3.4");

%connections = thrasherd_http_connections();
is ($connections{"127.0.0.1:$main::sockport"}->{requests}, 2);
is ($connections{"127.0.0.1:$main::sockport"}->{connDate}, $main::connDate);
ok (exists $connections{"127.0.0.1:$main::sockport"}->{lastDate});

is (thrasher_query_v1("10.10.10.10", "host1", "/uri1"), 1);
is (thrasher_query_v1("1.2.3.4", "host1", "/uri1"), 1);
is (thrasher_query_v1("4.3.2.1", "host1", "/uri1"), 0);
is (thrasher_query_v2("10.10.10.10"), 1);
is (thrasher_query_v2("1.2.3.4"), 1);
is (thrasher_query_v2("4.3.2.1"), 0);
is (thrasher_query_v3(1, "10.10.10.10", "host3", "/uri3"), 1);
is (thrasher_query_v3(2, "1.2.3.4", "host3", "/uri3"), 1);
is (thrasher_query_v3(3, "4.3.2.1", "host3", "/uri3"), 0);
is (thrasher_query_v3(0, "10.10.10.10", "host3", "/uri3"), 1); #Bug: Test id=0 with v3

my %holddowns = thrasherd_http_holddowns();
is($holddowns{"1.2.3.4"}->{count}, 3);
is($holddowns{"1.2.3.4"}->{trigger}, "255.255.255.255");
cmp_ok($holddowns{"1.2.3.4"}->{timeout}, '>=', $softtimeout-1);
is($holddowns{"10.10.10.10"}->{count}, 4);
is($holddowns{"10.10.10.10"}->{trigger}, "255.255.255.255");
cmp_ok($holddowns{"10.10.10.10"}->{timeout}, '>=', $softtimeout-1);
is($holddowns{"4.3.2.1"}, undef);

sleep(1);

# Check *_table items
%addrs = thrasherd_http_addrs();
my %hosts = thrasherd_http_hosts();
%uris = thrasherd_http_uris();

is ($addrs{"4.3.2.1"}->{connections}, 1);
is ($hosts{"4.3.2.1:host1"}->{connections}, 1);
is ($hosts{"4.3.2.1:host3"}->{connections}, 1);
is ($uris{"4.3.2.1:/uri1"}->{connections}, 1);
is ($uris{"4.3.2.1:/uri3"}->{connections}, 1);

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
is (thrasher_query_v2("10.10.10.10"), 0);
is (thrasher_query_v2("1.2.3.4"), 0);
is (thrasher_query_v2("4.3.2.1"), 0);
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
    thrasher_query_v2("10.10.10.10");
    thrasher_query_v2("1.2.3.4");
    thrasher_query_v3(1, "10.10.10.10", "host", "/");
    thrasher_query_v3(2, "1.2.3.4", "host", "/");
}

sleep(1);
%holddowns = thrasherd_http_holddowns();
is($holddowns{"1.2.3.4"}->{count}, 289);
is($holddowns{"1.2.3.4"}->{trigger}, "127.0.0.1");
cmp_ok($holddowns{"1.2.3.4"}->{timeout}, '>=', $softtimeout-1);
is($holddowns{"10.10.10.10"}->{count}, 289);
is($holddowns{"10.10.10.10"}->{trigger}, "127.0.0.1");
cmp_ok($holddowns{"10.10.10.10"}->{timeout}, '>=', $softtimeout-1);
is($holddowns{"4.3.2.1"}, undef);

is (thrasher_query_v1("10.10.10.10", "host", "/"), 1);
is (thrasher_query_v1("1.2.3.4", "host", "/"), 1);
is (thrasher_query_v1("4.3.2.1", "host", "/"), 0);
is (thrasher_query_v2("10.10.10.10"), 1);
is (thrasher_query_v2("1.2.3.4"), 1);
is (thrasher_query_v2("4.3.2.1"), 0);
is (thrasher_query_v3(1, "10.10.10.10", "host", "/"), 1);
is (thrasher_query_v3(2, "1.2.3.4", "host", "/"), 1);
is (thrasher_query_v3(3, "4.3.2.1", "host", "/"), 0);

%addrs = thrasherd_http_addrs();


# Cleanup
thrasher_remove("10.10.10.10");
thrasher_remove("1.2.3.4");
thrasher_remove("4.3.2.1");
sleep(1);

my %connections = thrasherd_http_connections();
is ($connections{"127.0.0.1:$main::sockport"}->{requests}, 635);
is ($connections{"127.0.0.1:$main::sockport"}->{connDate}, $main::connDate);
ok (exists $connections{"127.0.0.1:$main::sockport"}->{lastDate});

