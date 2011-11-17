#!/usr/bin/perl
# Simple regression script

use strict;
use IO::Socket;
use LWP::Simple;
use Test::More tests => 92;
use File::Temp qw/tempfile/;
use Data::Dumper;

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
    my $content = get("http://localhost:54321/holddowns");
    #print $content;
    foreach my $line (split(/\n/, $content)) {
        next if ($line =~ /Blocked/);
        chomp $line;
        my ($ip, $trigger, $count, $velocity, $timeout, $hardto, $recentto) = split(/ +/, $line);
        $holddowns{$ip} = {trigger => $trigger, count => $count, velocity=> $velocity, timeout => $timeout, hardTimeout => $hardto, recentTimeout => $recentto};
    }
    return %holddowns;
}

sub thrasherd_http_config {
    my %config;
    my $content = get("http://localhost:54321/config");
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
    my $content = get("http://localhost:54321/connections");
    #print $content;
    foreach my $line (split(/\n/, $content)) {
        next if ($line !~ /^\d/);
        chomp $line;
        my ($ip, $port, $requests, $conn, $last) = ($line =~ /^([\d\.]+) +(\d+) +(\d+) +(\w+ +\d+ [\d:]+) +(N.A|\w+ +\d+ [\d:]+)/);
        $connections{"$ip:$port"} = {requests => $requests, connDate => $conn, lastDate => $last};
    }
    #print Dumper(\%connections);
    return %connections;
}

sub thrasherd_http_addrs {
    my %addrs;
    my $content = get("http://localhost:54321/addrs");
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
    my $content = get("http://localhost:54321/uris");
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
    my $content = get("http://localhost:54321/hosts");
    #print $content;
    foreach my $line (split(/\n/, $content)) {
        next if ($line !~ /^\d/);
        chomp $line;
        my ($ip, $connections, $timeout, $host) = split(/ +/, $line);
        $hosts{"$ip:$host"} = {connections => $connections, timeout => $timeout};
    }
    return %hosts;
}

######################################################################

$main::thrasher = IO::Socket::INET->new('localhost:54320');
die "Couldn't connect to thrashd on 'localhost:54320'" if (!$main::thrasher);
$main::sockport = $main::thrasher->sockport();

if ($ARGV[0] eq "--singletest") {
    for (my $x = 0; $x < 300000; $x++) {
                thrasher_query_v1("10.11.10.10", "host", "/");
    }
    exit 0;
} elsif ($ARGV[0] eq "--spreadtest") {
    for (my $x = 0; $x < 50; $x++) {
        for (my $y = 0; $y < 50; $y++) {
            for (my $z = 0; $z < 500; $z++) {
                thrasher_query_v1("10.10.$x.$y", "host$x.$y", "/$x/$z");
            }
        }
    }
    exit 0;
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
is ($main::config{"URI block ratio"}, "10 hits over 11 seconds");
is ($main::config{"Host block ratio"}, "12 hits over 13 seconds");
is ($main::config{"ADDR block ratio"}, "14 hits over 15 seconds");
is ($main::config{"Soft block timeout"}, 6);
is ($main::config{"Hard block timeout"}, 10);
is ($main::config{"/"}, "16 hits over 17 seconds");
is ($main::config{"/url1"}, "18 hits over 19 seconds");
is ($main::config{"/foo/bar"}, "20 hits over 21 seconds");

my $softtimeout = $main::config{"Soft block timeout"};
my $hardtimeout = $main::config{"Hard block timeout"};

# Check our connection stats
my %connections = thrasherd_http_connections();
is ($connections{"127.0.0.1:$main::sockport"}->{requests}, 0);
is ($connections{"127.0.0.1:$main::sockport"}->{lastDate}, "N/A");
ok (exists $connections{"127.0.0.1:$main::sockport"}->{connDate});
$main::connDate = $connections{"127.0.0.1:$main::sockport"}->{connDate};

# First test adding ips to holddown
thrasher_add("10.10.10.10");
thrasher_add("1.2.3.4");

sleep(1);

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
cmp_ok($holddowns{"1.2.3.4"}->{velocity}, '<=', 1000);
cmp_ok($holddowns{"1.2.3.4"}->{timeout}, '>=', $softtimeout-1);
cmp_ok($holddowns{"1.2.3.4"}->{hardTimeout}, '>=', $hardtimeout-2);
is($holddowns{"1.2.3.4"}->{recentTimeout}, "N/A");
is($holddowns{"10.10.10.10"}->{count}, 4);
is($holddowns{"10.10.10.10"}->{trigger}, "255.255.255.255");
cmp_ok($holddowns{"10.10.10.10"}->{velocity}, '<=', 1000);
cmp_ok($holddowns{"10.10.10.10"}->{timeout}, '>=', $softtimeout-1);
is($holddowns{"10.10.10.10"}->{recentTimeout}, "N/A");
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

%holddowns = thrasherd_http_holddowns();
is($holddowns{"1.2.3.4"}->{count}, 286);
is($holddowns{"1.2.3.4"}->{trigger}, "127.0.0.1");
cmp_ok($holddowns{"1.2.3.4"}->{velocity}, '>=', 10000);
cmp_ok($holddowns{"1.2.3.4"}->{timeout}, '>=', $softtimeout-1);
cmp_ok($holddowns{"1.2.3.4"}->{hardTimeout}, '>=', $hardtimeout-1);
is($holddowns{"1.2.3.4"}->{recentTimeout}, "N/A");
is($holddowns{"10.10.10.10"}->{count}, 286);
is($holddowns{"10.10.10.10"}->{trigger}, "127.0.0.1");
cmp_ok($holddowns{"10.10.10.10"}->{velocity}, '>=', 10000);
cmp_ok($holddowns{"10.10.10.10"}->{timeout}, '>=', $softtimeout-1);
cmp_ok($holddowns{"10.10.10.10"}->{hardTimeout}, '>=', $hardtimeout-1);
is($holddowns{"10.10.10.10"}->{recentTimeout}, "N/A");
is($holddowns{"4.3.2.1"}, undef);

sleep(4);

is (thrasher_query_v1("10.10.10.10", "host", "/"), 1);
is (thrasher_query_v1("1.2.3.4", "host", "/"), 1);
is (thrasher_query_v1("4.3.2.1", "host", "/"), 0);
is (thrasher_query_v2("10.10.10.10"), 1);
is (thrasher_query_v2("1.2.3.4"), 1);
is (thrasher_query_v2("4.3.2.1"), 0);
is (thrasher_query_v3(1, "10.10.10.10", "host", "/"), 1);
is (thrasher_query_v3(2, "1.2.3.4", "host", "/"), 1);
is (thrasher_query_v3(3, "4.3.2.1", "host", "/"), 0);

# Make sure the hard timeout didn't get reset
%holddowns = thrasherd_http_holddowns();
cmp_ok($holddowns{"1.2.3.4"}->{timeout}, '>=', $holddowns{"1.2.3.4"}->{hardTimeout});
cmp_ok($holddowns{"10.10.10.10"}->{timeout}, '>=', $holddowns{"10.10.10.10"}->{hardTimeout});

# Make sure velocity is going down with no requests
cmp_ok($holddowns{"1.2.3.4"}->{velocity}, '<=', 1000);
cmp_ok($holddowns{"10.10.10.10"}->{velocity}, '<=', 1000);

%addrs = thrasherd_http_addrs();
is ($addrs{"1.2.3.4"}->{connections}, 6);
cmp_ok($holddowns{"10.10.10.10"}->{hardTimeout} + 1, '<', $addrs{"10.10.10.10"}->{timeout});
cmp_ok($holddowns{"1.2.3.4"}->{hardTimeout} + 1, '<', $addrs{"1.2.3.4"}->{timeout});

# Make sure when hard timeout fires, the addr table is cleared
sleep($holddowns{"10.10.10.10"}->{hardTimeout}+1);
%holddowns = thrasherd_http_holddowns();
%addrs = thrasherd_http_addrs();
is ($addrs{"1.2.3.4"}, undef);
is ($holddowns{"1.2.3.4"}, undef);
is ($addrs{"10.10.10.10"}, undef);
is ($holddowns{"10.10.10.10"}, undef);


# Cleanup
thrasher_remove("10.10.10.10");
thrasher_remove("1.2.3.4");
thrasher_remove("4.3.2.1");
sleep(1);

my %connections = thrasherd_http_connections();
is ($connections{"127.0.0.1:$main::sockport"}->{requests}, 635);
is ($connections{"127.0.0.1:$main::sockport"}->{connDate}, $main::connDate);
ok (exists $connections{"127.0.0.1:$main::sockport"}->{lastDate});
