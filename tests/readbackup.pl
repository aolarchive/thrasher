#!/usr/bin/perl
# Read backup file
use Socket;
use strict;

sub u16 {
    read(INPUT, my $buf, 2);
    my ($result) = unpack("n", $buf);
    return $result;
}

sub u32 {
    read(INPUT, my $buf, 4);
    my ($result) = unpack("N", $buf);
    return $result;
}

sub str {
    my $len = u16();
    read(INPUT, my $buf, $len);
    return $buf;
}

open (INPUT,"$ARGV[0]") || die "Can't open file $ARGV[0]";

die "Wrong file header" if (str() ne "thrasher");
die "Wrong version " if (u16() != 1);
my $seconds = u32();
my $elements = my $num = u32();

print ("elements = $elements\n");
printf("written time = %s\n", scalar localtime($seconds));

printf ("%24s %15s %15s %6s %8s %6s %6s\n", 
        "Last Time",
        "IP",
        "Reporting IP",
        "Count",
        "Ratio",
        "Soft",
        "Hard");

while ($num > 0) {
    my ($saddr, $count, $last_time, $first_addr, $ratio_connections, $ratio_timelimit, $softblock, $hardblock) = (u32(), u32(), u32(), u32(),u16(),u16(),u32(),u32());
    printf ("%23s %15s %15s %6d %8s %6d %6d\n", 
    scalar localtime($last_time),
    inet_ntoa(pack 'V', $saddr),
    inet_ntoa(pack 'V', $first_addr),
    $count,
    sprintf("%d:%d", $ratio_connections, $ratio_timelimit),
    $softblock,
    $hardblock);
    $num--;
}
