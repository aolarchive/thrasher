#!/usr/bin/perl
# Read backup file
use Socket;
use strict;

my $filename;

my $html = ($ARGV[0] eq "--html");
my $filename = ($ARGV[0] eq "--html"?$ARGV[1]:$ARGV[0]);

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

open (INPUT,$filename) || die "Can't open file $filename";

die "Wrong file header" if (str() ne "thrasher");
die "Wrong version " if (u16() != 1);
my $seconds = u32();
my $elements = my $num = u32();

print ("elements = $elements\n");
printf("written time = %s\n", scalar localtime($seconds));
my @headers = (
        "Last Time",
        "IP",
        "Reporting IP",
        "Count",
        "Ratio",
        "Soft",
        "Hard");

if ($html) {
    print '<style type="text/css">th{background:#444;text-align:left;color:#ccc;padding:4px 6px 6px;}td{background:#fff;border-bottom:1px solid #ccc;padding:2px 4px 4px;}</style>';
    printf ("<table>\n");
    printf ("<tr><th>%24s</th><th>%15s</th><th>%15s</th><th>%6s</th><th>%8s</th><th>%6s</th><th>%6s</tr>\n",  @headers);
} else {
    printf ("%24s %15s %15s %6s %8s %6s %6s\n",  @headers);
}

while ($num > 0) {
    my ($saddr, $count, $last_time, $first_addr, $ratio_connections, $ratio_timelimit, $softblock, $hardblock) = (u32(), u32(), u32(), u32(),u16(),u16(),u32(),u32());
    my @data = (scalar localtime($last_time),
                inet_ntoa(pack 'V', $saddr),
                inet_ntoa(pack 'V', $first_addr),
                $count,
                sprintf("%d:%d", $ratio_connections, $ratio_timelimit),
                $softblock,
                $hardblock);
if ($html) {
    printf ("<tr><td>%24s</td><td>%15s</td><td>%15s</td><td>%6d</td><td>%8s</td><td>%6d</td><td>%6d</tr>\n",  @data);
} else {
    printf ("%24s %15s %15s %6d %8s %6d %6d\n",  @data);
}
    $num--;
}

if ($html) {
    printf ("</table>");
}
