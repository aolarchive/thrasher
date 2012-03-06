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
my $version = u16();
die "Wrong version $version" if ($version > 2);
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
        "Hard",
        "Reason");

if ($html) {
    print '<style type="text/css">th{background:#444;text-align:left;color:#ccc;padding:4px 6px 6px;}td{background:#fff;border-bottom:1px solid #ccc;padding:2px 4px 4px;}</style>';
    printf ("<table>\n");
    printf ("<tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</tr>\n",  @headers);
} else {
    printf ("%24s %15s %15s %6s %8s %6s %6s %6s\n",  @headers);
}

while ($num > 0) {
    my ($saddr, $count, $last_time, $first_addr, $ratio_connections, $ratio_timelimit, $softblock, $hardblock) = (u32(), u32(), u32(), u32(),u16(),u16(),u32(),u32());
    my $reason = "";
    $reason = str() if ($version >= 2);
    my @data = (scalar localtime($last_time),
                inet_ntoa(pack 'V', $saddr),
                inet_ntoa(pack 'V', $first_addr),
                $count,
                sprintf("%d:%d", $ratio_connections, $ratio_timelimit),
                $softblock,
                $hardblock,
                $reason);
if ($html) {
    printf ("<tr><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%d</td><td>%d</tr>\n",  @data);
} else {
    printf ("%24s %15s %15s %6d %8s %6d %6d\n",  @data);
}
    $num--;
}

if ($html) {
    printf ("</table>");
}
