#!/usr/bin/perl

use strict;
use warnings;

sub func {
    my ($counters, $loop) = @_;
    for my $i ( 0 .. $loop ) {
        $counters->{$i}++;
    }
    for my $key (keys %$counters) {
	if ($key > 0) {
		delete $counters->{$key};
	}
    }
}

sub main {

    if ( $ENV{TRACE} ) {
        print "func\n";
    }

    my $counters = {};

    func($counters, 5);

    if ( $ENV{TRACE} ) {
        print "TRACKING_MALLOC_ENABLE: ", `echo \$TRACKING_MALLOC_ENABLE`, "\n";
    }

    print "set TRACKING_MALLOC_ENABLE = 1\n";
    $ENV{'TRACKING_MALLOC_ENABLE'} = 1;

    if ( $ENV{TRACE} ) {
        print "TRACKING_MALLOC_ENABLE: ", `echo \$TRACKING_MALLOC_ENABLE`, "\n";
    }

    if ( $ENV{TRACE} ) {
        print "func\n";
    }

    func($counters, 2);

    if ( $ENV{TRACE} ) {
        print "set TRACKING_MALLOC_ENABLE = 0\n";
    }

    $ENV{'TRACKING_MALLOC_ENABLE'} = 0;
    print "TRACKING_MALLOC_ENABLE: ", `echo \$TRACKING_MALLOC_ENABLE`, "\n";

    if ( $ENV{TRACE} ) {
        print "func again\n";
    }
    func($counters, 7);

    delete $ENV{'TRACKING_MALLOC_ENABLE'};
    if ( $ENV{TRACE} ) {
        print "TRACKING_MALLOC_ENABLE: ", `echo \$TRACKING_MALLOC_ENABLE`, "\n";
    }
}

main();

