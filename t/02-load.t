#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Regexp::F2B::Baphomet_YAML' ) || print "Bail out!\n";
}

diag( "Testing Regexp::F2B::Baphomet_YAML $Regexp::F2B::Baphomet_YAML::VERSION, Perl $], $^X" );
