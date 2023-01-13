#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;
use Data::Dumper;

BEGIN {
	use_ok('Regexp::F2B::Baphomet_YAML');
}

my $tests_ran = 1;
my $object;

# Make sure the it wont create a object with stuff undefined.
my $worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B::Baphomet_YAML->parse;
	$worked = 1;
};
ok( $worked eq '0', 'all undef check' ) or diag("Created a object when all requirements were undef");

# make sure it works with known good files
$worked = 0;
$tests_ran++;
eval {
#	$object = Regexp::F2B::Baphomet_YAML->parse( file => 't/baphomet/common.yaml' );
	$object = Regexp::F2B::Baphomet_YAML->parse( file => 't/baphomet/fastlog_MiscAtk.yaml' );
die(Dumper($object));
	$worked = 1;
};
ok( $worked eq '1', 'file check' ) or diag( "Failed to load a known good files... " . $@ );

done_testing($tests_ran);
