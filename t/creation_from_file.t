#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;
use Data::Dumper;

BEGIN {
	use_ok('Regexp::F2B');
}

my $tests_ran = 1;
my $object;

# Make sure the it wont create a object with stuff undefined.
my $worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new_from_f2b_filter;
	$worked = 1;
};
ok( $worked eq '0', 'all undef check' ) or diag("Created a object when all requirements were undef");

# make sure it works with a known good file
$worked = 0;
$tests_ran++;
eval {
#	$object = Regexp::F2B->new_from_f2b_filter( file => 't/filter.d/fast-log-attack-src.conf' );
	$object = Regexp::F2B->new_from_f2b_filter( file => 't/filter.d/sshd.conf' );
	die(Dumper($object));
	$worked = 1;
};
ok( $worked eq '1', 'file exists check1' ) or diag( "Failed to load a simple known good file... " . $@ );

# make sure it works with a known good file
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new_from_f2b_filter( file => 't/filter.d/fast-log-attack-src.conf-does-not-exist' );
	$worked = 1;
};
ok( $worked eq '0', 'file exists check2' ) or diag("Does not die for non-existent files");

done_testing($tests_ran);
