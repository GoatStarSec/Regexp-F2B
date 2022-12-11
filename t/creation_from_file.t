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

# # make sure it works with known good files
# $worked = 0;
# $tests_ran++;
# eval {
# 	$object = Regexp::F2B->new_from_f2b_filter( file => 't/filter.d/fast-log-attack-src.conf' );
# 	$object = Regexp::F2B->new_from_f2b_filter( file => 't/filter.d/sshd.conf' );
# 	$worked = 1;
# };
# ok( $worked eq '1', 'file check' ) or diag( "Failed to load a known good files... " . $@ );

# # make sure it works with a known good file
# $worked = 0;
# $tests_ran++;
# eval {
# 	$object = Regexp::F2B->new_from_f2b_filter( file => 't/filter.d/fast-log-attack-src.conf-does-not-exist' );
# 	$worked = 1;
# };
# ok( $worked eq '0', 'file does not exist exists check' ) or diag("Does not die for non-existent files");

# # test matching of loaded items
# $worked = 0;
# $tests_ran++;
# my $test='12/08/2022-21:44:56.542761  [**] [1:2402000:6468] ET DROP Dshield Block Listed Source group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 205.210.31.54:53983 -> 192.168.14.42:8';
# my $expected='205.210.31.54';
# eval {
# 	$object = Regexp::F2B->new_from_f2b_filter( file => 't/filter.d/fast-log-attack-src.conf' );
# 	my $found=$object->proc_line($test);
# 	if ($found ne $expected) {
# 		die('$object->proc_lines($test) did not return the expected "'.$expected.'" for "'.$test.'"... got... '.Dumper($found));
# 	}
# 	$worked = 1;
# };
# ok( $worked eq '1', 'matching check2' ) or diag( "Failed to load a simple known good file... " . $@ );

# test matching of loaded items
# $worked = 0;
# $tests_ran++;
# $test='12/08/2022-21:44:56.542761  [**] [1:2402000:6468] ET DROP Dshield Block Listed Source group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 205.210.31.54:53983 -> 192.168.14.42:8';
# $expected='205.210.31.54';
# eval {
# 	$object = Regexp::F2B->new_from_f2b_filter( file => 't/filter.d/sshd.conf' );
# 	my $found=$object->proc_line($test);
# 	if ($found ne $expected) {
# 		die('$object->proc_lines($test) did not return the expected "'.$expected.'" for "'.$test.'"... got... '.Dumper($found));
# 	}
# 	$worked = 1;
# };
# ok( $worked eq '1', 'matching check2' ) or diag( "Failed to load a simple known good file... " . $@ );

done_testing($tests_ran);
