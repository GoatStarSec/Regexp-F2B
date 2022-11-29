#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Regexp::F2B');
}

my $tests_ran = 1;
my $object;

# Make sure the it wont create a object with stuff undefined.
my $worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new;
	$worked = 1;
};
ok( $worked eq '0', 'all undef check' ) or diag("Created a object when all requirements were undef");

# make sure it will will accept regexp
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new( regexp => ['.*host\:\ <HOST>.*'] );
	$worked = 1;
};
ok( $worked eq '1', 'basic good test' ) or diag( "Object creation failed... " . $@ );

# make sure it won't accept executable regexp
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new( regexp => [ '.*host\:\ <HOST>.*', '(?{' ] );
	$worked = 1;
};
ok( $worked eq '0', 'regexp exec test' ) or diag( "regexp containining (?{ can be used" . $@ );

# make sure it will create lines 1
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new(
		regexp => ['.*host\:\ <HOST>.*'],
		lines  => 1,
	);
	$worked = 1;
};
ok( $worked eq '1', 'lines test 1' ) or diag( "failed to create a object with a lines value of 1... " . $@ );

# make sure it won't accept lines set to 0
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new(
		regexp => ['.*host\:\ <HOST>.*'],
		lines  => 0,
	);
	$worked = 1;
};
ok( $worked eq '0', 'lines test 2' ) or diag("created a object with a lines value of 0");

#
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new(
		regexp => ['.*host\:\ <HOST>.*'],
		lines  => 2,
	);
	$worked = 1;
};
ok( $worked eq '1', 'lines test 3' ) or diag( "failed to created a object with a lines value of 2... " . $@ );

# make sure it will accept large lines values
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new(
		regexp => ['.*host\:\ <HOST>.*'],
		lines  => 999,
	);
	$worked = 1;
};
ok( $worked eq '1', 'lines test 4' ) or diag( "failed to created a object with a lines value of 999... " . $@ );

# make sure it won't accept negative numbers
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new(
		regexp => ['.*host\:\ <HOST>.*'],
		lines  => -1,
	);
	$worked = 1;
};
ok( $worked eq '0', 'lines test 5' ) or diag("created a object with a lines value of -1");

# make sure it won't accept negative numbers
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new(
		regexp => ['.*host\:\ <HOST>.*'],
		lines  => -999,
	);
	$worked = 1;
};
ok( $worked eq '0', 'lines test 5' ) or diag("created a object with a lines value of -999");

done_testing($tests_ran);
