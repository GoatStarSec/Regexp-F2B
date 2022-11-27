#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
   use_ok('Regexp::F2B');
}

my $tests_ran=1;
my $object;

# Make sure the it wont create a object with stuff undefined.
my $worked=0;
$tests_ran++;
eval{
        $object=Regexp::F2B->new;
        $worked=1;
};
ok( $worked eq '0', 'all undef check') or diag("Created a object when all requirements were undef");

# 
$worked=0;
$tests_ran++;
eval{
        $object=Regexp::F2B->new(regexp=>['.*host\:\ <HOST>.*']);
        $worked=1;
};
ok( $worked eq '1', 'basic good test') or diag("Object creation failed... ".$@);

# 
$worked=0;
$tests_ran++;
eval{
        $object=Regexp::F2B->new(regexp=>['.*host\:\ <HOST>.*','(?{']);
        $worked=1;
};
ok( $worked eq '0', 'regexp exec test') or diag("regexp containining (?{ can be used".$@);

# 
$worked=0;
$tests_ran++;
eval{
	$object=Regexp::F2B->new(
							 regexp=>['.*host\:\ <HOST>.*'],
							 lines=>1,
							 );
	$worked=1;
};
ok( $worked eq '1', 'lines test 1') or diag("failed to create a object with a lines value of 1... ".$@);

# 
$worked=0;
$tests_ran++;
eval{
	$object=Regexp::F2B->new(
							 regexp=>['.*host\:\ <HOST>.*'],
							 lines=>0,
							 );
	$worked=1;
};
ok( $worked eq '0', 'lines test 2') or diag("created a object with a lines value of 0");

# 
$worked=0;
$tests_ran++;
eval{
	$object=Regexp::F2B->new(
							 regexp=>['.*host\:\ <HOST>.*'],
							 lines=>0,
							 );
	$worked=1;
};
ok( $worked eq '0', 'lines test 2') or diag("created a object with a lines value of 0");

# 
$worked=0;
$tests_ran++;
eval{
	$object=Regexp::F2B->new(
							 regexp=>['.*host\:\ <HOST>.*'],
							 lines=>2,
							 );
	$worked=1;
};
ok( $worked eq '1', 'lines test 3') or diag("failed to created a object with a lines value of 2... ".$@);

# 
$worked=0;
$tests_ran++;
eval{
	$object=Regexp::F2B->new(
							 regexp=>['.*host\:\ <HOST>.*'],
							 lines=>999,
							 );
	$worked=1;
};
ok( $worked eq '1', 'lines test 4') or diag("failed to created a object with a lines value of 999... ".$@);

# 
$worked=0;
$tests_ran++;
eval{
	$object=Regexp::F2B->new(
							 regexp=>['.*host\:\ <HOST>.*'],
							 lines=>-1,
							 );
	$worked=1;
};
ok( $worked eq '0', 'lines test 5') or diag("created a object with a lines value of -1");

done_testing($tests_ran);
