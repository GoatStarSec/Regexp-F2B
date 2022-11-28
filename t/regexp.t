#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;
use Data::Dumper;

BEGIN {
   use_ok('Regexp::F2B');
}

my $tests_ran=1;
my $object;

# make sure it will replace <HOST>
my $worked=0;
$tests_ran++;
eval{
	$object=Regexp::F2B->new(regexp=>['auth failed src\:\ <HOST>, dst:.*$']);
	if ($object->{regexp}[0] =~ /\<HOST\>/) {
		die($object->{regexp}[0]);
	}
	$worked=1;
};
ok( $worked eq '1', 'host replace test') or diag("did not replace <HOST>... ".$@);

# make sure it will replace <IP4>
$worked=0;
$tests_ran++;
eval{
	$object=Regexp::F2B->new(regexp=>['auth failed src\:\ <IP4>, dst:.*$']);
	if ($object->{regexp}[0] =~ /\<IP4\>/) {
		die($object->{regexp}[0]);
	}
	$worked=1;
};
ok( $worked eq '1', 'ip4 replace test') or diag("did not replace <IP4>... ".$@);

# host test
$worked=0;
$tests_ran++;
eval{
	$object=Regexp::F2B->new(regexp=>['auth failed src: <HOST>, dst:.*$']);
	my $line='2022-09-11T05:03:11 auth failed src: 1.2.3.4, dst:5.6.7.8';
	my $matched=$object->proc_line($line);
	if ($matched ne '1.2.3.4') {
		die("returned '".$matched."'\n\n".Dumper($line,$object));
	}
	$worked=1;
};
ok( $worked eq '1', 'host test1') or diag("match failed... ".$@);

# host test
$worked=0;
$tests_ran++;
eval{
	$object=Regexp::F2B->new(regexp=>['auth failed src: <HOST>, dst:.*$']);
	my $line='2022-09-11T05:03:11 auth failed src: foo.bar, dst:5.6.7.8';
	my $matched=$object->proc_line($line);
	if ($matched ne 'foo.bar') {
		die("returned '".$matched."'\n\n".Dumper($line,$object));
	}
	$worked=1;
};
ok( $worked eq '1', 'host test2') or diag("match failed... ".$@);

# ipv4 test
$worked=0;
$tests_ran++;
eval{
	$object=Regexp::F2B->new(regexp=>['auth failed src: <IP4>, dst:.*$']);
	my $line='2022-09-11T05:03:11 auth failed src: 1.2.3.4, dst:5.6.7.8';
	my $matched=$object->proc_line($line);
	if ($matched ne '1.2.3.4') {
		die("returned '".$matched."'\n\n".Dumper($line,$object));
	}
	$worked=1;
};
ok( $worked eq '1', 'host test2') or diag("match failed... ".$@);



done_testing($tests_ran);
