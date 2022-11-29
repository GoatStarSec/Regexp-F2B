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

# make proc_line requires something passed
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new( regexp => ['.*src\:\ <HOST>, dst:.*$'] );
	$object->proc_line();
	$worked = 1;
};
ok( $worked eq '0', 'die on undef' ) or diag('Failed to die on undef line');

# make proc_line does not die when a line is defined
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new( regexp => ['.*src\:\ <HOST>, dst:.*$'] );
	$object->proc_line('foo');
	$worked = 1;
};
ok( $worked eq '1', 'dont die on def' ) or diag('Dies when a line is specified');

# make proc_line does not die when a line is defined
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new( regexp => ['.*src\:\ <HOST>, dst:.*$'] );
	if ( $object->proc_line('foo') ) {
		die('matched');
	}
	$worked = 1;
};
ok( $worked eq '1', 'dont match non-matching' ) or diag( 'Matched a line that it should not of ' . $@ );

# make sure proc_lines can be called multiple times
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new( regexp => ['.*src\:\ <HOST>, dst:.*$'] );
	$object->proc_line('foo1');
	$object->proc_line('foo2');
	$object->proc_line('foo3');
	$object->proc_line('foo4');
	$worked = 1;
};
ok( $worked eq '1', 'test multiple lines' ) or diag( 'Died when calling proc_line multiple times ' . $@ );

# make sure it will never have more then one line
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new( regexp => ['.*src\:\ <HOST>, dst:.*$'], lines => 1 );
	$object->proc_line('foo1');
	if ( defined( $object->{log_lines}[1] ) ) {
		die('log_lines[1] defined');
	}
	$object->proc_line('foo2');
	if ( defined( $object->{log_lines}[1] ) ) {
		die('log_lines[1] defined');
	}
	$object->proc_line('foo3');
	if ( defined( $object->{log_lines}[1] ) ) {
		die('log_lines[1] defined');
	}
	$object->proc_line('foo4');
	if ( defined( $object->{log_lines}[1] ) ) {
		die('log_lines[1] defined');
	}
	$worked = 1;
};
ok( $worked eq '1', 'ensure more never more 1' ) or diag( 'log_lines[1] defined... ' . $@ );

# make sure it will never have more then two line
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new( regexp => ['.*src\:\ <HOST>, dst:.*$'], lines => 2 );
	$object->proc_line('foo1');
	if ( defined( $object->{log_lines}[2] ) ) {
		die('log_lines[2] defined');
	}
	$object->proc_line('foo2');
	if ( defined( $object->{log_lines}[2] ) ) {
		die('log_lines[2] defined');
	}
	$object->proc_line('foo3');
	if ( defined( $object->{log_lines}[2] ) ) {
		die('log_lines[2] defined');
	}
	$object->proc_line('foo4');
	if ( defined( $object->{log_lines}[2] ) ) {
		die('log_lines[2] defined');
	}
	$worked = 1;
};
ok( $worked eq '1', 'ensure more never more 2' ) or diag( 'log_lines[2] defined... ' . $@ );

# make sure the log_lines is all good
$worked = 0;
$tests_ran++;
eval {
	$object = Regexp::F2B->new( regexp => ['.*src\:\ <HOST>, dst:.*$'], lines => 2 );
	$object->proc_line('foo1');
	if ( $object->{log_lines}[0] ne 'foo1' ) {
		die('log_lines[0] ne foo1');
	}
	$object->proc_line('foo2');
	if ( $object->{log_lines}[0] ne 'foo1' ) {
		die('log_lines[0] foo1');
	}
	if ( $object->{log_lines}[1] ne 'foo2' ) {
		die('log_lines[1] ne foo2');
	}
	$object->proc_line('foo3');
	if ( $object->{log_lines}[0] ne 'foo2' ) {
		die('log_lines[0] foo2');
	}
	if ( $object->{log_lines}[1] ne 'foo3' ) {
		die('log_lines[1] ne foo3');
	}
	$object->proc_line('foo4');
	if ( $object->{log_lines}[0] ne 'foo3' ) {
		die('log_lines[0] foo3');
	}
	if ( $object->{log_lines}[1] ne 'foo4' ) {
		die('log_lines[1] ne foo4');
	}
	$worked = 1;
};
ok( $worked eq '1', 'log_lines rotation test' ) or diag( 'log_lines rotation failing... ' . $@ );

done_testing($tests_ran);
