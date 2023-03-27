package Regexp::F2B;

use 5.006;
use strict;
use warnings;
use File::Slurp;
use Data::Dumper;
use File::Spec;
use Regexp::IPv6 qw($IPv6_re);
use Regexp::IPv4 qw($IPv4_re);

$Data::Dumper::Sortkeys = 1;

=head1 NAME

Regexp::F2B - The great new Regexp::F2B!

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Regexp::F2B;
    use Data::Dumper;

    my $f2b = Regexp::F2B->new(
                               regexp=\@to_attempt_to_match,
                               lines=>1
                              );

    my $found=$f2b->proc_line($some_log_line);

    print Dumper($found);

=head1 METHODS

=head2 new

Args

    - lines :: Number of match lines to use for mathcing. Defaults to 1.

    - pre_regexp ::

    - start_chomp :: Remove date at the start.
        - Default :: 1

    - start_pattern :: Removes this from the start of log lines.
        - Default :: (?<b_time>[a-zA-Z]+)\ +(?<d_time>\d+)\ +(?<T_time>(?<R_time>(?<H_time>\d+)\:(?<M_time>\d+))\:(?<S_time>\d+))\ +

=cut

sub new {
	my ( $blank, %opts ) = @_;

	# make sure we have something sane for lines
	if ( !defined $opts{lines} ) {
		$opts{lines} = 1;
	}
	else {
		if ( $opts{lines} !~ /^[0-9]+$/ ) {
			die( 'lines is set to "' . $opts{lines} . '" which is not numeric' );
		}

		if ( $opts{lines} < 1 ) {
			die( 'lines is set to "' . $opts{lines} . '" which is less than 1' );
		}
	}

	if ( !defined( $opts{regexp} ) ) {
		die('regexp is undefined');
	}
	else {
		if ( ref( $opts{regexp} ) ne 'ARRAY' ) {
			die( 'regexp is a ' . ref( $opts{regexp} ) . ' and not a array' );
		}
	}

	my $int = 0;
	while ( defined( $opts{regexp}[$int] ) ) {
		if ( ref( \$opts{regexp}[$int] ) ne 'SCALAR' ) {
			die( 'regexp[' . $int . '] is a ' . ref( \$opts{regexp}[$int] ) . ' and not a scalar' );
		}
		elsif (ref( \$opts{regexp}[$int] ) ne 'SCALAR'
			&& ref( $opts{regexp}[$int] ) ne 'SCALAR' )
		{
			die( 'regexp[' . $int . '] is a ' . ref( $opts{regexp}[$int] ) . ' and not a scalar' );
		}

		if ( $opts{regexp}[$int] =~ /\(\?\{/ ) {
			die( 'regexp[' . $int . '], "' . $opts{regexp}[$int] . '", contains "(?{"' );
		}

		$int++;
	}

	if ( !defined( $opts{pre_regexp} ) ) {
		$opts{pre_regexp} = [];
	}
	else {
		if ( ref( $opts{pre_regexp} ) ne 'ARRAY' ) {
			die( 'regexp is a ' . ref( $opts{pre_regexp} ) . ' and not a array' );
		}
	}

	if ( !defined( $opts{start_chomp} ) ) {
		$opts{start_chomp} = 1;
	}

	if ( !defined( $opts{start_pattern} ) ) {
		$opts{start_pattern}
			= '(?<b_time>[a-zA-Z]+)\ +(?<d_time>\d+)\ +(?<T_time>(?<R_time>(?<H_time>\d+)\:(?<M_time>\d+))\:(?<S_time>\d+))\ +';
	}

	my $self = {
		lines         => $opts{lines},
		log_lines     => [],
		pre_regexp    => $opts{pre_regexp},
		regexp        => $opts{regexp},
		start_pattern => $opts{start_pattern},
		start_chomp   => $opts{start_chomp},
	};
	bless $self;

	my $to_drop = { regexp => [], pre_regexp => [] };

	#
	#
	# process each pre_regexp
	#
	#
	$int = 0;
	my @pre_regexp_tmp;
	while ( defined( $self->{pre_regexp}[$int] ) ) {
		my $regexp = 'pre_regexp';
		my $value  = $self->{$regexp}[$int];

		# pre_regexp should not match any hosts etc... only for checking if it is a line we want and
		# maybe grabbing the bits we want to check via regexp
		if (   $value =~ /\<HOST\>/
			|| $value =~ /\<CIDR\>/
			|| $value =~ /\<SUBNET\>/
			|| $value =~ /\<IP4\>/
			|| $value =~ /\<IP6\>/
			|| $value =~ /\<ADDR\>/
			|| $value =~ /\<DNS\>/ )
		{
			die( "HOST, CIDR, SUBNET, IP4, IP6, and DNS may only be used in regexp... " . $value );
		}

		$value =~ s/\<F\-MLFID\>/(?<FMLFID>/;
		$value =~ s/\<\/F\-MLFID\>/)/;
		$value =~ s/\<F-CONTENT\>/(?<FCONTENT>/;
		$value =~ s/\<\/F-CONTENT\>/)/;

		if ( $value ne '' ) {
			push( @pre_regexp_tmp, $value );
		}

		$int++;
	}
	delete( $self->{pre_regexp} );
	$self->{pre_regexp} = \@pre_regexp_tmp;

	#
	#
	# process each regexp
	#
	#
	$int = 0;
	while ( defined( $self->{regexp}[$int] ) ) {

		# we should only have F-CONTENT in pre_regexp
		if (   $self->{regexp}[$int] =~ /\<F\-CONTENT\>/
			|| $self->{regexp}[$int] =~ /\<\/F\-CONTENT\>/ )

		{
			die( "F-CONTENT tags can only be used in pre_regexp and not regexp... '" . $self->{regexp}[$int] . "'" );
		}

		# process any /F-[A-Za-z0-9\_\-]+/ items
		if ( $self->{regexp}[$int] =~ /\<F\-[A-Za-z0-9\_]+\>/ ) {
			$self->{regexp}[$int] =~ s/\<F\-([A-Za-z0-9\_]+)\>/(?<F$1>/g;
		}
		if ( $self->{regexp}[$int] =~ /\<\/F\-[A-Za-z0-9\_]+\>/ ) {
			$self->{regexp}[$int] =~ s/\<\/F\-[A-Za-z0-9\_]+\>/)/g;
		}

		# add ^ and $ bits as needed
		if ( $self->{regexp}[$int] !~ /\$$/ ) {
			$self->{regexp}[$int] = $self->{regexp}[$int] . '.*$';
		}
		if ( $self->{regexp}[$int] !~ /^\^/ ) {
			$self->{regexp}[$int] = '^.*' . $self->{regexp}[$int];
		}

		# replace various tags with regexps for matching
		my $has_finder = 0;
		if ( $self->{regexp}[$int] =~ /\<HOST\>/ ) {
			$self->{regexp}[$int] =~ s/\<HOST\>/(?<HOST>$IPv4_re|$IPv6_re|[a-zA-Z][a-zA-Z\-0-9\.]*[a-zA-Z\-0-9]+)/;
			$has_finder = 1;
		}
		elsif ( $self->{regexp}[$int] =~ /\<ADDR\>/ ) {
			$self->{regexp}[$int] =~ s/\<ADDR\>/(?<ADDR>$IPv4_re|$IPv6_re)/;
			$has_finder = 1;
		}
		elsif ( $self->{regexp}[$int] =~ /\<CIDR\>/ ) {
			$self->{regexp}[$int]
				=~ s/\<CIDR\>/(?<CIDR>$IPv4_re\/\\b([1-9]|[12][0-9]|3[0-2])\\b|$IPv6_re\/\\b([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])\\b)/;
			$has_finder = 1;
		}
		elsif ( $self->{regexp}[$int] =~ /\<SUBNET\>/ ) {
			$self->{regexp}[$int]
				=~ s/\<SUBNET\>/(?<SUBNET>$IPv4_re|$IPv6_re|$IPv4_re\/\\b([1-9]|[12][0-9]|3[0-2])\\b|$IPv6_re\/\\b([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])\\b)/;
			$has_finder = 1;
		}
		elsif ( $self->{regexp}[$int] =~ /\<IP4\>/ ) {
			$self->{regexp}[$int] =~ s/\<IP4\>/(?<IP4>$IPv4_re)/;
			$has_finder = 1;
		}
		elsif ( $self->{regexp}[$int] =~ /\<IP6\>/ ) {
			$self->{regexp}[$int] =~ s/\<IP6\>/(?<IP6>$IPv6_re)/;
			$has_finder = 1;
		}
		elsif ( $self->{regexp}[$int] =~ /\<DNS\>/ ) {
			$self->{regexp}[$int] =~ s/\<DNS\>/(?<DNS>[a-zA-Z][a-zA-Z\-0-9\.]*[a-zA-Z\-0-9]+)/;
			$has_finder = 1;
		}

		if ( $self->{regexp}[$int] =~ /\<SRC\>/ ) {
			$self->{regexp}[$int] =~ s/\<SRC\>/(?<SRC>$IPv4_re|$IPv6_re)/;
			$has_finder = 1;
		}
		if ( $self->{regexp}[$int] =~ /\<DEST\>/ ) {
			$self->{regexp}[$int] =~ s/\<DEST\>/(?<DEST>$IPv4_re|$IPv6_re)/;
			$has_finder = 1;
		}

		# if it actually does not match anything, remove it
		if ( !$has_finder ) {
			push( @{ $to_drop->{regexp} }, $int );
		}

		# if this is meant to be able to include multiple lines, insert .* to allow it to do that
		if ( $self->{regexp}[$int] =~ /\<SKIPLINES\>/ ) {
			$self->{regexp}[$int] =~ s/\<SKIPLINES\>/.*/g;
		}

		# while pyhton allows conditionals for items like <foo> to be checked
		# via (?(foo), perl needs (?(<foo>)
		$self->{regexp}[$int] =~ s/\(\?\(([a-zA-Z_0-0][a-zA-Z_0-0]+)\)/(?(<$1>)/g;

		$int++;
	}

	# remove any blank items
	my @items = ( 'pre_regexp', 'regexp' );
	foreach my $regexp (@items) {
		$int = 0;
		my @new_array;
		while ( defined( $self->{$regexp}[$int] ) ) {
			if ( $self->{$regexp}[$int] ne '' ) {
				push( @new_array, $self->{$regexp}[$int] );
			}

			$int++;
		}
		delete( $self->{$regexp} );
		$self->{$regexp} = \@new_array;
	}

	# make sure we have atleast one item we can use
	foreach my $regexp (@items) {
		if ( !defined( $self->{regexp}[0] ) ) {
			die('Post processing there are no regexp defined');
		}
	}

	return $self;
}

=head2 proc_lines

=cut

sub proc_line {
	my ( $self, $line ) = @_;

	my $orig = $line;

	if ( !defined($line) ) {
		die('No line passed');
	}

	my $found = { found => 0, new_line => $orig, data => {} };

	if ( $self->{start_chomp} ) {
		my $regex = $self->{start_pattern};
		$line =~ s/^$regex//;
		my %found_items = %+;
		foreach my $key ( keys(%found_items) ) {
			$found->{data}{$key} = $found_items{$key};
		}
	}

	chomp($line);

	push( @{ $self->{log_lines} }, $line );
	if ( defined( $self->{log_lines}[ $self->{lines} ] ) ) {
		shift( @{ $self->{log_lines} } );
	}

	my $joined = '';

	foreach my $join_line ( @{ $self->{log_lines} } ) {
		$joined = $joined . $join_line . "\n";
	}
	chomp($joined);

	$found->{joined} = $joined;

	#
	# if we have a pre_regexp, search and see if we find anything
	#
	my $int       = 0;
	my $not_found = 1;
	while ( defined( $self->{pre_regexp}[$int] ) && $not_found ) {
		my $regexp = $self->{pre_regexp}[$int];
		if ( $joined =~ /$regexp/ ) {
			if ( defined( $+{'FCONTENT'} ) ) {
				$not_found                  = 0;
				$joined                     = $+{'FCONTENT'};
				$found->{data}{'F-CONTENT'} = $+{'FCONTENT'};
				if ( defined( $+{'FMLFID'} ) ) {
					$found->{data}{'F-MLFID'} = $+{'FMLFID'};
				}
			}
		}

		$int++;
	}

	# we did not any matching lines, so just return
	if ( defined( $self->{pre_regexp}[$int] ) && $not_found ) {
		return $found;
	}

	#
	# now search through each regexp for possible matches
	#
	$int       = 0;
	$not_found = 1;
	while ( defined( $self->{regexp}[$int] ) && $not_found ) {

		# copy this here so the key test for F keys does not cause an issue
		my $regexp = $self->{regexp}[$int];
		if ( $joined =~ /$regexp/ ) {
			my %found_items = %+;
			foreach my $key ( keys(%found_items) ) {
				$not_found = 0;
				if ( $key =~ /^F/ ) {
					my $new_key = $key;
					$new_key =~ s/^F/F-/;
					$found->{data}{$new_key} = $found_items{$key};
				}
				else {
					$found->{data}{$key} = $found_items{$key};
				}
			}
			$not_found = 0;
			$found->{found} = 1;
		}

		$int++;
	}

	return $found;
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-regexp-f2b at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Regexp-F2B>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Regexp::F2B


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Regexp-F2B>

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/Regexp-F2B>

=item * Search CPAN

L<https://metacpan.org/release/Regexp-F2B>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991


=cut

1;    # End of Regexp::F2B
