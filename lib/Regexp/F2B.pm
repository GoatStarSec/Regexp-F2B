package Regexp::F2B;

use 5.006;
use strict;
use warnings;
use File::Slurp;
use Data::Dumper;

=head1 NAME

Regexp::F2B - The great new Regexp::F2B!

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Regexp::F2B;

    # if using pre-compiled
    my $f2b = Regexp::F2B->new(
                               regexp=\@to_attempt_to_match,
                               lines=>1
                              );

    # reading it in from a file
    my $f2b = Regexp::F2B->new_from_file(
                              file=>'sshd.conf',
                              )

=head1 METHODS

=head2 new

Args

    - lines :: Number of match lines to use for mathcing.

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

	my $self = {
		lines     => $opts{lines},
		log_lines => [],
		regexp    => $opts{regexp},
	};
	bless $self;

	# process each regexp
	$int = 0;
	while ( defined( $self->{regexp}[$int] ) ) {
		if ( $self->{regexp}[$int] =~ /\<HOST\>/ ) {
			$self->{regexp}[$int] =~ s/\<HOST\>/(\[*[0-9\:\.a-z-A-Z]+\]*)/;
		}
		elsif ( $self->{regexp}[$int] =~ /\<IP4\>/ ) {
			$self->{regexp}[$int] =~ s/\<IP4\>/([1-9]+[0-9]*\.[1-9]+[0-9]*\.[1-9]+[0-9]*\.[1-9]+[0-9]*)/;
		}
		elsif ( $self->{regexp}[$int] =~ /\<IP6\>/ ) {
			$self->{regexp}[$int] =~ s/\<IP6\>/([\:0-9a-fA-F][\:0-9a-fA-F][\:0-9a-fA-F][\:0-9a-fA-F]*)/;
		}
		elsif ( $self->{regexp}[$int] =~ /\<DNS\>/ ) {
			$self->{regexp}[$int] =~ s/\<DNS\>/([a-zA-Z][a-zA-Z\-0-9\.]*[a-zA-Z\-0-9]+)/;
		}

		if ( $self->{regexp}[$int] =~ /\<SKIPLINES\>/ ) {
			$self->{regexp}[$int] =~ s/\<SKIPLINES\>/.*\n.*/g;
		}

		if ( $self->{regexp}[$int] !~ /\$$/ ) {
			$self->{regexp}[$int] = $self->{regexp}[$int] . '.*$';
		}
		if ( $self->{regexp}[$int] !~ /^\^/ ) {
			$self->{regexp}[$int] = '^.*' . $self->{regexp}[$int];
		}

		$int++;
	}

	return $self;
}

=head2 proc_lines

=cut

sub proc_line {
	my ( $self, $line ) = @_;

	if ( !defined($line) ) {
		die('No line passed');
	}

	chomp($line);

	push( @{ $self->{log_lines} }, $line );
	use Data::Dumper;
	print Dumper( $self->{log_lines} );
	if ( defined( $self->{log_lines}[ $self->{lines} ] ) ) {
		shift( @{ $self->{log_lines} } );
	}

	my $joined = '';

	foreach my $join_line ( @{ $self->{log_lines} } ) {
		print $join_line. "\n";
		$joined = $joined . $join_line . "\n";
	}
	chomp($joined);
	my $joined_orig = $joined;

	foreach my $regexp ( @{ $self->{regexp} } ) {
		$joined =~ s/$regexp/$1/;
		if ( $joined_orig ne $joined ) {
			return $joined;
		}
	}

	return 0;
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
