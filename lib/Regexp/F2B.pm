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

sub new{
	my ( $blank, %opts ) = @_;

	# make sure we have something sane for lines
	if (!defined $opts{lines}) {
		$opts{lines}=0;
	}else {
		if ($opts{lines}!~/^[0-9]+$/) {
			die('lines is set to "'.$opts{lines}.'" which is not numeric');
		}

		if ($opts{lines} < 1) {
			die('lines is set to "'.$opts{lines}.'" which is less than 1');
		}

		# perl indexes from 0, so subtrack 1
		$opts{lines} = 		$opts{lines} - 1;
	}

	if (!defined($opts{regexp})) {
		die('regexp is undefined');
	}else {
		if (ref($opts{regexp}) ne 'ARRAY' ) {
			die('regexp is a '.ref($opts{regexp}).' and not a array');
		}
	}

	my $int=0;
	while (defined( $opts{regexp}[$int] )) {
		if (ref( \$opts{regexp}[$int] ) ne 'SCALAR' ) {
			die('regexp['.$int.'] is a '.ref( \$opts{regexp}[$int] ).' and not a scalar');
		}elsif (
				ref( \$opts{regexp}[$int] ) ne 'SCALAR' &&
				ref( $opts{regexp}[$int] ) ne 'SCALAR' ) {
			die('regexp['.$int.'] is a '.ref( $opts{regexp}[$int] ).' and not a scalar');
		}

		if ( $opts{regexp}[$int] =~ /\(\?\{/) {
			die('regexp['.$int.'], "'.$opts{regexp}[$int].'", contains "(?{"');
		}

		$int++;
	}

	my $self={
			  lines=>$opts{lines},
			  log_lines=>[],
			  regexp=>$opts{regexp},
			  };
	bless $self;

	return $self;
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

1; # End of Regexp::F2B
