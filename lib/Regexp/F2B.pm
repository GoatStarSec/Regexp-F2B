package Regexp::F2B;

use 5.006;
use strict;
use warnings;
use File::Slurp;
use Data::Dumper;
use Regexp::F2B::INI;
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

	if ( !defined( $opts{regexp} ) ) {
		$opts{pre_regexp} = [];
	}
	else {
		if ( ref( $opts{regexp} ) ne 'ARRAY' ) {
			die( 'regexp is a ' . ref( $opts{regexp} ) . ' and not a array' );
		}
	}

	my $self = {
		lines                     => $opts{lines},
		log_lines                 => [],
		pre_regexp                => $opts{pre_regexp},
		regexp                    => $opts{regexp},
		regexp_has_mlf_id         => {},
		regexp_has_mlf_forget     => {},
		regexp_has_mlf_gain       => {},
		regexp_has_no_fail        => {},
		pre_regexp_has_mlf_id     => {},
		pre_regexp_has_mlf_forget => {},
		pre_regexp_has_no_fail    => {},
		pre_regexp_has_mlf_gain   => {},
	};
	bless $self;

	# process each regexp
	my @items = ( 'regexp', 'pre_regexp' );
	foreach my $regexp (@items) {
		$int = 0;
		while ( defined( $self->{$regexp}[$int] ) ) {
			if ( $self->{$regexp}[$int] =~ /\<HOST\>/ ) {
				$self->{$regexp}[$int] =~ s/\<HOST\>/($IPv4_re|$IPv6_re|[a-zA-Z][a-zA-Z\-0-9\.]*[a-zA-Z\-0-9]+)/;
			}
			elsif ( $self->{$regexp}[$int] =~ /\<ADDR\>/ ) {
				$self->{$regexp}[$int] =~ s/\<ADDR\>/($IPv4_re|$IPv6_re)/;
			}
			elsif ( $self->{$regexp}[$int] =~ /\<CIDR\>/ ) {
				$self->{$regexp}[$int]
					=~ s/\<CIDR\>/($IPv4_re\/\\b([1-9]|[12][0-9]|3[0-2])\\b|$IPv6_re\/\\b([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])\\b)/;
			}
			elsif ( $self->{$regexp}[$int] =~ /\<SUBNET\>/ ) {
				$self->{$regexp}[$int]
					=~ s/\<SUBNET\>/($IPv4_re|$IPv6_re|$IPv4_re\/\\b([1-9]|[12][0-9]|3[0-2])\\b|$IPv6_re\/\\b([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])\\b)/;
			}
			elsif ( $self->{$regexp}[$int] =~ /\<IP4\>/ ) {
				$self->{$regexp}[$int] =~ s/\<IP4\>/($IPv4_re)/;
			}
			elsif ( $self->{$regexp}[$int] =~ /\<IP6\>/ ) {
				$self->{$regexp}[$int] =~ s/\<IP6\>/($IPv6_re)/;
			}
			elsif ( $self->{$regexp}[$int] =~ /\<DNS\>/ ) {
				$self->{$regexp}[$int] =~ s/\<DNS\>/([a-zA-Z][a-zA-Z\-0-9\.]*[a-zA-Z\-0-9]+)/;
			}

			if ( $self->{$regexp}[$int] =~ /\<SKIPLINES\>/ ) {
				$self->{$regexp}[$int] =~ s/\<SKIPLINES\>/.*/g;
			}

			# remove F-USER bits as those are pointless
			if ( $self->{$regexp}[$int] =~ /\<F-[ALT\_]*USER[0-9]\>/ ) {
				$self->{$regexp}[$int] =~ s/\<F-[ALT\_]*USER[0-9]\>//g;
			}
			if ( $self->{$regexp}[$int] =~ /\<\/F-[ALT\_]*USER[0-9]\>/ ) {
				$self->{$regexp}[$int] =~ s/\<\/F-[ALT\_]*USER[0-9]\>//g;
			}

			# find F-MLFID lines
			if ( $self->{$regexp}[$int] =~ /\<F-MLFID\>/ ) {
				$self->{$regexp}[$int] =~ s/\<F-MLFID>/(/g;
				$self->{$regexp}[$int] =~ s/\<\/F-MLFID\>/)/g;
				$self->{hash_mlf_id}{$int} = 1;
			}
			elsif ( $self->{$regexp}[$int] =~ /\<\/F-MLFID\>/ ) {
				die(      $regexp . '['
						. $int
						. '] contains </F-MLFID> but no <F-MLFID>... '
						. Dumper( $self->{$regexp}[$int] ) );
				$self->{ $regexp . '_hash_mlf_id' }{$int} = 1;
			}
			else {
				$self->{ $regexp . '_hash_mlf_id' }{$int} = 0;
			}

			# find F-NOFAIL lines
			if ( $self->{$regexp}[$int] =~ /\<F-NOFAIL\>/ ) {
				$self->{$regexp}[$int] =~ s/\<F-NOFAIL>/(/g;
				$self->{$regexp}[$int] =~ s/\<\/F-NOFAIL\>/)/g;
				$self->{ $regexp . '_hash_no_fail' }{$int} = 1;
			}
			elsif ( $self->{$regexp}[$int] =~ /\<\/F-NOFAIL\>/ ) {
				die(      $regexp . '['
						. $int
						. '] contains </F-NOFAIL> but no <F-NOFAIL>... '
						. Dumper( $self->{$regexp}[$int] ) );
			}
			else {
				$self->{ $regexp . '_hash_no_fail' }{$int} = 0;
			}

			# find F-MLFFORGET lines
			if ( $self->{$regexp}[$int] =~ /\<F-MLFFORGET\>/ ) {
				$self->{$regexp}[$int] =~ s/\<F-MLFFORGET>//g;
				$self->{$regexp}[$int] =~ s/\<\/F-MLFFORGET\>//g;
				$self->{ $regexp . '_hash_mlf_forget' }{$int} = 1;
			}
			elsif ( $self->{regexp}[$int] =~ /\<\/F-MLFFORGET\>/ ) {
				die(      $regexp . '['
						. $int
						. '] contains </F-MLFFORGET> but no <F-MLFFORGET>... '
						. Dumper( $self->{$regexp}[$int] ) );
			}
			else {
				$self->{ $regexp . '_hash_mlf_forget' }{$int} = 0;
			}

			# find F-MLFGAIN lines
			if ( $self->{$regexp}[$int] =~ /\<F-MLFGAIN\>/ ) {
				$self->{$regexp}[$int] =~ s/\<F-MLFGAIN>//g;
				$self->{$regexp}[$int] =~ s/\<\/F-MLFGAIN\>//g;
				$self->{ $regexp . '_hash_mlf_gain' }{$int} = 1;
			}
			elsif ( $self->{regexp}[$int] =~ /\<\/F-MLFGAIN\>/ ) {
				die(      $regexp . '['
						. $int
						. '] contains </F-MLFGAIN> but no <F-MLFGAIN>... '
						. Dumper( $self->{$regexp}[$int] ) );
			}
			else {
				$self->{ $regexp . '_hash_mlf_gain' }{$int} = 0;
			}

			# add ^ and $ bits as needed
			if ( $self->{$regexp}[$int] !~ /\$$/ ) {
				$self->{$regexp}[$int] = $self->{$regexp}[$int] . '.*$';
			}
			if ( $self->{$regexp}[$int] !~ /^\^/ ) {
				$self->{$regexp}[$int] = '^.*' . $self->{$regexp}[$int];
			}

			$int++;
		}
	}

	return $self;
}

=head2 new_from_f2b_filter

=cut

sub new_from_f2b_filter {
	my ( $blank, %opts, %override_vars ) = @_;

	if ( !defined( $opts{file} ) ) {
		die('No value for file defined');
	}

	if ( !-f $opts{file} ) {
		die( '"' . $opts{file} . '" does not exist' );
	}

	my ( $vol, $dir, $file_name ) = File::Spec->splitpath( $opts{file} );

	my $confs = {};
	eval { $confs->{$file_name} = parse_f2b_ini_file( $opts{file} ); };

	# init the ordering based on the read file
	my @order;
	my @to_read;
	if (   defined( $confs->{$file_name}{INCLUDES}{after} )
		&& defined( $confs->{$file_name}{INCLUDES}{after}[0] ) )
	{
		push( @order, $confs->{$file_name}{INCLUDES}{after}[0], $file_name );
		push( @to_read, $confs->{$file_name}{INCLUDES}{after}[0] );
	}
	else {
		push( @order, $file_name );
	}
	if (   defined( $confs->{$file_name}{INCLUDES}{before} )
		&& defined( $confs->{$file_name}{INCLUDES}{before}[0] ) )
	{
		push( @to_read, $confs->{$file_name}{INCLUDES}{before}[0] );
	}

	# begin reading in other confs
	my $confs_read = { $file_name => 1 };
	foreach my $item (@to_read) {

		# don't die on non-existent .local files
		my $non_existent_fatal = 1;
		if ( $item =~ /\.local$/ ) {
			$non_existent_fatal = 0;
		}

		if ( !-f $dir . '/' . $item
			&& $non_existent_fatal )
		{
			die( "'" . $item . "' required and is not a .local file and does not exist" );
		}
		elsif ( -f $dir . '/' . $item ) {

			# make sure we have not read this previously
			if ( defined( $confs_read->{$item} ) ) {
				die( "'" . $item . "' has already been read... likely circular dependency" );
			}
			$confs_read->{$item} = 1;

			# try to parse the new file
			eval { $confs->{$item} = parse_f2b_ini_file( $dir . '/' . $item ); };
			if ($@) {
				die( '"' . $dir . '/' . $item . '" could not be parsed... ' . $@ );
			}

			if (   defined( $confs->{$item}{INCLUDES}{after} )
				&& defined( $confs->{$item}{INCLUDES}{after}[0] ) )
			{
				push( @order, $confs->{$item}{INCLUDES}{after}[0], $item );
				push( @to_read, $confs->{$item}{INCLUDES}{after}[0] );
			}
			else {
				push( @order, $item );
			}
			if (   defined( $confs->{$item}{INCLUDES}{before} )
				&& defined( $confs->{$item}{INCLUDES}{before}[0] ) )
			{
				push( @to_read, $confs->{$item}{INCLUDES}{before}[0] );
			}
		}
	}

	# @order is actually reversed given how it is generated
	# reverse it so it can be used with foreach
	@order = reverse(@order);

	my %vars = %override_vars;

	my @array_keysA;
	my @scalar_keysA;
	my %array_keysH;
	my %scalar_keysH;
	foreach my $conf (@order) {
		if ( defined( $confs->{$conf} ) ) {
			my @sections = grep( !/^INCLUDES$/, grep( !/^INCLUDES$/, keys( %{ $confs->{$conf} } ) ) );

			foreach my $section (@sections) {
				my $var_prepend = '';
				if ( $section ne 'DEFAULT' && $section ne 'Definition' ) {
					$var_prepend = $section . '/';
				}

				my @vars = keys( %{ $confs->{$conf}{$section} } );
				foreach my $var (@vars) {
					if ( $var eq 'datepattern' ) {
						delete( $confs->{$conf}{$section}{$var} );
					}
					else {
						my $var_name = $var_prepend . $var;
						if ( !defined( $override_vars{$var_name} ) ) {
							if ( defined( $confs->{$conf}{$section}{$var}[1] ) ) {
								$vars{$var_name} = $confs->{$conf}{$section}{$var};
								push( @array_keysA, $var_name );
								$array_keysH{$var_name} = 1;
							}
							elsif ( defined( $confs->{$conf}{$section}{$var}[0] ) ) {
								$vars{$var_name} = $confs->{$conf}{$section}{$var}[0];
								push( @scalar_keysA, $var_name );
								$scalar_keysH{$var_name} = 1;
							}
						}
					}
				}
			}
		}
	}

	my $loop_max   = 3;
	my $loop_count = 0;
	while ( $loop_count <= $loop_max ) {
		foreach my $scalar (@scalar_keysA) {
			foreach my $key ( keys(%vars) ) {
				if ( $scalar ne $key ) {
					my $quoted      = quotemeta($scalar);
					my $replacement = $vars{$scalar};
					if ( ref( $vars{$key} ) eq '' ) {
						$vars{$key} =~ s/<$quoted>/$replacement/g;
						$vars{$key} =~ s/\%\($quoted\)s/$replacement/g;
					}
					elsif ( ref( $vars{$key} ) eq 'ARRAY' ) {
						my $int = 0;
						while ( defined( $vars{$key}[$int] ) ) {
							$vars{$key}[$int] =~ s/<$quoted>/$replacement/g;
							$vars{$key}[$int] =~ s/\%\($quoted\)s/$replacement/g;
							$int++;
						}
					}
				}
			}
		}

		$loop_count++;
	}

	die( Dumper( \%vars ) );
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
	if ( defined( $self->{log_lines}[ $self->{lines} ] ) ) {
		shift( @{ $self->{log_lines} } );
	}

	my $joined = '';

	foreach my $join_line ( @{ $self->{log_lines} } ) {
		$joined = $joined . $join_line . "\n";
	}
	chomp($joined);
	my $joined_orig = $joined;

	foreach my $regexp ( @{ $self->{regexp} } ) {
		$joined =~ s/$regexp/$1/s;
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
