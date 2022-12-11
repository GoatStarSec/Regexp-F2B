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

	if ( !defined( $opts{pre_regexp} ) ) {
		$opts{pre_regexp} = [];
	}
	else {
		if ( ref( $opts{pre_regexp} ) ne 'ARRAY' ) {
			die( 'regexp is a ' . ref( $opts{pre_regexp} ) . ' and not a array' );
		}
	}

	my $self = {
		lines         => $opts{lines},
		log_lines     => [],
		pre_regexp    => $opts{pre_regexp},
		ignore_regexp => $opts{ignore_regexp},
		regexp        => $opts{regexp},
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

		$value =~ s/\<F\-MLFID\>/(?<F-MLFID>/;
		$value =~ s/\<\/F\-MLFID\>/)/;
		$value =~ s/\<F-CONTENT\>/(?<F-CONTENT>/;
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
		if ( $self->{regexp}[$int] =~ /\<F\-[A-Za-z0-9\_\-]+\>/ ) {
			$self->{regexp}[$int] =~ s/(\<F\-[A-Za-z0-9\_\-]+\>)/(?$1/g;
		}
		if ( $self->{regexp}[$int] =~ /\<F\-[A-Za-z0-9\_\-]+\>/ ) {
			$self->{regexp}[$int] =~ s/\<\/F\-[A-Za-z0-9\_\-]+\>/)/g;
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

		# if it actually does not match anything, remove it
		if ( !$has_finder ) {
			push( @{ $to_drop->{regexp} }, $int );
		}

		# if this is meant to be able to include multiple lines, insert .* to allow it to do that
		if ( $self->{regexp}[$int] =~ /\<SKIPLINES\>/ ) {
			$self->{regexp}[$int] =~ s/\<SKIPLINES\>/.*/g;
		}

		$int++;
	}

	# remove any blank items
	my @items = ( 'pre_regexp', 'regexp' );
	foreach my $regexp (@items) {
		$int = 0;
		my @new_array;
		while ( defined( $self->{$regexp}[$int] ) ) {
			if ( $self->{$regexp}[$int] eq '' ) {
				delete( $self->{$regexp}[$int] );
			}
			else {
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

	# variable substitution pass
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

	# array joining pass
	$loop_max   = 5;
	$loop_count = 0;
	while ( $loop_count <= $loop_max ) {
		foreach my $key ( keys(%vars) ) {
			if ( ref( $vars{$key} ) eq '' ) {
				if ( $vars{$key} =~ /(^\<|\%\()[a-zA-Z0-9\_\-]+(\>|\)s)$/ ) {
					my $var = $vars{$key};
					$var =~ s/^(\<|\%\()//;
					$var =~ s/(\>|\)s)$//;
					if ( defined( $array_keysH{$var} )
						&& $key ne $var )
					{
						$vars{$key} = $vars{$var};
					}
				}
			}
			elsif ( ref( $vars{$key} ) eq 'ARRAY' ) {
				my $new_array = ();
				my $changed   = 0;
				foreach my $value ( @{ $vars{$key} } ) {
					if ( $value =~ /(^\<|\%\()[a-zA-Z0-9\_\-]+(\>|\)s)$/ ) {
						my $var = $value;
						$var =~ s/^(\<|\%\()//;
						$var =~ s/(\>|\)s)$//;
						if ( defined( $array_keysH{$var} )
							&& $key ne $var )
						{
							foreach my $tmp_value ( @{ $vars{$var} } ) {
								push( @{$new_array}, $tmp_value );
							}
							$changed = 1;
						}
					}
					else {
						push( @{$new_array}, $value );
					}
				}
				if ($changed) {
					$vars{$key} = $new_array;
				}
			}
		}

		$loop_count++;
	}

	my @pre_regexp;
	if ( defined( $vars{prefregex} ) ) {
		if ( ref( $vars{prefregex} ) eq 'ARRAY' ) {
			foreach my $value ( @{ $vars{prefregex} } ) {
				if ( $value ne '' ) {
					push( @pre_regexp, $value );
				}
			}

		}
		elsif ( ref( $vars{prefregex} ) eq '' ) {
			if ( $vars{prefregex} ne '' ) {
				push( @pre_regexp, $vars{prefregex} );
			}
		}
	}

	my @ignore_regexp;
	if ( defined( $vars{ignoreregex} ) ) {
		if ( ref( $vars{ignoreregex} ) eq 'ARRAY' ) {
			foreach my $value ( @{ $vars{ignoreregex} } ) {
				if ( $value ne '' ) {
					push( @ignore_regexp, $value );
				}
			}
		}
		elsif ( ref( $vars{ignoreregex} ) eq '' ) {
			if ( defined( $vars{ignoreregexp} )
				&& $vars{ignoreregexp} ne '' )
			{
				push( @ignore_regexp, $vars{ignoreregex} );
			}
		}
	}

	my @regexp;
	if ( defined( $vars{failregex} ) ) {
		if ( ref( $vars{failregex} ) eq 'ARRAY' ) {
			foreach my $value ( @{ $vars{failregex} } ) {
				if ( $value ne '' ) {
					push( @regexp, $value );
				}
			}
		}
		elsif ( ref( $vars{failregex} ) eq '' ) {
			if ( $vars{failregex} ne '' ) {
				push( @regexp, $vars{failregex} );
			}
		}
	}

	my $lines = 1;
	if (   defined( $vars{maxlines} )
		&& ref( $vars{maxlines} ) eq ''
		&& $vars{maxlines} =~ /^[1-9][0-9]*$/ )
	{
		$lines = $vars{maxlines};
	}

	#die(Dumper(\@pre_regexp));
	return Regexp::F2B->new(
		lines         => $lines,
		regexp        => \@regexp,
		pre_regexp    => \@pre_regexp,
		ignore_regexp => \@ignore_regexp,
	);
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

	my $found = { found => 0, };

	foreach my $join_line ( @{ $self->{log_lines} } ) {
		$joined = $joined . $join_line . "\n";
	}
	chomp($joined);

	my $int       = 0;
	my $not_found = 1;
	while ( defined( $self->{regexp}[$int] ) && $not_found ) {
		my $regexp = $self->{regexp}[$int];
		if ( $joined =~ /$regexp/ ) {
			foreach my $key ( keys(%+) ) {
				$not_found = 0;
				$found->{$key} = $+{$key};
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
