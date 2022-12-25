package Regexp::F2B::INI;

use 5.006;
use strict;
use warnings;
use File::Slurp;
use Exporter qw(import);
use Regexp::F2B;

my @std_export = qw(
	parse_f2b_ini_file
	parse_f2b_ini_string
);
our %EXPORT_TAGS = ( 'std' => [@std_export], );

our @EXPORT = @std_export;

=head1 NAME

Regexp::F2B::INI - Parse Fail2ban style INI files

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Regexp::F2B::INI;
    use Data::Dumper;
    
    my $conf=parse_f2b_ini_file('/usr/local/etc/fail2ban/filter.d/sshd.conf');
    
    print Dumper($conf);

=head1 FUNCTIONS

=head2 parse_f2b_ini_file

Parses the specified file.

    my $conf=parse_f2b_ini_file('/usr/local/etc/fail2ban/filter.d/sshd.conf');

=cut

sub parse_f2b_ini_file {
	my ( $file ) = @_;

	if (!defined($file)) {
		die('No file specified');
	}

	if (! -f $file) {
		die("'".$file."' does not exist");
	}

	my $raw=read_file($file);

	if (!defined($raw)) {
		die('Got undef back from read_file');
	}

	my $conf;
	eval{
		$conf=parse_f2b_ini_string($raw);
	};
	if ($@) {
		die('parse_f2b_ini_string($raw) for the contents of "'.$file.'"... '.$@);
	}

	return parse_f2b_ini_string($raw);
}

=head2 parse_f2b_ini_string

Parses a f2b INI from a string.

   	my $raw=read_file($file);
    my $conf=parse_f2b_ini_string($raw);

=cut

sub parse_f2b_ini_string {
	my ( $raw ) = @_;

	if (!defined($raw)) {
		die('No string passed to parse');
	}

	my $conf={};

	my $var;
	my $sec='';
	my $line_number=1;
	foreach my $line (split(/\n/,$raw)) {
		my $data=undef;
		if ($line =~ /^[\ \t]*#/) {
			$var=undef;
		}elsif ($line =~ /^[\ \t]*$/) {
			$var=undef;
		}elsif ($line =~ /^\[[\ \t]*[A-Za-z0-9\-\_]+[\ \t]*\]/) {
			$sec=$line;
			$sec=~s/\[[\ \t]*//g;
			$sec=~s/[\ \t]*\].*$//g;
			if (!defined($conf->{$sec})) {
				$conf->{$sec}={};
			}else {
				die('Section "'.$sec.'" redefined at line "'.$line_number.'"');
			}
		}elsif ($line=~/^[\ \t]*[A-Za-z\-\_0-9]+[\ \t]=[\ \t]*.*$/) {
			$var=$line;
			$data=$line;
			$var=~s/^[\ \t]*([A-Za-z\-\_0-9]+)[\ \t]*=[\ \t]*.*$/$1/;
			$data=~s/^[\ \t]*[A-Za-z\-\_0-9]+[\ \t]*=[\ \t]*(.*)$/$1/;

			if (defined($conf->{$sec}{$var})) {
				die('$conf->{"'.$sec.'"}{"'.$var.'"} redefined at line '.$line_number);
			}else {
				$conf->{$sec}{$var}=[$data];
			}
		}elsif ($line =~ /^[\ \t]+.*$/) {
			if (!defined($var)) {
				die('Data line found at line '.$line_number.', but no variable is currently set');
			}
			$data=$line;
			$data=~ s/^[\ \t]+(.*)$/$1/;
			push(@{ $conf->{$sec}{$var} }, $data);
		}else {
			die('Failed to parse line '.$line_number);
		}

		$line_number++;
	}

	return $conf;
}

=head2 load

    - file :: File to load from.

    - vars :: A hash reference to use for extra variables or to be overriden.

The following will be passed to new if specified. See Regex::F2B->new for more info.

    - start_chomp
    - start_pattern

=cut

sub load {
	my ( $blank, %opts ) = @_;

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

	my %vars;

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
						if ( !defined( $opts{vars}{$var_name} ) ) {
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

	# add in the overrides...
	foreach my $var_name ( keys( %{ $opts{vars} } ) ) {
		$vars{$var_name} = $opts{vars}{$var_name};
		push( @scalar_keysA, $var_name );
		$scalar_keysH{$var_name} = 1;
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
	my $object = Regexp::F2B->new(
		lines         => $lines,
		regexp        => \@regexp,
		pre_regexp    => \@pre_regexp,
		ignore_regexp => \@ignore_regexp,
		start_chomp   => $opts{start_chomp},
		start_pattern => $opts{start_pattern},
	);

	$object->{vars} = \%vars;

	return $object;
}

=head1 F2B INI FORMAT

Has the basic INI sections style of /^[\ \t]*\[[\ \t]*([a-zA-Z0-9\-\_]+)[\ \t]*\]/.
Any white space before/after the section name between the [] is removed.
Anything after ] is ignored. If a section has not been declared yet, '', is
used as the section name.

Comments are lines matching /^[\ \t]*\#/.

Variables are all assumed to be arrays, given there is nothing to specify if a
variable is a array or not.

Variable names in the format of /[A-Za-z\-\_0-9]+/. Extraction is done via...

    $var=~s/^[\ \t]*([A-Za-z\-\_0-9]+)[\ \t]*=[\ \t]*.*$/$1/;

With the data section of the variable being extracted via...

    $data=~s/^[\ \t]*[A-Za-z\-\_0-9]+[\ \t]*=[\ \t]*(.*)$/$1/;

This assumes any white space at the end is relevant as it it is not possible to
tell if it is or not.

If the next line starts with white space and contains something after the white
space other than #, then it assumes it is part of the previous variable, removing
the starting white space and pushing it onto the array for the current variable.

Blank lines, comments, and sections unset the current variable and anything that
is not a new variable, comment, or section is considered an error.

    # the start of a file, current section ''
    a_variable=foo
    _another_var =bar
    _another_var_ = bar
    __another_var = item 0 of the array
                    item 1 of teh array

    [foo]
    # this is a the start of the section 'foo'
    
    _a_new-var_ = some thing

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-regexp-f2b at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Regexp-F2B>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Regexp::F2B::INI


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

1;    # End of Regexp::F2B::INI
