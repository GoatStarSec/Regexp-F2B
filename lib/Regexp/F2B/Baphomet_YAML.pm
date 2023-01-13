package Regexp::F2B::Baphomet_YAML;

use 5.006;
use strict;
use warnings;
use File::Slurp;
use Exporter qw(import);
use YAML::PP;

=head1 NAME

Regexp::F2B::Baphomet_YAML - Parse Fail2ban style INI files

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Regexp::F2B::Baphomet_YAML;
    use Data::Dumper;
    
    my $f2b_regexp_obj=Regexp::F2B::Baphomet_YAML->load('foo.yaml');
    
    print Dumper($conf);

=head1 METHODS

=head2 parse

Parses the specified file.

    my $conf=parse(file=>'foo.yaml',vars=>$vars);

=cut

sub parse {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{file} ) ) {
		die('No value for file defined');
	}

	if ( !-f $opts{file} ) {
		die( '"' . $opts{file} . '" does not exist' );
	}

	my ( $vol, $dir, $file_name ) = File::Spec->splitpath( $opts{file} );

	my $confs = {};

	# start reading in the configs
	my $ypp = YAML::PP->new;
	eval { $confs->{$file_name} = $ypp->load_file( $opts{file} ); };
	#eval { $confs->{$file_name} = Load( $opts{file} ); };
	if ($@) {
		die( 'Failed to read the file "' . $opts{file} . '"... ' . $@ );
	}

	# init the ordering based on the read file
	my @order;
	my @to_read;
	if (   defined( $confs->{$file_name}{includes} )
		&& defined( $confs->{$file_name}{includes}[0] ) )
	{
		push( @order,   $file_name );
		push( @to_read, @{ $confs->{$file_name}{includes} } );
	}else {
		push( @order,   $file_name );
	}

	# begin reading in other confs
	my $confs_read = { $file_name => 1 };
	foreach my $item (@to_read) {
		push( @order,   $item );
		if ( !-f $dir . '/' . $item ) {
			die( "'" . $item . "' required does not exist" );
		}

		# make sure we have not read this previously
		if ( defined( $confs_read->{$item} ) ) {
			die( "'" . $item . "' has already been read... likely circular dependency" );
		}
		$confs_read->{$item} = 1;

		# try to parse the new file
		eval { $confs->{$item} = $ypp->load_file( $dir . '/' . $item ); };
		if ($@) {
			die( 'Failed to read the file "' . $dir . '/' . $item . '" as a include for "'.$opts{file}.'"... ' . $@ );
		}

		if (   defined( $confs->{$item}{includes} )
			   && defined( $confs->{$item}{includes}[0] ) )
		{
			push( @order,   $item );
			push( @to_read, @{ $confs->{$item}{includes} } );
		}

	}

	# @order is actually reversed given how it is generated
	# reverse it so it can be used with foreach
	@order = reverse(@order);

	my %vars;
	my @vars_order;
	my $start_chomp;
	my $start_pattern;
	my @pre_regexp;
	my @regexp;
#	my $use_template;
#	my %template_config;
	#	my %template_vars;

	if (defined($opts{vars})) {
		%vars=%{$opts{vars}};
	}

	# real in the vars for each include
	foreach my $conf (@order) {

		if (defined( $confs->{$conf}{vars_order} ) &&
			defined( $confs->{$conf}{vars_order}[0] )
			) {
			push(@vars_order, @{  $confs->{$conf}{vars_order} });
		}

		if (defined( $confs->{$conf}{pre_regexp} ) &&
			defined( $confs->{$conf}{pre_regexp}[0] )
			) {
			push(@pre_regexp, @{  $confs->{$conf}{pre_regexp} });
		}

		if (defined( $confs->{$conf}{regexp} ) &&
			defined( $confs->{$conf}{regexp}[0] )
			) {
			push(@regexp, @{  $confs->{$conf}{regexp} });
		}

		if (defined( $confs->{$conf}{start_chomp} ) ){
			$start_chomp=$confs->{$conf}{start_chomp};
		}

		if (defined( $confs->{$conf}{start_pattern} ) ){
			$start_chomp=$confs->{$conf}{start_pattern};
		}

		if (defined( $confs->{$conf}{vars} ) ){
			my @conf_keys=keys( %{ $confs->{$conf}{vars} } );
			foreach my $conf_key (@conf_keys) {
				$vars{$conf_key}=$confs->{$conf}{vars}{$conf_key};
			}
		}
	}

	# process priority vars
	my @var_keys=keys( %vars );
	@vars_order=reverse(@vars_order);
	my $count=0;
	foreach my $item (@vars_order) {
		while ($count <= 1 ) {
			if (defined( $vars{$item} )) {
				foreach my $var (@var_keys) {
					my $val=$vars{$var};
					$vars{$item}=~s/\[\=\= *$var *\=\=\]/$val/g;
				}
			}

			$count++;
		}
	}

	# put all the vars together
	$count=0;
	while ($count <= 1 ) {
		foreach my $item (@var_keys) {
			foreach my $var (@var_keys) {
				foreach my $var (@var_keys) {
					if ($var ne $item) {
						my $val=$vars{$var};
						$vars{$item}=~s/\[\=\= *$var *\=\=\]/$val/g;
					}
				}
			}
		}

		$count++;
	}

	my $conf={
			  regexp=>\@regexp,
			  pre_regexp=>\@regexp,
			  vars=>\%vars,
			  vars_order=>\@vars_order,
			  start_chomp=>$start_chomp,
			  start_pattern=>$start_pattern,
			  };

	return $conf;
}

=head1 Baphomet YAML Schema

There are several vars.

    - vars :: A hash with various variables to use.
        - Default :: undef

    - vars_order :: A array with the order variables should be processed in.
        - Default :: undef

    - includes :: Array of include files to use. Anything used previously may not be re-included.
        - Default :: undef

    - start_chomp :: A 0 or 1 boolean for if the start of the line should
                     have a chunk removed.
        - Default :: undef

    - start_pattern :: Removes this from the start of log lines.
        - Default :: undef

    - pre_regexp :: An optional array regexps to used for matching lines and extracting content.

    - regexp :: An array of regexps to use.

=cut

#    - use_template :: A 0 or 1 boolean for if L<Template> should be used or not.
#        - Default :: 0

#    - template_config :: The config to pass to L<Template>. Include INCLUDE_PATH will be excluded if defined.

#    - template_vars :: Additional vars to pass to template if used. 'vars', 'start_chomp', and 'start_pattern'
#                       reserved variable names and as those from above will be passed as those.

=pod

    - tests :: A hash of tests for perform. See the relevant section below on that.
        - Default :: undef

=head1 Processing

The processing is done in the order below.

'[==' and '==]' are used for bracking variables to be replaced. Done like below.

    $foo~s/\[\=\=\ *$var\ *\=\=\]/$val/g;

=over 4

=item 1: Includes

Includes are read in order they are found. The order is then reversed for the
the purpose of working from the last included to the config file that started
it all.

A file may not be included more than once.

Files also must be in the same directory as the file being read.

    - vars :: May be added to, but no previously defined item may be replaced.

    - vars_order :: New items will be appended to the end.

    - start_chomp :: Overrides the previous set.

    - start_pattern :: Overrides the previous set.

    - pre_regexp :: New items will be appended to the end.

    - regexp :: New items will be appended to the end.

=cut

#    - use_template ::  Can be set if not already set.

#    - template_config :: May be added to, but no previously defined item may be replaced.

#    - template_vars :: May be added to, but no previously defined item may be replaced.

=pod

    - vars_order :: New items will be appended to the end.

=item 2: Variables, Priority

Initial variable substitutions made in order.

=item 3: Variables, Other

At this point two passes are made on the variables doing substitutions, but this time
for all variables.

=cut

#=item 4: Templating

#If use_template defined and set to 1, L<Template> is now used with the variables.

=pod

=item 4: Filling In Of pre_regexp, regexp, And start_pattern

Now that variable substitution and variable templating is done, the resulting variables are
used for filling in any substitutions in pre_regexp, regexp, and start_pattern.

=back

=head1 Simplified/Named Capture Groups

The following simplified capture groups that are autobuilt when used.

They when used, the capture group regexp is automatically filled in.

=over 4

=item <HOST>

Matches a domain name, IPv4 address, or IPv6 address.

=item <SUBNET>

Matches a IPv6 or IPv4 subnet or address.

=item <IP4>

Matches a IPv4 address.

=item <IP6>

Matches a IPv6 address.

=item <ADDR>

Matches a IPv4 or IPv6 address.

=item <DNS>

Matches a domainname.

=item <SRC> / <DEST>

These two are meant to be used in combination and only regard as being found if
matched together.

It will match either a IPv4 or IPv6 address.

=back

=head1 Tests

This is a hash of hash. The expected keys are below. The keys of the top level hash is the
test name. The following keys for each test are available.

    - line :: The log line to feed it.
    - found :: IF found should be 0 or 1.
    - data :: A hash of expected found captures and results.
    - undefed :: A list captures that sould not be defined.
    - vars :: A hash of vars to be used specified for passing at object creation.

Example...

    tests:
      found:
        line: "Dec 28 01:02:53 localhost foo[1234]: failed auth from 1.2.3.4"
        found: 1
        data:
          HOST: "1.2.3.4"
      notFound:
        line: "Dec 28 01:02:53 localhost foo[1234]: authed from 1.2.3.4"
        found: 0
        undefed: ["HOST"]

Defines two tests, one named 'found' and the other 'notFound'. The first
tests to make sure it is found and the capture group 'HOST' is '1.2.3.4'
and the second makes sure it is not found and that 'HOST' is not defined.

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
