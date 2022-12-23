package Regexp::F2B::Baphomet_YAML;

use 5.006;
use strict;
use warnings;
use File::Slurp;
use Exporter qw(import);
use YAML;

my @std_export = qw(
	parse_baphomet_yaml_file
	parse_baphomet_yaml_string
);
our %EXPORT_TAGS = ( 'std' => [@std_export], );

our @EXPORT = @std_export;

=head1 NAME

Regexp::F2B::Baphomet_YAML - Parse Fail2ban style INI files

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Regexp::F2B::Baphomet_YAML;
    use Data::Dumper;
    
    my $conf=parse_baphomet_yaml_file('foo.yaml');
    
    print Dumper($conf);

=head1 FUNCTIONS

=head2 parse_baphomet_yaml_file

Parses the specified file.

    my $conf=parse_baphomet_yaml_file('foo.yaml');

=cut

sub parse_baphomet_yaml_file {
	my ($file) = @_;

	if ( !defined($file) ) {
		die('No file specified');
	}

	if ( !-f $file ) {
		die( "'" . $file . "' does not exist" );
	}

	my $raw = read_file($file);

	if ( !defined($raw) ) {
		die('Got undef back from read_file');
	}

	my $conf;
	eval { $conf = parse_f2b_ini_string($raw); };
	if ($@) {
		die( 'parse_baphomet_yaml_string($raw) for the contents of "' . $file . '"... ' . $@ );
	}

	return parse_f2b_ini_string($raw);
}

=head2 parse_baphomet_yaml_string

Parses a f2b INI from a string.

   	my $raw=read_file($file);
    my $conf=parse_baphomet_yaml_string($raw);

=cut

sub parse_baphomet_yaml_string {
	my ($raw) = @_;

	if ( !defined($raw) ) {
		die('No string passed to parse');
	}


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
