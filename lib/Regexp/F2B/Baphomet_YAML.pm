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
    
    my $f2b_regexp_obj=load('foo.yaml');
    
    print Dumper($conf);

=head1 FUNCTIONS

=head2 load

Parses the specified file.

    my $conf=load('foo.yaml');

=cut

sub load{
	my ($file)=@_;

	
}

=head1 Baphomet YAML Schema

There are several vars.

    - vars :: A hash with various variables to use.
        - Default :: undef

    - vars_order :: A array with the order variables should be processed in.
        - Default :: undef

    - include :: Include files to use. Anything used previously may not be re-included.
        - Default :: undef

    - start_chomp :: A 0 or 1 boolean for if the start of the line should
                     have a chunk removed.
        - Default :: undef

    - start_pattern :: Removes this from the start of log lines.
        - Default :: undef

    - pre_regexp :: An optional array regexps to used for matching lines and extracting content.

    - regexp :: An array of regexps to use.

    - use_template :: A 0 or 1 boolean for if L<Template> should be used or not.
        - Default :: 0

    - template_config :: The config to pass to L<Template>. Include INCLUDE_PATH will be excluded if defined.

    - template_vars :: Additional vars to pass to template if used. 'vars', 'start_chomp', and 'start_pattern'
                       reserved variable names and as those from above will be passed as those.

    - tests :: A hash of tests for perform. See the relevant section below on that.
        - Default :: undef

=head1 Processing

The processing is done in the order below.

=over 4

=item 1: Includes

Includes are read in order they are found. A file may not be included more than once. Files also must
be in the same directory as the file being read.

    - vars :: May be added to, but no previously defined item may be replaced.

    - vars_order :: New items will be appended to the end.

    - start_chomp :: Can be set if not already set.

    - start_pattern :: Can be set if not already set.

    - pre_regexp :: New items will be appended to the end.

    - regexp :: New items will be appended to the end.

    - use_template ::  Can be set if not already set.

    - template_config :: May be added to, but no previously defined item may be replaced.

    - template_vars :: May be added to, but no previously defined item may be replaced.

    - vars_order :: New items will be appended to the end.

=item 2: Variables, Priority

Initial variable substitutions made in order.

=item 3: Variables, Other

At this point two passes are made on the variables doing substitutions, but this time
for all variables.

=item 4: Templating

If use_template defined and set to 1, L<Template> is now used with the variables.

=item 5: Filling In Of pre_regexp And regexp

Now that variable substitution and variable templating is done, the resulting variables are
used for filling in any substitutions in pre_regexp and regexp.

=back

=head1 Tests

This is a hash of hash. The expected keys are below. The keys of the top level hash is the
test name. The following keys for each test are available.

    - line :: The log line to feed it.
    - found :: IF found should be 0 or 1.
    - data :: A hash of expected found captures and results.
    - undefed :: A list captures that sould not be defined.

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
