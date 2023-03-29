#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;
use Data::Dumper;

BEGIN {
	use_ok('Regexp::F2B::Baphomet_YAML');
}

my $tests_ran = 1;

my @baphomet_yamls = qw/
	common.yaml
	fastlog_ADoS.yaml
	fastlog_AUPG.yaml
	fastlog_blankC.yaml
	fastlog_C2domain.yaml
	fastlog_ConfChg.yaml
	fastlog_ConfErr.yaml
	fastlog_CredTheft.yaml
	fastlog_DoS.yaml
	fastlog_DOS.yaml
	fastlog_DRPCQ.yaml
	fastlog_ExeCode.yaml
	fastlog_ExpAtmp.yaml
	fastlog_ExpKit.yaml
	fastlog_FoDAccAtmp.yaml
	fastlog_GenICMP.yaml
	fastlog_GPCD.yaml
	fastlog_HWevent.yaml
	fastlog_IL.yaml
	fastlog_LrgSclIL.yaml
	fastlog_MalC2act.yaml
	fastlog_Mining.yaml
	fastlog_MiscActivity.yaml
	fastlog_MiscAtk.yaml
	fastlog_NetEvent.yaml
	fastlog_NetScan.yaml
	fastlog_NetTrojan.yaml
	fastlog_not_AppCont.yaml
	fastlog_not_DefUserPass.yaml
	fastlog_not_IL.yaml
	fastlog_not_LoginUsername.yaml
	fastlog_not_SucAdmPG.yaml
	fastlog_not_SucUsrPG.yaml
	fastlog_not_SusT.yaml
	fastlog_NS_PoE.yaml
	fastlog_OddClntPrt.yaml
	fastlog_PosSocEng.yaml
	fastlog_PotBadTraf.yaml
	fastlog_PotCorpPriVio.yaml
	fastlog_PotUnwantedProg.yaml
	fastlog_PotVulWebApp.yaml
	fastlog_ProgErr.yaml
	fastlog_RetrExtIP.yaml
	fastlog_Spam.yaml
	fastlog_SucAdmPG.yaml
	fastlog_SucUsrPG.yaml
	fastlog_SusFilename.yaml
	fastlog_SusProgExec.yaml
	fastlog_SusString.yaml
	fastlog_SusT.yaml
	fastlog_Syscall.yaml
	fastlog_SysEvent.yaml
	fastlog_TargetedMalAct.yaml
	fastlog_TCPconn.yaml
	fastlog_Unknown_T.yaml
	fastlog_WebAppAtk.yaml
	/;

# Make sure the it wont create a object with stuff undefined.
my $worked = 0;
$tests_ran++;
eval {
	my $object = Regexp::F2B::Baphomet_YAML->load;
	$worked = 1;
};
ok( $worked eq '0', 'all undef check' ) or diag("Created a object when all requirements were undef");

# make sure it works with a known good file
$worked = 0;
$tests_ran++;
eval {
	my $object = Regexp::F2B::Baphomet_YAML->load( file => 't/baphomet/common.yaml' );
	$worked = 1;
};
ok( $worked eq '0', 'load common' ) or diag("Loaded common.yaml, which a include and not a full rule file...");

# make sure it works with a known good file
$worked = 0;
$tests_ran++;
eval {
	my $object = Regexp::F2B::Baphomet_YAML->load( file => 't/baphomet/fastlog_NetScan.yaml' );
	if ( ref($object) ne 'Regexp::F2B' ) {
		die( 'ref($object) is "' . ref($object) . '" and not Regexp::F2B... ' . Dumper($object) );
	}

	if ( $object->{lines} ne 1 ) {
		die( '$object->{lines} ne 1... ' . Dumper($object) );
	}

	if ( $object->{start_chomp} ne 1 ) {
		die( '$object->{start_chomp} ne 1... ' . Dumper($object) );
	}

	if (
		$object->{start_pattern} ne '^\\d\\d\\/\\d\\d\\/\\d\\d\\d\\d\\-\\d\\d\\:\\d\\d\\:\\d\\d\\.\\d+  \\[\\*\\*\\] ' )
	{
		die(
			'$object->{start_pattern} ne \'^\\d\\d\\/\\d\\d\\/\\d\\d\\d\\d\\-\\d\\d\\:\\d\\d\\:\\d\\d\\.\\d+  \\[\\*\\*\\] \'... '
				. Dumper($object) );
	}

	if ( $object->{regexp}[0] ne
		'^.*\\[(?<group>\\d+)\\:(?<rule>\\d+)\\:(?<rev>\\d+)\\] [a-zA-Z0-9\\ \\-\\(\\)\\:]+ \\[\\*\\*\\] \\[Classification\\: (?<class>Detection of a Network Scan)\\] \\[Priority\\: (?<pri>\\d+)\\] \\{(?<proto>[a-zA-Z0-9]+)\\} (?<SRC>(?^:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})(?:\\.(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})){3}))|(?^::(?::[0-9a-fA-F]{1,4}){0,5}(?:(?::[0-9a-fA-F]{1,4}){1,2}|:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}|:)|(?::(?:[0-9a-fA-F]{1,4})?|(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})?|))|(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[0-9a-fA-F]{1,4}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){0,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,2}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,3}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,4}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))))\\:(?<src_port>\\d+) \\-+\\> (?<DEST>(?^:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})(?:\\.(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})){3}))|(?^::(?::[0-9a-fA-F]{1,4}){0,5}(?:(?::[0-9a-fA-F]{1,4}){1,2}|:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}|:)|(?::(?:[0-9a-fA-F]{1,4})?|(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})?|))|(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[0-9a-fA-F]{1,4}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){0,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,2}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,3}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))|(?:(?::[0-9a-fA-F]{1,4}){0,4}(?::(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[0-9a-fA-F]{1,4}){1,2})|:))))\\:(?<dst_port>\\d+).*$'
	)
	{
		die( '$object->{regexp}[0] is not the expected ressults... ' . Dumper($object) );
	}

	$worked = 1;
};
ok( $worked eq '1', 'load all' ) or diag( "Failed to load a known good files... " . $@ );

done_testing($tests_ran);
