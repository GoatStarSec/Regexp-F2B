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
	my $object = Regexp::F2B::Baphomet_YAML->parse;
	$worked = 1;
};
ok( $worked eq '0', 'all undef check' ) or diag("Created a object when all requirements were undef");

# make sure it works with known good files
$worked = 0;
$tests_ran++;
eval {
	foreach my $yaml (@baphomet_yamls) {
		my $object = Regexp::F2B::Baphomet_YAML->parse( file => 't/baphomet/'.$yaml );
	}
	$worked = 1;
};
ok( $worked eq '1', 'load all' ) or diag( "Failed to load a known good files... " . $@ );

# does some basic checking on a parsed file
$worked = 0;
$tests_ran++;
eval {
	my $object = Regexp::F2B::Baphomet_YAML->parse( file => 't/baphomet/common.yaml' );

	if ( $object->{vars}{fastlog_pri} ne '\\[Priority\\: (?(pri)\\d+)\\]' ) {
		die 'parsing failed... $object->{vars}{fastlog_pri} ne \'\\[Priority\\: (?(pri)\\d+)\\]\'';
	}
	elsif ( $object->{vars}{snort_rule_id} ne '\\(?<group>d+)\\:\\(?<rule>d+)\\:\\(?<rev>d+)' ) {
		die 'parsing failed... $object->{vars}{snort_rule_id} ne \'\\(?<group>d+)\\:\\(?<rule>d+)\\:\\(?<rev>d+)\'... '
			. $object->{vars}{snort_rule_id};
	}
	elsif ( $object->{vars}{fastlog_proto} ne '\\{(?<proto>[a-zA-Z0-9]+)\\}' ) {
		die 'parsing failed... $object->{vars}{fastlog_proto} ne \'\\{(?<proto>[a-zA-Z0-9]+)\\}\'... '
			. $object->{vars}{fastlog_proto};
	}
	elsif ( $object->{vars}{log_src} ne '[A-Za-z0-9\\/]+' ) {
		die 'parsing failed... $object->{vars}{log_src} ne \'[A-Za-z0-9\\/]+\'... ' . $object->{vars}{log_src};
	}
	elsif ( $object->{vars}{fastlog_with_class} ne '^\\d\\d\\/\\d\\d\\/\\d\\d\\d\\d\\-\\d\\d\\:\\d\\d\\:\\d\\d\\.\\d+  \\[\\*\\*\\] \\[\\(?<group>d+)\\:\\(?<rule>d+)\\:\\(?<rev>d+)\\] [a-zA-Z0-9\\ \\-\\(\\)\\:] \\[\\*\\*\\] \\[Classification\\: (?<class>[== fastlog_class_to_use ==]) \\] \\[Priority\\: (?(pri)\\d+)\\] \\-\\-\\> \\{(?<proto>[a-zA-Z0-9]+)\\} <SRC>\\:(?<src_port>\\d+) <DEST>\\:(?<dst_port>\\d+)' ) {
		die  Dumper($object->{vars}{fastlog_with_class});
	}

	$worked = 1;
};
ok( $worked eq '1', 'parse check' ) or diag( "Failed to load a known good files... " . $@ );

done_testing($tests_ran);
