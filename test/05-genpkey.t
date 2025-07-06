#!/usr/bin/perl
use Test2::V0;

skip_all('This test is only suitable for the provider')
    unless $ARGV[0] eq 'provider';
plan(2);

my $prov = $ENV{'PROVIDER_NAME'} || 'gostprov';
my $cmd;

$cmd = "openssl genpkey -algorithm gost2012_256 -provider $prov -provider default -out tmp-key.pem";
my $out = `$cmd 2>&1`;
ok($? == 0, 'genpkey via provider');

$cmd = "openssl pkey -in tmp-key.pem -provider $prov -provider default -text -noout";
$out = `$cmd 2>&1`;
like($out, qr/Private-Key/, 'read generated key');

unlink 'tmp-key.pem';
