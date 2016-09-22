#!/usr/bin/perl
use strict;
use warnings;
use Crypt::RSA;
use Crypt::CBC;
use Crypt::Random qw( makerandom );

my $symetrickey = makerandom( Size => 128, Strength => 1);
print $symetrickey;
my $cipher = new Crypt::CBC->new(-key => $symetrickey);
print "hi NAME\n";
local $/ = undef;
open(my $fh, "<", "test.txt");	
open(my $ofh, ">", "testEncrypt.txt");
my $rsa = new Crypt::RSA;
my ($alicePublic, $alicePrivate) = $rsa->keygen(Size => 1024);
my ($bobPublic, $bobPrivate) = $rsa->keygen(Size => 1024);

while(my $line = <$fh>) {	
	print $ofh $cipher->encrypt($line);
	#print $ofh $rsa->encrypt(Message => $line,Key => $bobPublic);
}
close $ofh;
open($ofh, ">", "testdecrypt.txt");
open(my $encryptedFileHandle, "<", "testEncrypt.txt");

while (my $line = <$encryptedFileHandle>) {
	print $ofh $cipher->decrypt($line);
	#print $ofh $rsa->decrypt(Cyphertext => $line, Key => $bobPrivate);
}
close $fh;
close $ofh;
close $encryptedFileHandle;