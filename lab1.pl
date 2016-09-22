#!/usr/bin/perl
use strict;
use warnings;
use Crypt::RSA;
use Crypt::CBC;
use Digest::MD5;
use Crypt::Random qw( makerandom );

my $symetrickey = makerandom( Size => 128, Strength => 1);
my $md5 = Digest::MD5->new;
my $cipher = Crypt::CBC->new( -key => $symetrickey);
my $rsa = new Crypt::RSA;
local $/ = undef;
open(my $fh, "<", "test.txt");	
open(my $ofh, ">", "testEncrypt.txt");
my $h1;
my ($alicePublic, $alicePrivate) = $rsa->keygen(Size => 3072);
my ($bobPublic, $bobPrivate) = $rsa->keygen(Size => 3072);
while(my $line = <$fh>) {	
	print $ofh $cipher->encrypt($line);
	$md5->add($line);
	$h1 = $md5->digest();
	print $h1;
	#print $ofh $rsa->encrypt(Message => $line,Key => $bobPublic);
}
close $ofh;
open($ofh, ">", "testdecrypt.txt");
open(my $encryptedFileHandle, "<", "testEncrypt.txt");

while (my $line = <$encryptedFileHandle>) {
	my $decryptedText = $cipher->decrypt($line);
	$md5->add($decryptedText);
	my $h2 = $md5->digest();
	if($h2 eq $h1){
		print "they are the sammmme \n";
	}
	print $ofh $decryptedText;
	#print $ofh $rsa->decrypt(Cyphertext => $line, Key => $bobPrivate);
}
close $fh;
close $ofh;
close $encryptedFileHandle;