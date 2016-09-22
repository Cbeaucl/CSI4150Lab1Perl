#!/usr/bin/perl
use strict;
use warnings;
use Crypt::RSA;
use Crypt::CBC;
use Digest::MD5;
use Crypt::Random qw( makerandom );

my $symetrickey = makerandom( Size => 128, Strength => 1);
my $md5 = Digest::MD5->new;
my $aliceCipher = Crypt::CBC->new( -key => $symetrickey);
my $rsa = new Crypt::RSA;
local $/ = undef;
open(my $fh, "<", "test.txt");	
open(my $ofh, ">", "testEncrypt.txt");
my $h1;
my $encryptedKey;
my ($alicePublic, $alicePrivate) = $rsa->keygen(Size => 3072);
my ($bobPublic, $bobPrivate) = $rsa->keygen(Size => 3072);
#Alice Actions
while(my $line = <$fh>) {	
	print $ofh $aliceCipher->encrypt($line);
	$md5->add($line);
	$h1 = $md5->digest();
	$encryptedKey = $rsa->encrypt(Message => $symetrickey,Key => $bobPublic);
}
my $aliceSignature = $rsa->sign(Message=>$h1, Key =>$alicePrivate);


close $ofh;
open($ofh, ">", "testdecrypt.txt");
open(my $encryptedFileHandle, "<", "testEncrypt.txt");
#BobActions
while (my $line = <$encryptedFileHandle>) {
	my $decyptedKey = $rsa->decrypt (Cyphertext=> $encryptedKey, Key=>$bobPrivate);
	my $bobCipher = Crypt::CBC->new( -key => $decyptedKey);
	my $decryptedText = $bobCipher->decrypt($line);
	$md5->add($decryptedText);
	my $h2 = $md5->digest();
	my $h = $rsa->verify(Message =>$h2, Signature=> $aliceSignature, Key=>$alicePublic);
	if($h == 1){
		print "Hash is good, and Signature matches\n";
	}else {
		print "ermagerd you've been hacked GASP\n";
	}
	if($h2 eq $h1){
		print "they are the sammmme \n";
	}
	print $ofh $decryptedText;
	#print $ofh $rsa->decrypt(Cyphertext => $line, Key => $bobPrivate);
}
close $fh;
close $ofh;
close $encryptedFileHandle;