#!/usr/bin/perl
use strict;
use warnings;
use Crypt::RSA;
use Crypt::CBC;
use Digest::MD5;
use Crypt::Random qw( makerandom );

my $symetrickey = makerandom( Size => 128, Strength => 1 );
my $md5         = Digest::MD5->new;
my $aliceCipher = Crypt::CBC->new( -key => $symetrickey );
my $rsa         = new Crypt::RSA;
local $/ = undef;
open( my $fh,  "<", "test.txt" );
open( my $ofh, ">", "testEncrypt.txt" );
my $h1;
my $encryptedKey;

#Generate Key Pairs for both Bob and Alice.
my ( $alicePublic, $alicePrivate ) = $rsa->keygen( Size => 3072 );
my ( $bobPublic,   $bobPrivate )   = $rsa->keygen( Size => 3072 );

#Alice Actions
my $line = <$fh>;

#Ecrypt File and write it to file.
print $ofh $aliceCipher->encrypt($line);

#Compute Hash.
$md5->add($line);
$h1 = $md5->digest();

#Encrypt symetric key with Bobs Public Key.
$encryptedKey = $rsa->encrypt( Message => $symetrickey, Key => $bobPublic );

#Sign Hash.
my $aliceSignature = $rsa->sign( Message => $h1, Key => $alicePrivate );

close $ofh;
open( $ofh,                    ">", "testdecrypt.txt" );
open( my $encryptedFileHandle, "<", "testEncrypt.txt" );

#BobActions

#Read Encrypted File.
$line = <$encryptedFileHandle>;

#Decrypt symetric key.
my $decyptedKey =
  $rsa->decrypt( Cyphertext => $encryptedKey, Key => $bobPrivate );

#Create cipher with decrypted key for Bob.
my $bobCipher = Crypt::CBC->new( -key => $decyptedKey );

#Decrypt text sent from alice.
my $decryptedText = $bobCipher->decrypt($line);

#Find MD5 hash
$md5->add($decryptedText);
my $h2 = $md5->digest();

#Two birds with one stone, see if Hash maches the one Alice used to sign and verify signature.
my $h = $rsa->verify(
    Message   => $h2,
    Signature => $aliceSignature,
    Key       => $alicePublic
);

#If the signature/hash mached, say so.
if ( $h == 1 ) {
    print "Hash is good, and Signature matches\n";
}
else {
    print "ermagerd you've been hacked GASP\n";
}
print $ofh $decryptedText;

close $fh;
close $ofh;
close $encryptedFileHandle;
