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
open( STDOUT,  ">", "output.txt" );
open( my $fh,  "<", "PlainText.txt" );
open( my $ofh, ">", "testEncrypt.txt" );

my $encryptedKey;
print "Symmetric Key: " . $symetrickey . "\n";

#Generate Key Pairs for both Bob and Alice.
my ( $alicePublic, $alicePrivate ) = $rsa->keygen( Size => 3072 );

print "Alice private key: " . $alicePrivate . "\n";
print "Alice public key: " . $alicePublic . "\n";

my ( $bobPublic, $bobPrivate ) = $rsa->keygen( Size => 3072 );

print "Bob private key: " . $bobPrivate . "\n";
print "Bob public key: " . $bobPublic . "\n";

#Alice Actions
my $line = <$fh>;

print "Text to encrypt: " . $line . "\n";

#Ecrypt File and write it to file.
my $encryptedText = $aliceCipher->encrypt($line);
print $ofh $encryptedText;

print "Encrypted text: " . $encryptedText . "\n";

#Compute Hash.
$md5->add($line);
my $h1 = $md5->digest();

print "Text hash: " . $h1 . "\n";

#Encrypt symetric key with Bobs Public Key.
$encryptedKey = $rsa->encrypt( Message => $symetrickey, Key => $bobPublic );
print "Encrypted Key: " . $encryptedKey . "\n";

#Sign Hash.
my $aliceSignature = $rsa->sign( Message => $h1, Key => $alicePrivate );
print "Alice signature: " . $aliceSignature . "\n\n";

close $ofh;
open( $ofh,                    ">", "testdecrypt.txt" );
open( my $encryptedFileHandle, "<", "testEncrypt.txt" );

#BobActions
print "Start Bob Actions\n";

#Read Encrypted File.
$line = <$encryptedFileHandle>;
print "Encrypted file: " . $line . "\n";

#Decrypt symetric key.
print "Encrypted key: " . $encryptedKey . "\n";
my $decyptedKey =
  $rsa->decrypt( Cyphertext => $encryptedKey, Key => $bobPrivate );

print "Decrypted Key: " . $decyptedKey . "\n";

#Create cipher with decrypted key for Bob.
my $bobCipher = Crypt::CBC->new( -key => $decyptedKey );

#Decrypt text sent from alice.
my $decryptedText = $bobCipher->decrypt($line);
print "Decrypted text: " . $decryptedText . "\n";

#Find MD5 hash
$md5->add($decryptedText);
my $h2 = $md5->digest();

print "Decrypted file hash: " . $h2 . "\n";

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
    print "Hash or Signature is invalid, please try again.\n";
}
print $ofh $decryptedText;

close $fh;
close $ofh;
close $encryptedFileHandle;
