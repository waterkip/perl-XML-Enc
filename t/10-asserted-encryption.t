use strict;
use warnings;
use Test::More;
use XML::Enc;
use XML::LibXML;
use XML::LibXML::XPathContext;

diag $XML::Enc::VERSION;

my $xml;
{
    open my $fh, '<', 't/asserted-encryption.xml';
    local $/ = undef;
    $xml = <$fh>;
}

my $enc = XML::Enc->new(
    {
        key                 => 't/encrypted-sign-private.pem',
        no_xml_declaration  => 1
    }
);

$xml = XML::LibXML->load_xml(string => $xml);
my $xpc = XML::LibXML::XPathContext->new($xml);
$xpc->registerNs('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
$xpc->registerNs('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
$xpc->registerNs('xenc', 'http://www.w3.org/2001/04/xmlenc#');

my $decrypted = $enc->decrypt($xml);
ok($decrypted, "Got a decrypted message");

diag $decrypted;

$xml = XML::LibXML->load_xml(string => $decrypted);
$xpc = XML::LibXML::XPathContext->new($xml);
$xpc->registerNs('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
$xpc->registerNs('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
$xpc->registerNs('xenc', 'http://www.w3.org/2001/04/xmlenc#');
$xpc->registerNs('dsig', 'http://www.w3.org/2000/09/xmldsig#');

my $assertion = $xpc->findnodes('//saml:Assertion');
is($assertion->size, 1, "Found one assertion node");


#diag explain $xml->toString;

done_testing;
