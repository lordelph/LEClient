<?php

namespace Zwartpet\PHPCertificateToolbox;

use Zwartpet\PHPCertificateToolbox\DNSValidator\DNSOverHTTPS;
use PHPUnit\Framework\TestCase;

/**
 * This is an integration test with external dependancies and will be excluded from the usual
 * continuous integration tests
 *
 * @group integration
 */
class DNSOverHTTPSTest extends TestCase
{
    public function testGetGoogle()
    {
        $client = new DNSOverHTTPS(DNSOverHTTPS::DNS_GOOGLE);
        $output = $client->get('example.com', 1);
        $this->assertEquals(0, $output->Status);
    }

    public function testGetMozilla()
    {
        $client = new DNSOverHTTPS(DNSOverHTTPS::DNS_MOZILLA);
        $output = $client->get('example.com', 1);
        $this->assertEquals(0, $output->Status);
    }

    public function testGetCloudflare()
    {
        $client = new DNSOverHTTPS(DNSOverHTTPS::DNS_CLOUDFLARE);
        $output = $client->get('example.com', 1);
        $this->assertEquals(0, $output->Status);
    }
}
