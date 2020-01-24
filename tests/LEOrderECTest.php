<?php

namespace Zwartpet\PHPCertificateToolbox;

use Zwartpet\PHPCertificateToolbox\Exception\LogicException;
use Zwartpet\PHPCertificateToolbox\Exception\RuntimeException;
use Prophecy\Argument;
use Psr\Log\NullLogger;

class LEOrderECTest extends LETestCase
{
    protected function setUp()
    {
        if (version_compare(PHP_VERSION, '7.1.0') == -1) {
            $this->markTestSkipped('PHP 7.1+ required for EC keys');
        }

        parent::setUp();
    }

    /**
     * @return LEConnector
     */
    private function mockConnector($orderValid = false, $authValid = true, $orderStatus = null)
    {
        if (is_null($orderStatus)) {
            $orderStatus = $orderValid ? 'valid' : 'pending';
        }

        $connector = $this->prophesize(LEConnector::class);
        $connector->newOrder = 'http://test.local/new-order';

        $connector->checkHTTPChallenge(Argument::any(), Argument::any(), Argument::any())
            ->willReturn(true);

        $connector->signRequestKid(Argument::any(), Argument::any(), Argument::any())
            ->willReturn(json_encode(['protected'=>'','payload'=>'','signature'=>'']));

        $neworder=[];
        $neworder['header']='201 Created\r\nLocation: http://test.local/order/test';
        $neworder['body']=json_decode($this->getOrderJSON($orderStatus), true);
        $neworder['status']=201;

        $connector->post('http://test.local/new-order', Argument::any())
            ->willReturn($neworder);

        $authz1=[];
        $authz1['header']='200 OK';
        $authz1['status']=200;
        $authz1['body']=json_decode($this->getAuthzJSON('example.org', $authValid), true);
        $connector->get(
            'https://acme-staging-v02.api.letsencrypt.org/acme/authz/X2QaFXwrBz7VlN6zdKgm_jmiBctwVZgMZXks4YhfPng',
            Argument::any()
        )->willReturn($authz1);

        $authz2=[];
        $authz2['header']='200 OK';
        $authz2['status']=200;
        $authz2['body']=json_decode($this->getAuthzJSON('test.example.org', $authValid), true);
        $connector->get(
            'https://acme-staging-v02.api.letsencrypt.org/acme/authz/WDMI8oX6avFT_rEBfh-ZBMdZs3S-7li2l5gRrps4MXM',
            Argument::any()
        )->willReturn($authz2);

        $orderReq=[];
        $orderReq['header']='200 OK';
        $orderReq['status']=200;
        $orderReq['body']=json_decode($this->getOrderJSON($orderStatus), true);
        $connector->get("http://test.local/order/test")->willReturn($orderReq);

        //simulate challenge URLs
        foreach ($authz1['body']['challenges'] as $challenge) {
            $url=$challenge['url'];
            $connector->post($url, Argument::any())->willReturn(['status'=>200]);
        }
        foreach ($authz2['body']['challenges'] as $challenge) {
            $url=$challenge['url'];
            $connector->post($url, Argument::any())->willReturn(['status'=>200]);
        }


        return $connector->reveal();
    }

    protected function initCertStore() : CertificateStorageInterface
    {
        $keyDir=sys_get_temp_dir().'/le-order-test';
        $this->deleteDirectory($keyDir);

        $store = new FilesystemCertificateStorage($keyDir);
        $this->addAccountKey($store);

        return $store;
    }

    protected function addAccountKey(CertificateStorageInterface $store)
    {
        $public=<<<PUBLIC
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1DSspCkz2MXeM3r0FQaC
egERuedApU6067WSgH9j3vOxV21G6WnTdAu52GkNlRbaT4uQFsbV4w58OZjh5Wln
hb1pYawFwzUmeqgeXLjQFTMEStvAzuBgw3IabC4F6TE812gbJcaiDiQTtP1uH1lv
YwJhc5iaVgpZjNk3aX/E76ngpiORTBtbGTFn7VBSifFgY9OeSgi9moB9NWmmWqPM
8wY+nQhdiXCqPXjuRnqbCO0nXUswp5lfcHG7iR8nTEBK+3P39fRBhZShBPjMpAsX
8RjOQVWvEpQ4Bcxz95Dm02LPN20p6PGtXktj4MsRZEZBb4ENTO+2EVqRdxiZud6x
v81DsHJJqzcm+EVeQQHVagg55wHIWAwt73VQfvAimF7KQpIgT8r85A1CfUyKTUug
nmRz+JaAD3leOo5Ta13/S2zEgEiYAXI24SwviYtPpfpdvzgLk4oPUPUl9lpxW6mz
yDkZh93J0ffpuIyqHrGkA/CUudNo+giqOcxJvkqpKlTdPFsDJhZIYDOmdHeod0pj
eRiaZBvf2VbGvWkkbMTqNMz3q7rKJnnR9riG7a/K6YQqowPAs8v8CnHXBiduZ0jc
xSj9HNwpp5D0Q2eZTd1mmQMIpYnB6DiMKzYMsOpf5inzb0hjMfEe/8bVpmV4xxDD
N9Ff3vjR5jl4+OCLcWwhwv0CAwEAAQ==
-----END PUBLIC KEY-----
PUBLIC;
        $private=<<<PRIVATE
-----BEGIN PRIVATE KEY-----
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
D9sUEJc4jMddoAsQGMEiIrKAttGsm90Q
-----END PRIVATE KEY-----
PRIVATE;

        $store->setAccountPublicKey($public);
        $store->setAccountPrivateKey($private);
    }

    public function testBasicCreateAndReload()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        $this->assertNotEmpty($store->getPublicKey($basename));


        //if we construct again, it should load the existing order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        //it's enough to reach here without getting any exceptions
        $this->assertNotNull($order);
    }

    public function testCreateWithValidatedOrder()
    {
        //our connector will return an order with a certificate url
        $conn = $this->mockConnector(true);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        //and reload the validated order for coverage!
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        //it's enough to reach here without getting any exceptions
        $this->assertNotNull($order);
    }


    public function testCreateWithInvalidOrder()
    {
        //our connector will return an order with a certificate url
        $conn = $this->mockConnector(true);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        //now we want to load the same order, but we're goign to make it invalid
        $conn = $this->mockConnector(true, true, 'invalid');

        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        //it's enough to reach here without getting any exceptions - we could do with a better mock for this
        //test as the invalid order will get replaced with a fresh one (but also invalid!)
        $this->assertNotNull($order);
    }



    public function testHttpAuthorizations()
    {
        //our connector will return an order with a certificate url
        $conn = $this->mockConnector(true, false);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();

        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        //we expect to find some pending http authorizations
        $pending = $order->getPendingAuthorizations(LEOrder::CHALLENGE_TYPE_HTTP);
        $this->assertCount(2, $pending);

        //let's try and verify!
        //TODO - we need a more sophisticated mock here to return a valid challenge
        //$order->verifyPendingOrderAuthorization($basename, LEOrder::CHALLENGE_TYPE_HTTP);
    }


    public function testMismatchedReload()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        $this->assertNotEmpty($store->getPublicKey($basename));

        //we construct again to get a reload, but with different domains
        $domains = ['example.com', 'test.example.com'];
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        //this is allowed - we will just create a new order for the given domains, so it's enough to reach
        //here without exception
        $this->assertNotNull($order);
    }


    /**
     * @expectedException LogicException
     */
    public function testCreateWithBadWildcard()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['*.*.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);
    }

    /**
     * @expectedException LogicException
     */
    public function testCreateWithBadKeyType()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org'];
        $keyType = 'wibble-4096';
        $notBefore = '';
        $notAfter = '';

        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);
    }

    /**
     * @expectedException LogicException
     */
    public function testCreateWithBadDates()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org'];
        $keyType = 'ec';
        $notBefore = 'Hippopotamus';
        $notAfter = 'Primrose';

        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);
    }

    /**
     * @return LEConnector
     */
    private function mockConnectorWithNoAuths($valid = false)
    {
        $connector = $this->prophesize(LEConnector::class);
        $connector->newOrder = 'http://test.local/new-order';

        $connector->signRequestKid(Argument::any(), Argument::any(), Argument::any())
            ->willReturn(json_encode(['protected'=>'','payload'=>'','signature'=>'']));

        $order = json_decode($this->getOrderJSON($valid?'valid':'pending'), true);
        $order['authorizations'] = [];

        $neworder=[];
        $neworder['header']='201 Created\r\nLocation: http://test.local/order/test';
        $neworder['status']=201;
        $neworder['body']=$order;

        $connector->post('http://test.local/new-order', Argument::any())
            ->willReturn($neworder);

        $orderReq=[];
        $orderReq['header']='200 OK';
        $orderReq['status']=200;
        $orderReq['body']=$order;

        $connector->get("http://test.local/order/test")->willReturn($orderReq);

        return $connector->reveal();
    }

    /**
     * Covers the case where there are no authorizations in the order
     */
    public function testAllAuthorizationsValid()
    {
        $conn = $this->mockConnectorWithNoAuths();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        $this->assertFalse($order->allAuthorizationsValid());
    }

    /**
     * @return LEConnector
     */
    private function mockConnectorForProcessingCert($eventuallyValid = true, $goodCertRequest = true, $garbage = false)
    {
        $valid = true;

        $connector = $this->prophesize(LEConnector::class);
        $connector->newOrder = 'http://test.local/new-order';
        $connector->revokeCert = 'http://test.local/revoke-cert';

        $connector->signRequestKid(Argument::any(), Argument::any(), Argument::any())
            ->willReturn(json_encode(['protected'=>'','payload'=>'','signature'=>'']));

        $connector->signRequestJWK(Argument::any(), Argument::any(), Argument::any())
            ->willReturn(json_encode(['protected'=>'','payload'=>'','signature'=>'']));


        //the new order is setup to be processing...
        $neworder=[];
        $neworder['header']='201 Created\r\nLocation: http://test.local/order/test';
        $neworder['status']=201;
        $neworder['body']=json_decode($this->getOrderJSON('valid'), true);
        $neworder['body']['status'] = 'processing';

        $connector->post('http://test.local/new-order', Argument::any())
            ->willReturn($neworder);

        $authz1=[];
        $authz1['header']='200 OK';
        $authz1['status']=200;
        $authz1['body']=json_decode($this->getAuthzJSON('example.org', $valid), true);
        $connector->get(
            'https://acme-staging-v02.api.letsencrypt.org/acme/authz/X2QaFXwrBz7VlN6zdKgm_jmiBctwVZgMZXks4YhfPng',
            Argument::any()
        )->willReturn($authz1);

        $authz2=[];
        $authz2['header']='200 OK';
        $authz2['status']=200;
        $authz2['body']=json_decode($this->getAuthzJSON('test.example.org', $valid), true);
        $connector->get(
            'https://acme-staging-v02.api.letsencrypt.org/acme/authz/WDMI8oX6avFT_rEBfh-ZBMdZs3S-7li2l5gRrps4MXM',
            Argument::any()
        )->willReturn($authz2);

        //when the order is re-fetched, it's possibly valid
        $orderReq=[];
        $orderReq['header']='200 OK';
        $orderReq['status']=200;
        $orderReq['body']=json_decode($this->getOrderJSON('valid'), true);
        if (!$eventuallyValid) {
            $orderReq['body']['status'] = 'processing';
        }
        $connector->get('http://test.local/order/test')->willReturn($orderReq);

        $certReq=[];
        $certReq['header']=$goodCertRequest ? '200 OK' : '500 Failed';
        $certReq['status']=200;
        $certReq['body']=$garbage ? 'NOT-A-CERT' : $this->getCertBody();
        $connector->get('https://acme-staging-v02.api.letsencrypt.org/acme/cert/fae09c6dcdaf7aa198092b3170c69129a490')
            ->willReturn($certReq);

        $revokeReq=[];
        $revokeReq['header']='200 OK';
        $revokeReq['status']=200;
        $revokeReq['body']='';
        $connector->post('http://test.local/revoke-cert', Argument::any())
            ->willReturn($revokeReq);

        $connector->post('http://test.local/bad-revoke-cert', Argument::any())
            ->willThrow(new RuntimeException('Revocation failed'));

        return $connector->reveal();
    }

    /**
     * Test a certificate fetch with a 'processing' loop in effect
     */
    public function testGetCertificate()
    {

        $conn = $this->mockConnectorForProcessingCert(true);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        $this->assertEmpty($store->getCertificate($basename));

        $ok = $order->getCertificate();
        $this->assertTrue($ok);
        $this->assertNotEmpty($store->getCertificate($basename));
    }

    /**
     * Test a certificate fetch with a 'processing' loop in effect
     */
    public function testGetCertificateWithValidationDelay()
    {
        $conn = $this->mockConnectorForProcessingCert(false);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        $ok = $order->getCertificate();
        $this->assertFalse($ok);
    }

    public function testGetCertificateWithRetrievalFailure()
    {
        $conn = $this->mockConnectorForProcessingCert(true, false);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        $ok = $order->getCertificate();
        $this->assertFalse($ok);
    }

    public function testGetCertificateWithGarbageRetrieval()
    {
        $conn = $this->mockConnectorForProcessingCert(true, true, true);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        $ok = $order->getCertificate();
        $this->assertFalse($ok);
    }

    public function testRevoke()
    {
        $conn = $this->mockConnectorForProcessingCert(true);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);
        $this->assertTrue($order->getCertificate());

        $ok = $order->revokeCertificate();
        $this->assertTrue($ok);
    }

    public function testRevokeIncompleteOrder()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        $this->assertNotEmpty($store->getPublicKey($basename));

        //can't revoke
        $ok = $order->revokeCertificate();
        $this->assertFalse($ok);
    }

    public function testRevokeMissingCertificate()
    {
        $conn = $this->mockConnectorForProcessingCert(true);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);
        $this->assertTrue($order->getCertificate());

        //now we're going to remove the cert
        $this->assertNotEmpty($store->getCertificate($basename));
        $store->setCertificate($basename, null);

        $ok = $order->revokeCertificate();
        $this->assertFalse($ok);
    }

    /**
     * @expectedException RuntimeException
     */
    public function testRevokeFailure()
    {
        $conn = $this->mockConnectorForProcessingCert(true);

        //we use an alternate URL for revocation which fails with a 403
        $conn->revokeCert = 'http://test.local/bad-revoke-cert';

        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $store = $this->initCertStore();

        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertNull($store->getPublicKey($basename));

        //this should create a new order
        $order = new LEOrder($conn, $store, $log, $dns, $sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);
        $this->assertTrue($order->getCertificate());

        //this should fail as we use a revocation url which simulates failure
        $order->revokeCertificate();
    }
}
