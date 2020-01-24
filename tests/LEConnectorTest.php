<?php

namespace Zwartpet\PHPCertificateToolbox;

use Zwartpet\PHPCertificateToolbox\Exception\LogicException;
use Zwartpet\PHPCertificateToolbox\Exception\RuntimeException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;

class LEConnectorTest extends LETestCase
{
    private function prepareKeysStorage($subdir = 'le-client-test') : CertificateStorageInterface
    {
        $keys=sys_get_temp_dir().'/'.$subdir;
        $this->deleteDirectory($keys);
        return new FilesystemCertificateStorage($keys);
    }

    public function testConstructor()
    {
        $logger=new DiagnosticLogger();

        // when the LEConnector is constructed, it requests the directory and get a new nonce, so
        // we set that up here
        $mock = new MockHandler([
            $this->getDirectoryResponse(),
            $this->headNewNonceResponse(),
            new RequestException("Unexpected request", new Request('GET', 'test'))
        ]);

        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);
        $store = $this->prepareKeysStorage();

        $connector = new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $store);

        //it's enough to reach here without getting any exceptions
        $this->assertNotNull($connector);
    }


    /**
     * @expectedException RuntimeException
     */
    public function testBadRequest()
    {
        $logger=new DiagnosticLogger();

        // when the LEConnector is constructed, it requests the directory and get a new nonce, so
        // we set that up here
        $mock = new MockHandler([
            $this->getMissingResponse(),
            new RequestException("Unexpected request", new Request('GET', 'test'))
        ]);

        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);
        $store = $this->prepareKeysStorage();

        new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $store);
    }

    /**
     * @expectedException LogicException
     */
    public function testDeactivated()
    {
        $logger=new DiagnosticLogger();

        // when the LEConnector is constructed, it requests the directory and get a new nonce, so
        // we set that up here
        $mock = new MockHandler([
            $this->getDirectoryResponse(),
            $this->headNewNonceResponse(),
            new RequestException("Unexpected request", new Request('GET', 'test'))
        ]);

        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);
        $store = $this->prepareKeysStorage();


        $connector = new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $store);

        //deactivation isn't persisted, its just a flag to prevent further API calls in the same session
        $connector->accountDeactivated = true;

        $connector->get("https://acme-staging-v02.api.letsencrypt.org/acme/new-acct");
    }

    /**
     * Just for coverage, this checks that if guzzle throws some kind of internal failure, we
     * in turn throw a RuntimeException
     * @expectedException RuntimeException
     */
    public function testGuzzleException()
    {
        $logger=new DiagnosticLogger();
        $mock = new MockHandler([
            new TransferException("Guzzle failure")
        ]);

        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);
        $store = $this->prepareKeysStorage();


        new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $store);
    }

    public function testSignRequestJWK()
    {
        $logger=new DiagnosticLogger();

        // when the LEConnector is constructed, it requests the directory and get a new nonce, so
        // we set that up here
        $mock = new MockHandler([
            $this->getDirectoryResponse(),
            $this->headNewNonceResponse(),
            new RequestException("Unexpected request", new Request('GET', 'test'))
        ]);

        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);
        $store = $this->prepareKeysStorage();

        //build some keys
        $accKeys = LEFunctions::RSAgenerateKeys(2048);
        $store->setAccountPrivateKey($accKeys['private']);
        $store->setAccountPublicKey($accKeys['public']);

        $connector = new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $store);

        $json = $connector->signRequestJWK(['test'=>'foo'], 'http://example.org');
        $data = json_decode($json, true);
        $this->assertArrayHasKey('protected', $data);
        $this->assertArrayHasKey('payload', $data);
        $this->assertArrayHasKey('signature', $data);
    }

    public function testSignRequestKid()
    {
        $logger=new DiagnosticLogger();

        // when the LEConnector is constructed, it requests the directory and get a new nonce, so
        // we set that up here
        $mock = new MockHandler([
            $this->getDirectoryResponse(),
            $this->headNewNonceResponse(),
            new RequestException("Unexpected request", new Request('GET', 'test'))
        ]);

        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);
        $store = $this->prepareKeysStorage();

        //build some keys
        $accKeys = LEFunctions::RSAgenerateKeys(2048);
        $store->setAccountPrivateKey($accKeys['private']);
        $store->setAccountPublicKey($accKeys['public']);

        $connector = new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $store);

        $json = $connector->signRequestKid(['test'=>'foo'], '1234', 'http://example.org');
        $data = json_decode($json, true);
        $this->assertArrayHasKey('protected', $data);
        $this->assertArrayHasKey('payload', $data);
        $this->assertArrayHasKey('signature', $data);
    }
}
