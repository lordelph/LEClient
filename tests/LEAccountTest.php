<?php

namespace Zwartpet\PHPCertificateToolbox;

use Zwartpet\PHPCertificateToolbox\Exception\RuntimeException;
use Prophecy\Argument;
use Psr\Log\NullLogger;

/**
 * Tests LEAccount - because this was retrofitted to a class not really designed for testing, this
 * is a litle scrappy at present...
 *
 * @package Zwartpet\PHPCertificateToolbox
 */
class LEAccountTest extends LETestCase
{
    /**
     * @return LEConnector
     */
    private function mockConnector()
    {
        $connector = $this->prophesize(LEConnector::class);
        $connector->newAccount = 'http://test.local/new-account';
        $connector->keyChange = 'http://test.local/change-key';

        $connector->signRequestKid(Argument::any(), Argument::any(), Argument::any())
            ->willReturn(json_encode(['protected'=>'','payload'=>'','signature'=>'']));
        $connector->signRequestJWK(Argument::any(), Argument::any(), Argument::any())
            ->willReturn(json_encode(['protected'=>'','payload'=>'','signature'=>'']));

        $accountUrl='https://acme-staging-v02.api.letsencrypt.org/acme/acct/5757881';
        $newaccount=[];
        $newaccount['header']='201 Created\r\nLocation: '.$accountUrl;
        $newaccount['body']=json_decode($this->postNewAccountJSON(), true);
        $newaccount['status']=201;

        $connector->post('http://test.local/new-account', Argument::any())
            ->willReturn($newaccount);

        $account=$newaccount;
        $account['header']='200 OK\r\nLocation: '.$accountUrl;
        $account['status']=200;
        $connector->post($accountUrl, Argument::any())
            ->willReturn($account);

        $connector->post('http://test.local/new-account2', Argument::any())
            ->willReturn($account);

        $account['header']='404 Not Found';
        $account['status']=404;
        $connector->post('http://test.local/new-account3', Argument::any())
            ->willReturn($account);

        $account=$newaccount;
        $account['header']='200 OK\r\n';
        $account['status']=200;
        $connector->post($connector->keyChange, Argument::any())
            ->willReturn($account);

        return $connector->reveal();
    }

    protected function initCertStorage()
    {
        $keyDir=sys_get_temp_dir().'/le-acc-test';
        $this->deleteDirectory($keyDir);
        $store = new FilesystemCertificateStorage($keyDir);
        return $store;
    }

    public function testBasicCreateAndReload()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $store = $this->initCertStorage();

        //at first, should not exist
        $this->assertNull($store->getAccountPrivateKey());
        $this->assertNull($store->getAccountPublicKey());

        new LEAccount($conn, $log, ['test@example.org'], $store);

        $this->assertNotEmpty($store->getAccountPrivateKey());
        $this->assertNotEmpty($store->getAccountPublicKey());

        //reload for coverage...we need to fudge the mock connection a little
        $conn->newAccount = 'http://test.local/new-account2';

        new LEAccount($conn, $log, ['test@example.org'], $store);

        //it's enough to reach here without exception
        $this->assertTrue(true);
    }

    /**
     * @expectedException RuntimeException
     */
    public function testNotFound()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $store = $this->initCertStorage();

        //at first, should not exist
        $this->assertNull($store->getAccountPrivateKey());
        $this->assertNull($store->getAccountPublicKey());

        new LEAccount($conn, $log, ['test@example.org'], $store);

        $this->assertNotEmpty($store->getAccountPrivateKey());
        $this->assertNotEmpty($store->getAccountPublicKey());


        //when we reload, we fudge things to get a 404
        $conn->newAccount = 'http://test.local/new-account3';

        new LEAccount($conn, $log, ['test@example.org'], $store);
    }

    public function testUpdateAccount()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $store = $this->initCertStorage();

        $account = new LEAccount($conn, $log, ['test@example.org'], $store);

        $ok = $account->updateAccount(['new@example.org']);
        $this->assertTrue($ok);
    }

    public function testChangeKeys()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $store = $this->initCertStorage();

        $account = new LEAccount($conn, $log, ['test@example.org'], $store);

        $ok = $account->changeAccountKeys();
        $this->assertTrue($ok);
    }

    public function testDeactivate()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $store = $this->initCertStorage();

        $account = new LEAccount($conn, $log, ['test@example.org'], $store);

        $ok = $account->deactivateAccount();
        $this->assertTrue($ok);
    }
}
