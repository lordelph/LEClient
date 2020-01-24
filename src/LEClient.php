<?php

namespace Zwartpet\PHPCertificateToolbox;

use Zwartpet\PHPCertificateToolbox\DNSValidator\DNSOverHTTPS;
use Zwartpet\PHPCertificateToolbox\DNSValidator\DNSValidatorInterface;
use Zwartpet\PHPCertificateToolbox\DNSValidator\NativeDNS;
use Zwartpet\PHPCertificateToolbox\Exception\LogicException;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Main LetsEncrypt Client class, works as a framework for the LEConnector, LEAccount, LEOrder and
 * LEAuthorization classes.
 *
 * @author     Youri van Weegberg <youri@yourivw.nl>
 * @copyright  2018 Youri van Weegberg
 * @license    https://opensource.org/licenses/mit-license.php  MIT License
 */
class LEClient
{
    const LE_PRODUCTION = 'https://acme-v02.api.letsencrypt.org';
    const LE_STAGING = 'https://acme-staging-v02.api.letsencrypt.org';

    /** @var LEConnector */
    private $connector;

    /** @var LEAccount */
    private $account;

    private $baseURL;

    /** @var LoggerInterface */
    private $log;

    /** @var ClientInterface */
    private $httpClient;

    /** @var DNSValidatorInterface */
    private $dns;

    /** @var Sleep */
    private $sleep;

    /** @var CertificateStorageInterface */
    private $storage;


    private $email;

    /**
     * Initiates the LetsEncrypt main client.
     *
     * @param array $email The array of strings containing e-mail addresses. Only used in this function when
     *                                creating a new account.
     * @param string|bool $acmeURL ACME URL, can be string or one of predefined values: LE_STAGING or LE_PRODUCTION.
     *                                Defaults to LE_STAGING. Can also pass true/false for staging/production
     * @param LoggerInterface $logger PSR-3 compatible logger
     * @param ClientInterface|null $httpClient you can pass a custom client used for HTTP requests, if null is passed
     *                                one will be created
     * @param CertificateStorageInterface|null $storage service for certificates. If not supplied, a default
     *                                storage object will retain certificates in the local filesystem in a directory
     *                                called certificates in the current working directory
     * @param DNSValidatorInterface|null $dnsValidator service for checking DNS challenges. By default, this will use
     *                                Google's DNS over HTTPs service, which should insulate you from cached entries,
     *                                but this can be swapped for 'NativeDNS' or other alternative implementation
     */
    public function __construct(
        $email,
        $acmeURL = LEClient::LE_STAGING,
        LoggerInterface $logger = null,
        ClientInterface $httpClient = null,
        CertificateStorageInterface $storage = null,
        DNSValidatorInterface $dnsValidator = null
    ) {
        $this->log = $logger ?? new NullLogger();

        $this->initBaseUrl($acmeURL);

        $this->httpClient = $httpClient ?? new Client();

        $this->storage = $storage ?? new FilesystemCertificateStorage();
        $this->dns = $dnsValidator ?? new DNSOverHTTPS();
        $this->sleep = new Sleep;
        $this->email = $email;
    }

    private function initBaseUrl($acmeURL)
    {
        if (is_bool($acmeURL)) {
            $this->baseURL = $acmeURL ? LEClient::LE_STAGING : LEClient::LE_PRODUCTION;
        } elseif (is_string($acmeURL)) {
            $this->baseURL = $acmeURL;
        } else {
            throw new LogicException('acmeURL must be set to string or bool (legacy)');
        }
    }

    public function getBaseUrl()
    {
        return $this->baseURL;
    }

    /**
     * Inject alternative DNS resolver for testing
     * @param DNSValidatorInterface $dns
     */
    public function setDNS(DNSValidatorInterface $dns)
    {
        $this->dns = $dns;
    }

    /**
     * Inject alternative sleep service for testing
     * @param Sleep $sleep
     */
    public function setSleep(Sleep $sleep)
    {
        $this->sleep = $sleep;
    }

    private function getConnector()
    {
        if (!isset($this->connector)) {
            $this->connector = new LEConnector($this->log, $this->httpClient, $this->baseURL, $this->storage);

            //we need to initialize an account before using the connector
            $this->getAccount();
        }

        return $this->connector;
    }

    /**
     * Returns the LetsEncrypt account used in the current client.
     *
     * @return LEAccount    The LetsEncrypt Account instance used by the client.
     */
    public function getAccount()
    {
        if (!isset($this->account)) {
            $this->account = new LEAccount($this->getConnector(), $this->log, $this->email, $this->storage);
        }
        return $this->account;
    }

    /**
     * Returns a LetsEncrypt order. If an order exists, this one is returned. If not, a new order is created and
     * returned.
     *
     * @param string $basename The base name for the order. Preferable the top domain (example.org). Will be the
     *                          directory in which the keys are stored. Used for the CommonName in the certificate as
     *                          well.
     * @param array $domains The array of strings containing the domain names on the certificate.
     * @param string $keyType Type of the key we want to use for certificate. Can be provided in ALGO-SIZE format
     *                          (ex. rsa-4096 or ec-256) or simple "rsa" and "ec" (using default sizes)
     * @param string $notBefore A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) at which the
     *                          certificate becomes valid. Defaults to the moment the order is finalized. (optional)
     * @param string $notAfter A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) until which the
     *                          certificate is valid. Defaults to 90 days past the moment the order is finalized.
     *                          (optional)
     *
     * @return LEOrder  The LetsEncrypt Order instance which is either retrieved or created.
     */
    public function getOrCreateOrder($basename, $domains, $keyType = 'rsa-4096', $notBefore = '', $notAfter = '')
    {
        $this->log->info("LEClient::getOrCreateOrder($basename,...)");

        $order = new LEOrder($this->getConnector(), $this->storage, $this->log, $this->dns, $this->sleep);
        $order->loadOrder($basename, $domains, $keyType, $notBefore, $notAfter);

        return $order;
    }
}
