<?php

namespace Zwartpet\PHPCertificateToolbox;

use Zwartpet\PHPCertificateToolbox\DNSValidator\DNSValidatorInterface;
use Zwartpet\PHPCertificateToolbox\Exception\LogicException;
use Zwartpet\PHPCertificateToolbox\Exception\RuntimeException;
use Psr\Log\LoggerInterface;

/**
 * LetsEncrypt Order class, containing the functions and data associated with a specific LetsEncrypt order.
 *
 * @author     Youri van Weegberg <youri@yourivw.nl>
 * @copyright  2018 Youri van Weegberg
 * @license    https://opensource.org/licenses/mit-license.php  MIT License
 */
class LEOrder
{
    const CHALLENGE_TYPE_HTTP = 'http-01';
    const CHALLENGE_TYPE_DNS = 'dns-01';

    /** @var string order status (pending, processing, valid) */
    private $status;

    /** @var string expiration date for order */
    private $expires;

    /** @var array containing all the domain identifiers for the order */
    private $identifiers;

    /** @var string[] URLs to all the authorization objects for this order */
    private $authorizationURLs;

    /** @var LEAuthorization[] array of authorization objects for the order */
    private $authorizations;

    /** @var string URL for order finalization */
    private $finalizeURL;

    /** @var string URL for obtaining certificate */
    private $certificateURL;

    /** @var string base domain name for certificate */
    private $basename;

    /** @var string URL referencing order */
    private $orderURL;

    /** @var string type of key (rsa or ec) */
    private $keyType;

    /** @var int size of key (typically 2048 or 4096 for rsa, 256 or 384 for ec */
    private $keySize;

    /** @var LEConnector ACME API connection provided to constructor */
    private $connector;

    /** @var LoggerInterface logger provided to constructor */
    private $log;

    /** @var DNSValidatorInterface dns resolution provider to constructor*/
    private $dns;

    /** @var Sleep sleep service provided to constructor */
    private $sleep;

    /** @var CertificateStorageInterface storage interface provided to constructor */
    private $storage;

    /**
     * Initiates the LetsEncrypt Order class. If the base name is found in the $keysDir directory, the order data is
     * requested. If no order was found locally, if the request is invalid or when there is a change in domain names, a
     * new order is created.
     *
     * @param LEConnector $connector The LetsEncrypt Connector instance to use for HTTP requests.
     * @param CertificateStorageInterface $storage
     * @param LoggerInterface $log PSR-3 compatible logger
     * @param DNSValidatorInterface $dns DNS challenge checking service
     * @param Sleep $sleep Sleep service for polling
     */
    public function __construct(
        LEConnector $connector,
        CertificateStorageInterface $storage,
        LoggerInterface $log,
        DNSValidatorInterface $dns,
        Sleep $sleep
    ) {

        $this->connector = $connector;
        $this->log = $log;
        $this->dns = $dns;
        $this->sleep = $sleep;
        $this->storage = $storage;
    }

    /**
     * Loads or updates an order. If the base name is found in the $keysDir directory, the order data is
     * requested. If no order was found locally, if the request is invalid or when there is a change in domain names, a
     * new order is created.
     *
     * @param string $basename The base name for the order. Preferable the top domain (example.org).
     *                                         Will be the directory in which the keys are stored. Used for the
     *                                         CommonName in the certificate as well.
     * @param array $domains The array of strings containing the domain names on the certificate.
     * @param string $keyType Type of the key we want to use for certificate. Can be provided in
     *                                         ALGO-SIZE format (ex. rsa-4096 or ec-256) or simply "rsa" and "ec"
     *                                         (using default sizes)
     * @param string $notBefore A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss)
     *                                         at which the certificate becomes valid.
     * @param string $notAfter A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss)
     *                                         until which the certificate is valid.
     */
    public function loadOrder($basename, array $domains, $keyType, $notBefore, $notAfter)
    {
        $this->basename = $basename;

        $this->initialiseKeyTypeAndSize($keyType ?? 'rsa-4096');

        if ($this->loadExistingOrder($domains)) {
            $this->updateAuthorizations();
        } else {
            $this->createOrder($domains, $notBefore, $notAfter);
        }
    }

    private function loadExistingOrder($domains)
    {
        $orderUrl = $this->storage->getMetadata($this->basename.'.order.url');
        $publicKey = $this->storage->getPublicKey($this->basename);
        $privateKey = $this->storage->getPrivateKey($this->basename);

        //anything to load?
        if (empty($orderUrl) || empty($publicKey) || empty($privateKey)) {
            $this->log->info("No order found for {$this->basename}. Creating new order.");
            return false;
        }

        //valid URL?
        $this->orderURL = $orderUrl;
        if (!filter_var($this->orderURL, FILTER_VALIDATE_URL)) {
            //@codeCoverageIgnoreStart
            $this->log->warning("Order for {$this->basename} has invalid URL. Creating new order.");
            $this->deleteOrderFiles();
            return false;
            //@codeCoverageIgnoreEnd
        }

        //retrieve the order
        $get = $this->connector->get($this->orderURL);
        if ($get['status'] !== 200) {
            //@codeCoverageIgnoreStart
            $this->log->warning("Order for {$this->basename} could not be loaded. Creating new order.");
            $this->deleteOrderFiles();
            return false;
            //@codeCoverageIgnoreEnd
        }

        //ensure the order is still valid
        if ($get['body']['status'] === 'invalid') {
            $this->log->warning("Order for {$this->basename} is 'invalid', unable to authorize. Creating new order.");
            $this->deleteOrderFiles();
            return false;
        }

        //ensure retrieved order matches our domains
        $orderdomains = array_map(function ($ident) {
            return $ident['value'];
        }, $get['body']['identifiers']);
        $diff = array_merge(array_diff($orderdomains, $domains), array_diff($domains, $orderdomains));
        if (!empty($diff)) {
            $this->log->warning('Domains do not match order data. Deleting and creating new order.');
            $this->deleteOrderFiles();
            return false;
        }

        //the order is good
        $this->status = $get['body']['status'];
        $this->expires = $get['body']['expires'];
        $this->identifiers = $get['body']['identifiers'];
        $this->authorizationURLs = $get['body']['authorizations'];
        $this->finalizeURL = $get['body']['finalize'];
        if (array_key_exists('certificate', $get['body'])) {
            $this->certificateURL = $get['body']['certificate'];
        }

        return true;
    }

    private function deleteOrderFiles()
    {
        $this->storage->setPrivateKey($this->basename, null);
        $this->storage->setPublicKey($this->basename, null);
        $this->storage->setCertificate($this->basename, null);
        $this->storage->setFullChainCertificate($this->basename, null);
        $this->storage->setMetadata($this->basename.'.order.url', null);
    }

    private function initialiseKeyTypeAndSize($keyType)
    {
        if ($keyType == 'rsa') {
            $this->keyType = 'rsa';
            $this->keySize = 4096;
        } elseif ($keyType == 'ec') {
            $this->keyType = 'ec';
            $this->keySize = 256;
        } else {
            preg_match_all('/^(rsa|ec)\-([0-9]{3,4})$/', $keyType, $keyTypeParts, PREG_SET_ORDER, 0);

            if (!empty($keyTypeParts)) {
                $this->keyType = $keyTypeParts[0][1];
                $this->keySize = intval($keyTypeParts[0][2]);
            } else {
                throw new LogicException('Key type \'' . $keyType . '\' not supported.');
            }
        }
    }

    /**
     * Creates a new LetsEncrypt order and fills this instance with its data. Subsequently creates a new RSA keypair
     * for the certificate.
     *
     * @param array $domains The array of strings containing the domain names on the certificate.
     * @param string $notBefore A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss)
     *                          at which the certificate becomes valid.
     * @param string $notAfter A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss)
     *                          until which the certificate is valid.
     */
    private function createOrder($domains, $notBefore, $notAfter)
    {
        if (!preg_match('~(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z|^$)~', $notBefore) ||
            !preg_match('~(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z|^$)~', $notAfter)
        ) {
            throw new LogicException("notBefore and notAfter must be blank or iso-8601 datestamp");
        }

        $dns = [];
        foreach ($domains as $domain) {
            if (preg_match_all('~(\*\.)~', $domain) > 1) {
                throw new LogicException('Cannot create orders with multiple wildcards in one domain.');
            }
            $dns[] = ['type' => 'dns', 'value' => $domain];
        }
        $payload = ["identifiers" => $dns, 'notBefore' => $notBefore, 'notAfter' => $notAfter];
        $sign = $this->connector->signRequestKid(
            $payload,
            $this->connector->accountURL,
            $this->connector->newOrder
        );
        $post = $this->connector->post($this->connector->newOrder, $sign);
        if ($post['status'] !== 201) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('Creating new order failed.');
            //@codeCoverageIgnoreEnd
        }

        if (!preg_match('~Location: (\S+)~i', $post['header'], $matches)) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('New-order returned invalid response.');
            //@codeCoverageIgnoreEnd
        }

        $this->orderURL = trim($matches[1]);
        $this->storage->setMetadata($this->basename.'.order.url', $this->orderURL);

        $this->generateKeys();

        $this->status = $post['body']['status'];
        $this->expires = $post['body']['expires'];
        $this->identifiers = $post['body']['identifiers'];
        $this->authorizationURLs = $post['body']['authorizations'];
        $this->finalizeURL = $post['body']['finalize'];
        if (array_key_exists('certificate', $post['body'])) {
            $this->certificateURL = $post['body']['certificate'];
        }
        $this->updateAuthorizations();

        $this->log->info('Created order for ' . $this->basename);
    }

    private function generateKeys()
    {
        if ($this->keyType == "rsa") {
            $key = LEFunctions::RSAgenerateKeys($this->keySize);
        } else {
            $key = LEFunctions::ECgenerateKeys($this->keySize);
        }

        $this->storage->setPublicKey($this->basename, $key['public']);
        $this->storage->setPrivateKey($this->basename, $key['private']);
    }

    /**
     * Fetches the latest data concerning this LetsEncrypt Order instance and fills this instance with the new data.
     */
    private function updateOrderData()
    {
        $get = $this->connector->get($this->orderURL);
        if (strpos($get['header'], "200 OK") !== false) {
            $this->status = $get['body']['status'];
            $this->expires = $get['body']['expires'];
            $this->identifiers = $get['body']['identifiers'];
            $this->authorizationURLs = $get['body']['authorizations'];
            $this->finalizeURL = $get['body']['finalize'];
            if (array_key_exists('certificate', $get['body'])) {
                $this->certificateURL = $get['body']['certificate'];
            }
            $this->updateAuthorizations();
        } else {
            //@codeCoverageIgnoreStart
            $this->log->error("Failed to fetch order for {$this->basename}");
            //@codeCoverageIgnoreEnd
        }
    }

    /**
     * Fetches the latest data concerning all authorizations connected to this LetsEncrypt Order instance and
     * creates and stores a new LetsEncrypt Authorization instance for each one.
     */
    private function updateAuthorizations()
    {
        $this->authorizations = [];
        foreach ($this->authorizationURLs as $authURL) {
            if (filter_var($authURL, FILTER_VALIDATE_URL)) {
                $auth = new LEAuthorization($this->connector, $this->log, $authURL);
                if ($auth != false) {
                    $this->authorizations[] = $auth;
                }
            }
        }
    }

    /**
     * Walks all LetsEncrypt Authorization instances and returns whether they are all valid (verified).
     *
     * @return boolean  Returns true if all authorizations are valid (verified), returns false if not.
     */
    public function allAuthorizationsValid()
    {
        if (count($this->authorizations) > 0) {
            foreach ($this->authorizations as $auth) {
                if ($auth->status != 'valid') {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    private function loadAccountKey()
    {
        $keydata = $this->storage->getAccountPrivateKey();
        $privateKey = openssl_pkey_get_private($keydata);
        if ($privateKey === false) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException("Failed load account key");
            //@codeCoverageIgnoreEnd
        }
        return $privateKey;
    }


    private function loadCertificateKey()
    {
        $keydata = $this->storage->getPrivateKey($this->basename);
        $privateKey = openssl_pkey_get_private($keydata);
        if ($privateKey === false) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException("Failed load certificate key");
            //@codeCoverageIgnoreEnd
        }
        return $privateKey;
    }

    /**
     * Get all pending LetsEncrypt Authorization instances and return the necessary data for verification.
     * The data in the return object depends on the $type.
     *
     * @param string $type The type of verification to get. Supporting http-01 and dns-01.
     *                     Supporting LEOrder::CHALLENGE_TYPE_HTTP and LEOrder::CHALLENGE_TYPE_DNS. Throws a Runtime
     *                     Exception when requesting an unknown $type. Keep in mind a wildcard domain authorization only
     *                     accepts LEOrder::CHALLENGE_TYPE_DNS.
     *
     * @return array|bool Returns an array with verification data if successful, false if not pending LetsEncrypt
     *                  Authorization instances were found. The return array always
     *                  contains 'type' and 'identifier'. For LEOrder::CHALLENGE_TYPE_HTTP, the array contains
     *                  'filename' and 'content' for necessary the authorization file.
     *                  For LEOrder::CHALLENGE_TYPE_DNS, the array contains 'DNSDigest', which is the content for the
     *                  necessary DNS TXT entry.
     */

    public function getPendingAuthorizations($type)
    {
        $authorizations = [];

        $privateKey = $this->loadAccountKey();
        $details = openssl_pkey_get_details($privateKey);

        $header = [
            "e" => LEFunctions::base64UrlSafeEncode($details["rsa"]["e"]),
            "kty" => "RSA",
            "n" => LEFunctions::base64UrlSafeEncode($details["rsa"]["n"])

        ];
        $digest = LEFunctions::base64UrlSafeEncode(hash('sha256', json_encode($header), true));

        foreach ($this->authorizations as $auth) {
            if ($auth->status == 'pending') {
                $challenge = $auth->getChallenge($type);
                if ($challenge['status'] == 'pending') {
                    $keyAuthorization = $challenge['token'] . '.' . $digest;
                    switch (strtolower($type)) {
                        case LEOrder::CHALLENGE_TYPE_HTTP:
                            $authorizations[] = [
                                'type' => LEOrder::CHALLENGE_TYPE_HTTP,
                                'identifier' => $auth->identifier['value'],
                                'filename' => $challenge['token'],
                                'content' => $keyAuthorization
                            ];
                            break;
                        case LEOrder::CHALLENGE_TYPE_DNS:
                            $DNSDigest = LEFunctions::base64UrlSafeEncode(
                                hash('sha256', $keyAuthorization, true)
                            );
                            $authorizations[] = [
                                'type' => LEOrder::CHALLENGE_TYPE_DNS,
                                'identifier' => $auth->identifier['value'],
                                'DNSDigest' => $DNSDigest
                            ];
                            break;
                    }
                }
            }
        }

        return count($authorizations) > 0 ? $authorizations : false;
    }

    /**
     * Sends a verification request for a given $identifier and $type. The function itself checks whether the
     * verification is valid before making the request.
     * Updates the LetsEncrypt Authorization instances after a successful verification.
     *
     * @param string $identifier The domain name to verify.
     * @param int $type The type of verification. Supporting LEOrder::CHALLENGE_TYPE_HTTP and
     *                           LEOrder::CHALLENGE_TYPE_DNS.
     *
     * @return boolean  Returns true when the verification request was successful, false if not.
     */
    public function verifyPendingOrderAuthorization($identifier, $type)
    {
        $privateKey = $this->loadAccountKey();
        $details = openssl_pkey_get_details($privateKey);

        $header = [
            "e" => LEFunctions::base64UrlSafeEncode($details["rsa"]["e"]),
            "kty" => "RSA",
            "n" => LEFunctions::base64UrlSafeEncode($details["rsa"]["n"])
        ];
        $digest = LEFunctions::base64UrlSafeEncode(hash('sha256', json_encode($header), true));

        foreach ($this->authorizations as $auth) {
            if ($auth->identifier['value'] == $identifier) {
                if ($auth->status == 'pending') {
                    $challenge = $auth->getChallenge($type);
                    if ($challenge['status'] == 'pending') {
                        $keyAuthorization = $challenge['token'] . '.' . $digest;
                        switch ($type) {
                            case LEOrder::CHALLENGE_TYPE_HTTP:
                                return $this->verifyHTTPChallenge($identifier, $challenge, $keyAuthorization, $auth);
                            case LEOrder::CHALLENGE_TYPE_DNS:
                                return $this->verifyDNSChallenge($identifier, $challenge, $keyAuthorization, $auth);
                        }
                    }
                }
            }
        }

        //f we reach here, the domain identifier given did not match any authorization object
        //@codeCoverageIgnoreStart
        throw new LogicException("Attempt to verify authorization for identifier $identifier not in order");
        //@codeCoverageIgnoreEnd
    }

    private function verifyDNSChallenge($identifier, array $challenge, $keyAuthorization, LEAuthorization $auth)
    {
        //check it ourselves
        $DNSDigest = LEFunctions::base64UrlSafeEncode(hash('sha256', $keyAuthorization, true));
        if (!$this->dns->checkChallenge($identifier, $DNSDigest)) {
            $this->log->warning("DNS challenge for $identifier tested, found invalid.");
            return false;
        }

        //ask LE to check
        $sign = $this->connector->signRequestKid(
            ['keyAuthorization' => $keyAuthorization],
            $this->connector->accountURL,
            $challenge['url']
        );
        $post = $this->connector->post($challenge['url'], $sign);
        if ($post['status'] !== 200) {
            $this->log->warning("DNS challenge for $identifier valid, but failed to post to ACME service");
            return false;
        }

        while ($auth->status == 'pending') {
            $this->log->notice("DNS challenge for $identifier valid - waiting for confirmation");
            $this->sleep->for(1);
            $auth->updateData();
        }
        $this->log->notice("DNS challenge for $identifier validated");

        return true;
    }

    private function verifyHTTPChallenge($identifier, array $challenge, $keyAuthorization, LEAuthorization $auth)
    {
        if (!$this->connector->checkHTTPChallenge($identifier, $challenge['token'], $keyAuthorization)) {
            $this->log->warning("HTTP challenge for $identifier tested, found invalid.");
            return false;
        }

        $sign = $this->connector->signRequestKid(
            ['keyAuthorization' => $keyAuthorization],
            $this->connector->accountURL,
            $challenge['url']
        );

        $post = $this->connector->post($challenge['url'], $sign);
        if ($post['status'] !== 200) {
            //@codeCoverageIgnoreStart
            $this->log->warning("HTTP challenge for $identifier valid, but failed to post to ACME service");
            return false;
            //@codeCoverageIgnoreEnd
        }

        while ($auth->status == 'pending') {
            $this->log->notice("HTTP challenge for $identifier valid - waiting for confirmation");
            $this->sleep->for(1);
            $auth->updateData();
        }
        $this->log->notice("HTTP challenge for $identifier validated");
        return true;
    }

    /*
     * Deactivate an LetsEncrypt Authorization instance.
     *
     * @param string $identifier The domain name for which the verification should be deactivated.
     *
     * @return boolean  Returns true is the deactivation request was successful, false if not.
     */
    /*
    public function deactivateOrderAuthorization($identifier)
    {
        foreach ($this->authorizations as $auth) {
            if ($auth->identifier['value'] == $identifier) {
                $sign = $this->connector->signRequestKid(
                    ['status' => 'deactivated'],
                    $this->connector->accountURL,
                    $auth->authorizationURL
                );
                $post = $this->connector->post($auth->authorizationURL, $sign);
                if (strpos($post['header'], "200 OK") !== false) {
                    $this->log->info('Authorization for \'' . $identifier . '\' deactivated.');
                    $this->updateAuthorizations();
                    return true;
                }
            }
        }

        $this->log->warning('No authorization found for \'' . $identifier . '\', cannot deactivate.');

        return false;
    }
    */

    /**
     * Generates a Certificate Signing Request for the identifiers in the current LetsEncrypt Order instance.
     * If possible, the base name will be the certificate common name and all domain names in this LetsEncrypt Order
     * instance will be added to the Subject Alternative Names entry.
     *
     * @return string   Returns the generated CSR as string, unprepared for LetsEncrypt. Preparation for the request
     *                  happens in finalizeOrder()
     */
    private function generateCSR()
    {
        $domains = array_map(function ($dns) {
            return $dns['value'];
        }, $this->identifiers);

        $dn = ["commonName" => $this->calcCommonName($domains)];

        $san = implode(",", array_map(function ($dns) {
            return "DNS:" . $dns;
        }, $domains));
        $tmpConf = tmpfile();
        if ($tmpConf === false) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('LEOrder::generateCSR failed to create tmp file');
            //@codeCoverageIgnoreEnd
        }
        $tmpConfMeta = stream_get_meta_data($tmpConf);
        $tmpConfPath = $tmpConfMeta["uri"];

        fwrite(
            $tmpConf,
            'HOME = .
			RANDFILE = $ENV::HOME/.rnd
			[ req ]
			default_bits = 4096
			default_keyfile = privkey.pem
			distinguished_name = req_distinguished_name
			req_extensions = v3_req
			[ req_distinguished_name ]
			countryName = Country Name (2 letter code)
			[ v3_req ]
			basicConstraints = CA:FALSE
			subjectAltName = ' . $san . '
			keyUsage = nonRepudiation, digitalSignature, keyEncipherment'
        );

        $privateKey = $this->loadCertificateKey();
        $csr = openssl_csr_new($dn, $privateKey, ['config' => $tmpConfPath, 'digest_alg' => 'sha256']);
        openssl_csr_export($csr, $csr);
        return $csr;
    }

    private function calcCommonName($domains)
    {
        if (in_array($this->basename, $domains)) {
            $CN = $this->basename;
        } elseif (in_array('*.' . $this->basename, $domains)) {
            $CN = '*.' . $this->basename;
        } else {
            $CN = $domains[0];
        }
        return $CN;
    }

    /**
     * Checks, for redundancy, whether all authorizations are valid, and finalizes the order. Updates this LetsEncrypt
     * Order instance with the new data.
     *
     * @param string $csr The Certificate Signing Request as a string. Can be a custom CSR. If empty, a CSR will
     *                    be generated with the generateCSR() function.
     *
     * @return boolean  Returns true if the finalize request was successful, false if not.
     */
    public function finalizeOrder($csr = '')
    {
        if ($this->status == 'pending') {
            if ($this->allAuthorizationsValid()) {
                if (empty($csr)) {
                    $csr = $this->generateCSR();
                }
                if (preg_match(
                    '~-----BEGIN\sCERTIFICATE\sREQUEST-----(.*)-----END\sCERTIFICATE\sREQUEST-----~s',
                    $csr,
                    $matches
                )
                ) {
                    $csr = $matches[1];
                }
                $csr = trim(LEFunctions::base64UrlSafeEncode(base64_decode($csr)));
                $sign = $this->connector->signRequestKid(
                    ['csr' => $csr],
                    $this->connector->accountURL,
                    $this->finalizeURL
                );
                $post = $this->connector->post($this->finalizeURL, $sign);
                if (strpos($post['header'], "200 OK") !== false) {
                    $this->status = $post['body']['status'];
                    $this->expires = $post['body']['expires'];
                    $this->identifiers = $post['body']['identifiers'];
                    $this->authorizationURLs = $post['body']['authorizations'];
                    $this->finalizeURL = $post['body']['finalize'];
                    if (array_key_exists('certificate', $post['body'])) {
                        $this->certificateURL = $post['body']['certificate'];
                    }
                    $this->updateAuthorizations();
                    $this->log->info('Order for \'' . $this->basename . '\' finalized.');

                    return true;
                }
            } else {
                $this->log->warning(
                    'Not all authorizations are valid for \'' .
                    $this->basename . '\'. Cannot finalize order.'
                );
            }
        } else {
            $this->log->warning(
                'Order status for \'' . $this->basename .
                '\' is \'' . $this->status . '\'. Cannot finalize order.'
            );
        }
        return false;
    }

    /**
     * Gets whether the LetsEncrypt Order is finalized by checking whether the status is processing or valid. Keep in
     * mind, a certificate is not yet available when the status still is processing.
     *
     * @return boolean  Returns true if finalized, false if not.
     */
    public function isFinalized()
    {
        return ($this->status == 'processing' || $this->status == 'valid');
    }

    /**
     * Requests the certificate for this LetsEncrypt Order instance, after finalization. When the order status is still
     * 'processing', the order will be polled max four times with five seconds in between. If the status becomes 'valid'
     * in the meantime, the certificate will be requested. Else, the function returns false.
     *
     * @return boolean  Returns true if the certificate is stored successfully, false if the certificate could not be
     *                  retrieved or the status remained 'processing'.
     */
    public function getCertificate()
    {
        $polling = 0;
        while ($this->status == 'processing' && $polling < 4) {
            $this->log->info('Certificate for ' . $this->basename . ' being processed. Retrying in 5 seconds...');

            $this->sleep->for(5);
            $this->updateOrderData();
            $polling++;
        }

        if ($this->status != 'valid' || empty($this->certificateURL)) {
            $this->log->warning(
                'Order for ' . $this->basename . ' not valid. Cannot retrieve certificate.'
            );
            return false;
        }

        $get = $this->connector->get($this->certificateURL);
        if (strpos($get['header'], "200 OK") === false) {
            $this->log->warning(
                'Invalid response for certificate request for \'' . $this->basename .
                '\'. Cannot save certificate.'
            );
            return false;
        }

        return $this->writeCertificates($get['body']);
    }


    private function writeCertificates($body)
    {
        if (preg_match_all('~(-----BEGIN\sCERTIFICATE-----[\s\S]+?-----END\sCERTIFICATE-----)~i', $body, $matches)) {
            $this->storage->setCertificate($this->basename, $matches[0][0]);

            $matchCount = count($matches[0]);
            if ($matchCount > 1) {
                $fullchain = $matches[0][0] . "\n";

                for ($i = 1; $i < $matchCount; $i++) {
                    $fullchain .= $matches[0][$i] . "\n";
                }
                $this->storage->setFullChainCertificate($this->basename, $fullchain);
            }
            $this->log->info("Certificate for {$this->basename} stored");
            return true;
        }

        $this->log->error("Received invalid certificate for {$this->basename}, cannot save");
        return false;
    }

    /**
     * Revokes the certificate in the current LetsEncrypt Order instance, if existent. Unlike stated in the ACME draft,
     * the certificate revoke request cannot be signed with the account private key, and will be signed with the
     * certificate private key.
     *
     * @param int $reason The reason to revoke the LetsEncrypt Order instance certificate. Possible reasons can be
     *                        found in section 5.3.1 of RFC5280.
     *
     * @return boolean  Returns true if the certificate was successfully revoked, false if not.
     */
    public function revokeCertificate($reason = 0)
    {
        if ($this->status != 'valid') {
            $this->log->warning("Order for {$this->basename} not valid, cannot revoke");
            return false;
        }

        $certificate = $this->storage->getCertificate($this->basename);
        if (empty($certificate)) {
            $this->log->warning("Certificate for {$this->basename} not found, cannot revoke");
            return false;
        }

        preg_match('~-----BEGIN\sCERTIFICATE-----(.*)-----END\sCERTIFICATE-----~s', $certificate, $matches);
        $certificate = trim(LEFunctions::base64UrlSafeEncode(base64_decode(trim($matches[1]))));

        $certificateKey = $this->storage->getPrivateKey($this->basename);
        $sign = $this->connector->signRequestJWK(
            ['certificate' => $certificate, 'reason' => $reason],
            $this->connector->revokeCert,
            $certificateKey
        );
        //4**/5** responses will throw an exception...
        $this->connector->post($this->connector->revokeCert, $sign);
        $this->log->info("Certificate for {$this->basename} successfully revoked");
        return true;
    }
}
