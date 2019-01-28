<?php

namespace Elphin\PHPCertificateToolbox;

use Elphin\PHPCertificateToolbox\Exception\LogicException;
use Elphin\PHPCertificateToolbox\Exception\RuntimeException;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

/**
 * LetsEncrypt Connector class, containing the functions necessary to sign with JSON Web Key and Key ID, and perform
 * GET, POST and HEAD requests.
 *
 * @author     Youri van Weegberg <youri@yourivw.nl>
 * @copyright  2018 Youri van Weegberg
 * @license    https://opensource.org/licenses/mit-license.php  MIT License
 */
class LEConnector
{
    public $baseURL;

    private $nonce;

    public $keyChange;
    public $newAccount;
    public $newNonce;
    public $newOrder;
    public $revokeCert;

    public $accountURL;
    public $accountDeactivated = false;

    /** @var LoggerInterface */
    private $log;

    /** @var ClientInterface */
    private $httpClient;

    /** @var CertificateStorageInterface */
    private $storage;

    /**
     * Initiates the LetsEncrypt Connector class.
     *
     * @param LoggerInterface $log
     * @param ClientInterface $httpClient
     * @param string $baseURL The LetsEncrypt server URL to make requests to.
     * @param CertificateStorageInterface $storage
     */
    public function __construct(
        LoggerInterface $log,
        ClientInterface $httpClient,
        $baseURL,
        CertificateStorageInterface $storage
    ) {
    
        $this->baseURL = $baseURL;
        $this->storage = $storage;
        $this->log = $log;
        $this->httpClient = $httpClient;

        $this->getLEDirectory();
        $this->getNewNonce();
    }

    /**
     * Requests the LetsEncrypt Directory and stores the necessary URLs in this LetsEncrypt Connector instance.
     */
    private function getLEDirectory()
    {
        $req = $this->get('/directory');
        $this->keyChange = $req['body']['keyChange'];
        $this->newAccount = $req['body']['newAccount'];
        $this->newNonce = $req['body']['newNonce'];
        $this->newOrder = $req['body']['newOrder'];
        $this->revokeCert = $req['body']['revokeCert'];
    }

    /**
     * Requests a new nonce from the LetsEncrypt server and stores it in this LetsEncrypt Connector instance.
     */
    private function getNewNonce()
    {
        $result = $this->head($this->newNonce);

        if ($result['status'] !== 200) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException("No new nonce - fetched {$this->newNonce} got " . $result['header']);
            //@codeCoverageIgnoreEnd
        }
    }

    /**
     * Makes a request to the HTTP challenge URL and checks whether the authorization is valid for the given $domain.
     *
     * @param string $domain The domain to check the authorization for.
     * @param string $token The token (filename) to request.
     * @param string $keyAuthorization the keyAuthorization (file content) to compare.
     *
     * @return boolean  Returns true if the challenge is valid, false if not.
     */
    public function checkHTTPChallenge($domain, $token, $keyAuthorization)
    {
        $requestURL = $domain . '/.well-known/acme-challenge/' . $token;

        $request = new Request('GET', $requestURL);

        try {
            $response = $this->httpClient->send($request);
        } catch (\Exception $e) {
            $this->log->warning(
                "HTTP check on $requestURL failed ({msg})",
                ['msg' => $e->getMessage()]
            );
            return false;
        }

        $content = $response->getBody()->getContents();
        return $content == $keyAuthorization;
    }

    /**
     * Makes a Curl request.
     *
     * @param string $method The HTTP method to use. Accepting GET, POST and HEAD requests.
     * @param string $URL The URL or partial URL to make the request to.
     *                       If it is partial, the baseURL will be prepended.
     * @param string $data The body to attach to a POST request. Expected as a JSON encoded string.
     *
     * @return array Returns an array with the keys 'request', 'header' and 'body'.
     */
    private function request($method, $URL, $data = null)
    {
        if ($this->accountDeactivated) {
            throw new LogicException('The account was deactivated. No further requests can be made.');
        }

        $requestURL = preg_match('~^http~', $URL) ? $URL : $this->baseURL . $URL;

        $hdrs = ['Accept' => 'application/json'];
        if (!empty($data)) {
            $hdrs['Content-Type'] = 'application/jose+json';
        }

        $request = new Request($method, $requestURL, $hdrs, $data);

        try {
            $response = $this->httpClient->send($request);
        } catch (BadResponseException $e) {
            //4xx/5xx failures are not expected and we throw exceptions for them
            $msg = "$method $URL failed";
            if ($e->hasResponse()) {
                $body = (string)$e->getResponse()->getBody();
                $json = json_decode($body, true);
                if (!empty($json) && isset($json['detail'])) {
                    $msg .= " ({$json['detail']})";
                }
            }
            throw new RuntimeException($msg, 0, $e);
        } catch (GuzzleException $e) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException("$method $URL failed", 0, $e);
            //@codeCoverageIgnoreEnd
        }

        //uncomment this to generate a test simulation of this request
        //TestResponseGenerator::dumpTestSimulation($method, $requestURL, $response);

        $this->maintainNonce($method, $response);

        return $this->formatResponse($method, $requestURL, $response);
    }

    private function formatResponse($method, $requestURL, ResponseInterface $response)
    {
        $body = $response->getBody();

        $header = $response->getStatusCode() . ' ' . $response->getReasonPhrase() . "\n";
        $allHeaders = $response->getHeaders();
        foreach ($allHeaders as $name => $values) {
            foreach ($values as $value) {
                $header .= "$name: $value\n";
            }
        }

        $decoded = $body;
        if ($response->getHeaderLine('Content-Type') === 'application/json') {
            $decoded = json_decode($body, true);
            if (!$decoded) {
                //@codeCoverageIgnoreStart
                throw new RuntimeException('Bad JSON received ' . $body);
                //@codeCoverageIgnoreEnd
            }
        }

        $jsonresponse = [
            'request' => $method . ' ' . $requestURL,
            'header' => $header,
            'body' => $decoded,
            'raw' => $body,
            'status' => $response->getStatusCode()
        ];

        //$this->log->debug('{request} got {status} header = {header} body = {raw}', $jsonresponse);

        return $jsonresponse;
    }

    private function maintainNonce($requestMethod, ResponseInterface $response)
    {
        if ($response->hasHeader('Replay-Nonce')) {
            $this->nonce = $response->getHeader('Replay-Nonce')[0];
            $this->log->debug("got new nonce " . $this->nonce);
        } elseif ($requestMethod == 'POST') {
            $this->getNewNonce(); // Not expecting a new nonce with GET and HEAD requests.
        }
    }

    /**
     * Makes a GET request.
     *
     * @param string $url The URL or partial URL to make the request to.
     *                    If it is partial, the baseURL will be prepended.
     *
     * @return array Returns an array with the keys 'request', 'header' and 'body'.
     */
    public function get($url)
    {
        return $this->request('GET', $url);
    }

    /**
     * Makes a POST request.
     *
     * @param string $url The URL or partial URL for the request to. If it is partial, the baseURL will be prepended.
     * @param string $data The body to attach to a POST request. Expected as a json string.
     *
     * @return array Returns an array with the keys 'request', 'header' and 'body'.
     */
    public function post($url, $data = null)
    {
        return $this->request('POST', $url, $data);
    }

    /**
     * Makes a HEAD request.
     *
     * @param string $url The URL or partial URL to make the request to.
     *                    If it is partial, the baseURL will be prepended.
     *
     * @return array Returns an array with the keys 'request', 'header' and 'body'.
     */
    public function head($url)
    {
        return $this->request('HEAD', $url);
    }

    /**
     * Generates a JSON Web Key signature to attach to the request.
     *
     * @param array|string $payload The payload to add to the signature.
     * @param string $url The URL to use in the signature.
     * @param string $privateKey The private key to sign the request with.
     *
     * @return string   Returns a JSON encoded string containing the signature.
     */
    public function signRequestJWK($payload, $url, $privateKey = '')
    {
        if ($privateKey == '') {
            $privateKey = $this->storage->getAccountPrivateKey();
        }
        $privateKey = openssl_pkey_get_private($privateKey);
        if ($privateKey === false) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('LEConnector::signRequestJWK failed to get private key');
            //@codeCoverageIgnoreEnd
        }

        $details = openssl_pkey_get_details($privateKey);

        $protected = [
            "alg" => "RS256",
            "jwk" => [
                "kty" => "RSA",
                "n" => LEFunctions::base64UrlSafeEncode($details["rsa"]["n"]),
                "e" => LEFunctions::base64UrlSafeEncode($details["rsa"]["e"]),
            ],
            "nonce" => $this->nonce,
            "url" => $url
        ];

        $payload64 = LEFunctions::base64UrlSafeEncode(
            str_replace('\\/', '/', is_array($payload) ? json_encode($payload) : $payload)
        );
        $protected64 = LEFunctions::base64UrlSafeEncode(json_encode($protected));

        openssl_sign($protected64 . '.' . $payload64, $signed, $privateKey, OPENSSL_ALGO_SHA256);
        $signed64 = LEFunctions::base64UrlSafeEncode($signed);

        $data = [
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $signed64
        ];

        return json_encode($data);
    }

    /**
     * Generates a Key ID signature to attach to the request.
     *
     * @param array|string $payload The payload to add to the signature.
     * @param string $kid The Key ID to use in the signature.
     * @param string $url The URL to use in the signature.
     * @param string $privateKey The private key to sign the request with. Defaults to account key
     *
     * @return string   Returns a JSON encoded string containing the signature.
     */
    public function signRequestKid($payload, $kid, $url, $privateKey = '')
    {
        if ($privateKey == '') {
            $privateKey = $this->storage->getAccountPrivateKey();
        }
        $privateKey = openssl_pkey_get_private($privateKey);

        //$details = openssl_pkey_get_details($privateKey);

        $protected = [
            "alg" => "RS256",
            "kid" => $kid,
            "nonce" => $this->nonce,
            "url" => $url
        ];

        $payload64 = LEFunctions::base64UrlSafeEncode(
            str_replace('\\/', '/', is_array($payload) ? json_encode($payload) : $payload)
        );
        $protected64 = LEFunctions::base64UrlSafeEncode(json_encode($protected));

        openssl_sign($protected64 . '.' . $payload64, $signed, $privateKey, OPENSSL_ALGO_SHA256);
        $signed64 = LEFunctions::base64UrlSafeEncode($signed);

        $data = [
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $signed64
        ];

        return json_encode($data);
    }
}
