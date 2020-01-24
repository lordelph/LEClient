<?php

namespace Zwartpet\PHPCertificateToolbox;

use Zwartpet\PHPCertificateToolbox\DNSValidator\DNSValidatorInterface;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;

/**
 * This provides a variety of simulated ACME responses for test cases
 *
 * The TestResponseGenerator can be used to create this from real traffic
 *
 * @package Zwartpet\PHPCertificateToolbox
 */
class LETestCase extends TestCase
{
    /**
     * Return DNS mock which will return success or failure for checkChallenge
     * @param $success
     * @return DNSValidatorInterface
     */
    protected function mockDNS($success = true)
    {
        //mock DNS service which will pretend our challenges have been set
        $dns = $this->prophesize(DNSValidatorInterface::class);
        $dns->checkChallenge(Argument::any(), Argument::any())
            ->willReturn($success);

        return $dns->reveal();
    }

    /**
     * @return Sleep
     */
    protected function mockSleep()
    {
        //mock sleep service which, erm, won't sleep. Shave a few seconds off tests!
        $sleep = $this->prophesize(Sleep::class);
        $sleep->for(Argument::any())->willReturn(true);
        return $sleep->reveal();
    }

    /**
     * Recursive delete directory
     * @param $dir
     */
    protected function deleteDirectory($dir)
    {
        if (is_dir($dir)) {
            $objects = scandir($dir);
            foreach ($objects as $object) {
                if ($object != "." && $object != "..") {
                    if (is_dir($dir . "/" . $object)) {
                        $this->deleteDirectory($dir . "/" . $object);
                    } else {
                        unlink($dir . "/" . $object);
                    }
                }
            }
            rmdir($dir);
        }
    }

    /**
     * Simulated response to GET https://acme-staging-v02.api.letsencrypt.org/directory
     */
    protected function getDirectoryResponse()
    {
        $body = <<<JSON
        {
          "Zqd7Pa9j6z0": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
          "keyChange": "https://acme-staging-v02.api.letsencrypt.org/acme/key-change",
          "meta": {
            "termsOfService": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf"
          },
          "newAccount": "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct",
          "newNonce": "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce",
          "newOrder": "https://acme-staging-v02.api.letsencrypt.org/acme/new-order",
          "revokeCert": "https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert"
        }
JSON;
        $body = trim($body);

        $now = new \DateTime;
        $nowFmt = $now->format('D, j M Y H:i:s e');


        $headers = [
            'Server' => 'nginx',
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
            'X-Frame-Options' => 'DENY',
            'Strict-Transport-Security' => 'max-age=604800',
            'Expires' => $nowFmt,
            'Cache-Control' => 'max-age=0, no-cache, no-store',
            'Pragma' => 'no-cache',
            'Date' => $nowFmt,
            'Connection' => 'keep-alive'
        ];

        return new Response(200, $headers, $body);
    }

    /**
     * Simulated response for HEAD https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce
     * @return Response
     */
    protected function headNewNonceResponse()
    {
        $now = new \DateTime;
        $nowFmt = $now->format('D, j M Y H:i:s e');

        $headers = [
            'Server' => 'nginx',
            'Replay-Nonce' => 'nBmz5qIrxfRE12DYK0ZN2PvS-3PlPy0OWBPHljRvjlg',
            'X-Frame-Options' => 'DENY',
            'Strict-Transport-Security' => 'max-age=604800',
            'Expires' => $nowFmt,
            'Cache-Control' => 'max-age=0, no-cache, no-store',
            'Pragma' => 'no-cache',
            'Date' => $nowFmt,
            'Connection' => 'keep-alive'
        ];

        return new Response(200, $headers);
    }

    /**
     * Simulated response for a 404 which includes a JSON error
     * @return Response
     */
    protected function getMissingResponse()
    {
        $now = new \DateTime;
        $nowFmt = $now->format('D, j M Y H:i:s e');

        $body=['detail' => 'Requested object not found'];
        $json = json_encode($body);

        $headers = [
            'Server' => 'nginx',
            'X-Frame-Options' => 'DENY',
            'Strict-Transport-Security' => 'max-age=604800',
            'Expires' => $nowFmt,
            'Cache-Control' => 'max-age=0, no-cache, no-store',
            'Pragma' => 'no-cache',
            'Date' => $nowFmt,
            'Connection' => 'keep-alive',
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($json),
        ];

        return new Response(404, $headers, $json);
    }

    protected function postNewAccountJSON()
    {
        $date = new \DateTime;
        $isoNow = $date->format('c');

        $n='35wpDxjGtu4o6AZVA1l4qaDhVUtpkW-iFSHXWzMJMyjVLj9kVN8ZMky6y47VwctZhX0WdL7PLKfJslVUnQkP0kXD_AIPHdMjgOHqlNR_'.
            '4gNFIc8vpT8qjzfVzv5GMnDhTmzAH_YtemSkVJ3NwJxzcn5sjGsaQaHOIZMWbHnEq9LYHrBPzjITG_PLEGsmfjt5cYdzajif7RLYm_C'.
            'luGqZBOxhyy5_Q80m5lVg7tefaGsNK4rzZi2vWd1SIt_3vTBPc1YO9PtNoE-r6MpWUmRxQThcFivYT1iDNNY5oUtJDV8RFQ484P5C43'.
            'Ovj8HagiuZAIyQ6qKXly3o7ShFmY6VqXnHakPKJpk9MFR26qXiSkBWklDV5OEaslPXRetinhbcwNNYibrp7oJcPuTYLQz5DYvmcIGuS'.
            'Pxo1WmjkKPXRmgYkk76QBuYabEgs94jxUgz8Ez5YdqydFfnBGmQfgI_mzxlsZxwv1ArxlWsLP5tkRkBevXM4foY7Crek8_8YaW_4Jvz'.
            'KFF9dQctBmjFwNKjNcuJeKBM6wjQ6tIE13Lz8TTV8KaYbwEBFWjnXUKCSJAajFTSTDmo08kqdgQ2Awzku_JFWzkf-tuSQPmIc0kObRI'.
            'yFz6FDNX0j4Qpk_-V_Fu8QhAE5u9rwjMuhd8ypoNp-LdewNA4osCxSg0usM7p-n8';

        $body = <<<JSON
        {
          "id": 5757881,
          "key": {
            "kty": "RSA",
            "n": "$n",
            "e": "AQAB"
          },
          "contact": [
            "mailto:info@example.org"
          ],
          "agreement": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf",
          "initialIp": "81.106.234.253",
          "createdAt": "$isoNow",
          "status": "valid"
        }
JSON;
        $body = trim($body);
        return $body;
    }
    /**
     * Simulate response for POST https://acme-staging-v02.api.letsencrypt.org/acme/new-acct
     */
    protected function postNewAccountResponse()
    {
        $date = new \DateTime;
        $now = $date->format('D, j M Y H:i:s e');

        $body = $this->postNewAccountJSON();

        $headers = [
            'Server' => 'nginx',
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
            'Boulder-Requester' => '5757881',
            'Link' => '<https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf>;rel="terms-of-service"',
            'Location' => 'https://acme-staging-v02.api.letsencrypt.org/acme/acct/5757881',
            'Replay-Nonce' => 'RDDmW0V4WI-6tONjK3XCTY6u8Bvax6IvxKXG9jvqBig',
            'X-Frame-Options' => 'DENY',
            'Strict-Transport-Security' => 'max-age=604800',
            'Expires' => $now,
            'Cache-Control' => 'max-age=0, no-cache, no-store',
            'Pragma' => 'no-cache',
            'Date' => $now,
            'Connection' => 'keep-alive',
        ];
        return new Response(201, $headers, $body);
    }

    /**
     * Simulate response for POST https://acme-staging-v02.api.letsencrypt.org/acme/acct/5757881
     */
    protected function postAccountResponse()
    {
        $date = new \DateTime;
        $now = $date->format('D, j M Y H:i:s e');
        $isoNow = $date->format('c');

        $n='35wpDxjGtu4o6AZVA1l4qaDhVUtpkW-iFSHXWzMJMyjVLj9kVN8ZMky6y47VwctZhX0WdL7PLKfJslVUnQkP0kXD_AIPHdMjgOHqlNR_'.
            '4gNFIc8vpT8qjzfVzv5GMnDhTmzAH_YtemSkVJ3NwJxzcn5sjGsaQaHOIZMWbHnEq9LYHrBPzjITG_PLEGsmfjt5cYdzajif7RLYm_C'.
            'luGqZBOxhyy5_Q80m5lVg7tefaGsNK4rzZi2vWd1SIt_3vTBPc1YO9PtNoE-r6MpWUmRxQThcFivYT1iDNNY5oUtJDV8RFQ484P5C43'.
            'Ovj8HagiuZAIyQ6qKXly3o7ShFmY6VqXnHakPKJpk9MFR26qXiSkBWklDV5OEaslPXRetinhbcwNNYibrp7oJcPuTYLQz5DYvmcIGuS'.
            'Pxo1WmjkKPXRmgYkk76QBuYabEgs94jxUgz8Ez5YdqydFfnBGmQfgI_mzxlsZxwv1ArxlWsLP5tkRkBevXM4foY7Crek8_8YaW_4Jvz'.
            'KFF9dQctBmjFwNKjNcuJeKBM6wjQ6tIE13Lz8TTV8KaYbwEBFWjnXUKCSJAajFTSTDmo08kqdgQ2Awzku_JFWzkf-tuSQPmIc0kObRI'.
            'yFz6FDNX0j4Qpk_-V_Fu8QhAE5u9rwjMuhd8ypoNp-LdewNA4osCxSg0usM7p-n8';



        $body = <<<JSON
        {
          "id": 5757881,
          "key": {
            "kty": "RSA",
             "n": "$n",
             "e": "AQAB"
          },
          "contact": [
            "mailto:info@example.org"
          ],
          "agreement": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf",
          "initialIp": "81.106.234.253",
          "createdAt": "$isoNow",
          "status": "valid"
        }
JSON;
        $body = trim($body);

        $headers = [
            'Server' => 'nginx',
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
            'Boulder-Requester' => '5757881',
            'Link' => '<https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf>;rel="terms-of-service"',
            'Replay-Nonce' => 'Wa57-T-1ogpJPKmee3VE6OsUJQ97d-zn5_OSWnt4CbA',
            'X-Frame-Options' => 'DENY',
            'Strict-Transport-Security' => 'max-age=604800',
            'Expires' => $now,
            'Cache-Control' => 'max-age=0, no-cache, no-store',
            'Pragma' => 'no-cache',
            'Date' => $now,
            'Connection' => 'keep-alive',
        ];
        return new Response(200, $headers, $body);
    }

    protected function getOrderJSON($orderStatus = 'pending')
    {
        $expires = new \DateTime;
        $expires->add(new \DateInterval('P7D'));
        $isoExpires = $expires->format('c');

        $cert='';
        if ($orderStatus === 'valid') {
            $cert = '"certificate": ' .
                '"https://acme-staging-v02.api.letsencrypt.org/acme/cert/fae09c6dcdaf7aa198092b3170c69129a490",';
        }

        $json = <<<JSON
        {
          "status": "$orderStatus",
          "expires": "$isoExpires",
          "identifiers": [
            {
              "type": "dns",
              "value": "example.org"
            },
            {
              "type": "dns",
              "value": "test.example.org"
            }
          ],
          "authorizations": [
            "https://acme-staging-v02.api.letsencrypt.org/acme/authz/X2QaFXwrBz7VlN6zdKgm_jmiBctwVZgMZXks4YhfPng",
            "https://acme-staging-v02.api.letsencrypt.org/acme/authz/WDMI8oX6avFT_rEBfh-ZBMdZs3S-7li2l5gRrps4MXM"
          ],
          $cert
          "finalize": "https://acme-staging-v02.api.letsencrypt.org/acme/finalize/5758369/94473"
        }
JSON;
        $json = trim($json);
        return $json;
    }

    /**
     * Simulate response for POST https://acme-staging-v02.api.letsencrypt.org/acme/new-order
     */
    protected function postNewOrderResponse()
    {
        $date = new \DateTime;
        $now = $date->format('D, j M Y H:i:s e');

        $body = $this->getOrderJSON();

        $headers = [
            'Server' => 'nginx',
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
            'Boulder-Requester' => '5758369',
            'Location' => 'https://acme-staging-v02.api.letsencrypt.org/acme/order/5758369/94473',
            'Replay-Nonce' => 'rWPDZxnr7VhwT6suSqNjaZhHsTWAPHwihf32CAGVXqc',
            'X-Frame-Options' => 'DENY',
            'Strict-Transport-Security' => 'max-age=604800',
            'Expires' => $now,
            'Cache-Control' => 'max-age=0, no-cache, no-store',
            'Pragma' => 'no-cache',
            'Date' => $now,
            'Connection' => 'keep-alive',
        ];
        return new Response(201, $headers, $body);
    }

    protected function getAuthzJSON($domain = 'test.example.org', $dnsValidated = false)
    {
        $expires = new \DateTime;
        $expires->add(new \DateInterval('P7D'));
        $isoExpires = $expires->format('c');

        $status = $dnsValidated ? 'valid' : 'pending';

        $validationRecord='';
        if ($dnsValidated) {
            $validationRecord=<<<REC
            ,"validationRecord": [
                {
                    "hostname": "$domain"
                }
              ]
REC;
        }

        $prefix='https://acme-staging-v02.api.letsencrypt.org/acme/challenge';

        $json = <<<JSON
        {
          "identifier": {
            "type": "dns",
            "value": "$domain"
          },
          "status": "$status",
          "expires": "$isoExpires",
          "challenges": [
            {
              "type": "dns-01",
              "status": "$status",
              "url": "$prefix/WDMI8oX6avFT_rEBfh-ZBMdZs3S-7li2l5gRrps4MXM/110025186",
              "token": "1rRDBP200BnpujXAo609BwJa4Yk7f4LWrB-rtQP-foA"
              $validationRecord
            },
            {
              "type": "http-01",
              "status": "pending",
              "url": "$prefix/WDMI8oX6avFT_rEBfh-ZBMdZs3S-7li2l5gRrps4MXM/110025187",
              "token": "bluTsV3KD58nKkoHLYwC34uTThW1zyUA-CCNPll9nqs"
            }
          ]
        }
JSON;
        $json = trim($json);
        return $json;
    }

    /**
     * Simulate response for GET https://acme-staging-v02.api.letsencrypt.org/acme/authz/...
     */
    protected function getAuthzResponse($domain = 'test.example.org', $dnsValidated = false)
    {
        $date = new \DateTime;
        $now = $date->format('D, j M Y H:i:s e');

        $body=$this->getAuthzJSON($domain, $dnsValidated);

        $headers = [
            'Server' => 'nginx',
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
            'X-Frame-Options' => 'DENY',
            'Strict-Transport-Security' => 'max-age=604800',
            'Expires' => $now,
            'Cache-Control' => 'max-age=0, no-cache, no-store',
            'Pragma' => 'no-cache',
            'Date' => $now,
            'Connection' => 'keep-alive',
        ];
        return new Response(200, $headers, $body);
    }


    /**
     * Simulate response for POST https://acme-staging-v02.api.letsencrypt.org/acme/challenge/.../...
     */
    protected function postChallengeResponse()
    {
        $prefix='https://acme-staging-v02.api.letsencrypt.org/acme';

        $date = new \DateTime;
        $now = $date->format('D, j M Y H:i:s e');
        $body = <<<JSON
        {
          "type": "dns-01",
          "status": "pending",
          "url": "$prefix/challenge/rApg01jrldnZ648uZIorI1JtQLuz9nHu2mjZt_NS2WU/110041513",
          "token": "KJREAeF5n83j6mT4TAB9fvw4N5FfHBrlBFVsC4iiHIc"
        }
JSON;
        $body=trim($body);

        $headers=[
            'Server' => 'nginx',
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
            'Boulder-Requester' => '5758369',
            'Link' => "<$prefix/authz/rApg01jrldnZ648uZIorI1JtQLuz9nHu2mjZt_NS2WU>;rel=\"up\"",
            'Location' => "$prefix/challenge/rApg01jrldnZ648uZIorI1JtQLuz9nHu2mjZt_NS2WU/110041513",
            'Replay-Nonce' => '0NJ_rSgGswOF8jSsT4aTtZj2QA0NMaVmtCDwMIUHHrw',
            'X-Frame-Options' => 'DENY',
            'Strict-Transport-Security' => 'max-age=604800',
            'Expires' => $now,
            'Cache-Control' => 'max-age=0, no-cache, no-store',
            'Pragma' => 'no-cache',
            'Date' => $now,
            'Connection' => 'keep-alive',
        ];
        return new Response(200, $headers, $body);
    }


    /**
     * Simulate response for POST https://acme-staging-v02.api.letsencrypt.org/acme/finalize/5758753/94699
     */
    protected function getPostFinalizeResponse()
    {
        $date = new \DateTime;
        $now = $date->format('D, j M Y H:i:s e');

        $expires = new \DateTime;
        $expires->add(new \DateInterval('P7D'));
        $isoExpires = $expires->format('c');

        $body = <<<JSON
        {
          "status": "valid",
          "expires": "$isoExpires",
          "identifiers": [
            {
              "type": "dns",
              "value": "example.org"
            }
          ],
          "authorizations": [
            "https://acme-staging-v02.api.letsencrypt.org/acme/authz/rApg01jrldnZ648uZIorI1JtQLuz9nHu2mjZt_NS2WU"
          ],
          "finalize": "https://acme-staging-v02.api.letsencrypt.org/acme/finalize/5758369/94699",
          "certificate": "https://acme-staging-v02.api.letsencrypt.org/acme/cert/fae09c6dcdaf7aa198092b3170c69129a490"
        }
JSON;
        $body=trim($body);

        $headers=[
            'Server' => 'nginx',
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
            'Boulder-Requester' => '5758369',
            'Location' => 'https://acme-staging-v02.api.letsencrypt.org/acme/order/5758369/94699',
            'Replay-Nonce' => 'QFA6urc60RnOmGmM0ni5VYJsB0_VwPmY-4vo18OlL8o',
            'X-Frame-Options' => 'DENY',
            'Strict-Transport-Security' => 'max-age=604800',
            'Expires' => $now,
            'Cache-Control' => 'max-age=0, no-cache, no-store',
            'Pragma' => 'no-cache',
            'Date' => $now,
            'Connection' => 'keep-alive',
        ];
        return new Response(200, $headers, $body);
    }

    /**
     * Note that certificate below is deliberate garbage - for testing, we don't need a real cert
     * @return string
     */
    protected function getCertBody()
    {
        $body = <<<CERT
-----BEGIN CERTIFICATE-----
MIIG4zCCBcugAwIBAgITAPrgnG3Nr3qhmAkrMXDGkSmkkDANBgkqhkiG9w0BAQsF
ADAiMSAwHgYDVQQDDBdGYWtlIExFIEludGVybWVkaWF0ZSBYMTAeFw0xODAzMTcx
IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3kdWJI3C8vcoo2bP0SfCwc62
ODA5MzZaFw0xODA2MTUxODA5MzZaMBYxFDASBgNVBAMTC2xlLmRpeG8ubmV0MIIC
IA+YnLlNvnf8e3ini91T8I4x8ZWtaZkmrFODDjWRZfoOGhybL624gW5BW451OTWq
kl9g7eRI2wzvPeusEl6ij0zkUHvj1h+fwQxFyIAGxwu8SQeDv68YdUSw8wGBnwst
/4Tre34oatV50gFmoNHlOOOUZ5OwcnafbgiR6YpD7oHAyfDxl3IdSpRYJ9uId7XB
hHt2OES61EUCvTkbzfNPsu8AnzX6rBJ7Rrfn2k3GOuGLE5Tg9ZsWOrQv8sJ5oRrK
vR6tcMdAzdGgSR+ivPx6J/oLURKECqWl7pkIFTOoBjgRf5Hi6HhAZj0yJexk3v5G
VzXYcFmEyNKyEgl0bUIG107VfAe1ZhQ+uNNsij2iuJSHG/etrrpZmv/Iu0fAx7lk
4B3zD/MgcwowtezpcecnUbwPiMcdQBPJwiWvZPJqb59t9MDcCVwwvCKX3b18BqJl
ownlVqrPi1UQVOaIFDgaA6BgFmoNHlOOOUZ5Owcnafjlk27RbIifEa/9nqBTamPa
OnHkpxW6hP3VGpicGJpdDLf+PmbTphUFD2rHsbmP3KlttRUzgEecDLVgcrFrTiJ1
DvQi1Vvy9lQv70B8k/lOuqnlHcksjWY4A6iagA5zk5VlmVNJ4QKRtIAEyF7CBZmD
P0nZ7InRcnhrT8bDXRECAwEAAaOCAxwwggMYMA4GA1UdDwEB/wQEAwIFoDAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
FgQU6R6Kxx6o7/bPBdV1PiVjOGoW+igwHwYDVR0jBBgwFoAUwMwDRrlYIMxccnDz
4S7LIKb1aDowdwYIKwYBBQUHAQEEazBpMDIGCCsGAQUFBzABhiZodHRwOi8vb2Nz
cC5zdGctaW50LXgxLmxldHNlbmNyeXB0Lm9yZzAzBggrBgEFBQcwAoYnaHR0cDov
L2NlcnQuc3RnLWludC14MS5sZXRzZW5jcnlwdC5vcmcvMBYGA1UdEQQPMA2CC2xl
LmRpeG8ubmV0MIH+BgNVHSAEgfYwgfMwCAYGZ4EMAQIBMIHmBgsrBgEEAYLfEwEB
ATCB1jAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwgasG
CCsGAQUFBwICMIGeDIGbVGhpcyBDZXJ0aWZpY2F0ZSBtYXkgb25seSBiZSByZWxp
ZWQgdXBvbiBieSBSZWx5aW5nIFBhcnRpZXMgYW5kIG9ubHkgaW4gYWNjb3JkYW5j
ZSB3aXRoIHRoZSBDZXJ0aWZpY2F0ZSBQb2xpY3kgZm91bmQgYXQgaHR0cHM6Ly9s
ZXRzZW5jcnlwdC5vcmcvcmVwb3NpdG9yeS8wggEFBgorBgEEAdZ5AgQCBIH2BIHz
APEAdwDdmTT8peckgMlWaH2BNJkISbJJ97Vp2Me8qz9cwfNuZAAAAWI1XgHrAAAE
AwBIMEYCIQCtQZ5txYoDZubmMOlQlIiheUNo9oV44ONMGZBqcWj/DQIhAIVKRYSL
iak9CJe5jRDKr9fmhnlNGND8f/01dh2ifcyDAHYAsMyD5aX5fWuvfAnMKEkEhyrH
6IsTLGNQt8b9JuFsbHcAAAFiNV4CPgAABAMARzBFAiEAg45dCPzn9ND7Kn1i4lul
DVcVOF0Z+xAKz/Sn1mtFrNACICbXJj4vt4V0VkZhHcWN5JeoQ0TqTjrqiqN3I39f
rkEfMA0GCSqGSIb3DQEBCwUAA4IBAQBO4pLiqg8Pj4R8V4/UJgIs/SSunVoOlYUh
uZVMO6WSOiZN13m2Krb6uwYcj3fOvHha+1jTrjWv5vOy2DlDPy9VQvx6dmKw1ZLu
sxljuoOmDkznm78zXj6ylrv0lQ0svxRsGrql2DHv7mm1XWlRQNtWUJZIijokwyny
0vkBGBFLEInN9EiSmgDgkEr11k23MKo9Fwx2YHuzZg7x4Gb2W1TmC/ncRx9XvMD6
g2p2GwSf70bFQDSCIOyuuTJ77UNxuS70/ckp4t4ao4NiKDOUSS5XW9iGLsCJhxM1
9RFKHYYWs83vxym4mSRoRwIgIdPnwS6VGsT9h+hAsuVaiuyyXXb5
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIEqzCCApOgAwIBAgIRAIvhKg5ZRO08VGQx8JdhT+UwDQYJKoZIhvcNAQELBQAw
GjEYMBYGA1UEAwwPRmFrZSBMRSBSb290IFgxMB4XDTE2MDUyMzIyMDc1OVoXDTM2
MDUyMzIyMDc1OVowIjEgMB4GA1UEAwwXRmFrZSBMRSBJbnRlcm1lZGlhdGUgWDEw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtWKySDn7rWZc5ggjz3ZB0
8jO4xti3uzINfD5sQ7Lj7hzetUT+wQob+iXSZkhnvx+IvdbXF5/yt8aWPpUKnPym
oLxsYiI5gQBLxNDzIec0OIaflWqAr29m7J8+NNtApEN8nZFnf3bhehZW7AxmS1m0
xDH1Hizq+GKCcHsinDZWurCqder/afJBnQs+SBSL6MVApHt+d35zjBD92fO2Je56
ZnSsdHw0Fw+bgixPg2MQ9k9oefFeqa+7Kqdlz5bbrUYV2volxhDFtnI4Mh8BiWCN
dhMfzCgOKXeJ340WhW3TjD1zqLZXeaCyUNRnfOmWZV8nEhtHOFbUCU7r/KkjMZO9
AgMBAAGjgeMwgeAwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
HQYDVR0OBBYEFMDMA0a5WCDMXHJw8+EuyyCm9Wg6MHoGCCsGAQUFBwEBBG4wbDA0
BggrBgEFBQcwAYYoaHR0cDovL29jc3Auc3RnLXJvb3QteDEubGV0c2VuY3J5cHQu
b3JnLzA0BggrBgEFBQcwAoYoaHR0cDovL2NlcnQuc3RnLXJvb3QteDEubGV0c2Vu
Y3J5cHQub3JnLzAfBgNVHSMEGDAWgBTBJnSkikSg5vogKNhcI5pFiBh54DANBgkq
hkiG9w0BAQsFAAOCAgEABYSu4Il+fI0MYU42OTmEj+1HqQ5DvyAeyCA6sGuZdwjF
UGeVOv3NnLyfofuUOjEbY5irFCDtnv+0ckukUZN9lz4Q2YjWGUpW4TTu3ieTsaC9
AFvCSgNHJyWSVtWvB5XDxsqawl1KzHzzwr132bF2rtGtazSqVqK9E07sGHMCf+zp
DQVDVVGtqZPHwX3KqUtefE621b8RI6VCl4oD30Olf8pjuzG4JKBFRFclzLRjo/h7
IkkfjZ8wDa7faOjVXx6n+eUQ29cIMCzr8/rNWHS9pYGGQKJiY2xmVC9h12H99Xyf
zWE9vb5zKP3MVG6neX1hSdo7PEAb9fqRhHkqVsqUvJlIRmvXvVKTwNCP3eCjRCCI
PTAvjV+4ni786iXwwFYNz8l3PmPLCyQXWGohnJ8iBm+5nk7O2ynaPVW0U2W+pt2w
SVuvdDM5zGv2f9ltNWUiYZHJ1mmO97jSY/6YfdOUH66iRtQtDkHBRdkNBsMbD+Em
2TgBldtHNSJBfB3pm9FblgOcJ0FSWcUDWJ7vO0+NTXlgrRofRT6pVywzxVo6dND0
WzYlTWeUVsO40xJqhgUQRER9YLOLxJ0O6C8i0xFxAMKOtSdodMB3RIwt7RFQ0uyt
n5Z5MqkYhlMI3J1tPRTp1nEt9fyGspBOO05gi148Qasp+3N+svqKomoQglNoAxU=
-----END CERTIFICATE-----
CERT;
        return trim($body);
    }
    /**
     * Simulate response for GET https://acme-staging-v02.api.letsencrypt.org/acme/cert/...
     *
     */
    protected function getCertResponse()
    {
        $date = new \DateTime;
        $now = $date->format('D, j M Y H:i:s e');
        $body = $this->getCertBody();

        $headers=[
            'Server' => 'nginx',
            'Content-Type' => 'application/pem-certificate-chain',
            'Content-Length' => strlen($body),
            'X-Frame-Options' => 'DENY',
            'Strict-Transport-Security' => 'max-age=604800',
            'Expires' => $now,
            'Cache-Control' => 'max-age=0, no-cache, no-store',
            'Pragma' => 'no-cache',
            'Date' => $now,
            'Connection' => 'keep-alive',
        ];
        return new Response(200, $headers, $body);
    }

    /**
     * Simulate response for POST https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert
     */
    protected function getRevokeCertResponse()
    {
        $date = new \DateTime;
        $now = $date->format('D, j M Y H:i:s e');

        $headers=[
            'Server' => 'nginx',
            'Replay-Nonce' => 'z4yMN4_LKg22VZzJZkUe5YuSiC0sknSuwIfC2GF-FOw',
            'X-Frame-Options' => 'DENY',
            'Strict-Transport-Security' => 'max-age=604800',
            'Expires' => $now,
            'Cache-Control' => 'max-age=0, no-cache, no-store',
            'Pragma' => 'no-cache',
            'Date' => $now,
            'Connection' => 'keep-alive',
        ];
        return new Response(200, $headers);
    }
}
