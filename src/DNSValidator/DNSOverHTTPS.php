<?php

/**
 * DNSOverHTTPS
 *
 * MIT License
 *
 * Copyright (c) 2018 wutno (#/g/punk - Rizon)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace Zwartpet\PHPCertificateToolbox\DNSValidator;

use GuzzleHttp\Client;
use Zwartpet\PHPCertificateToolbox\Exception\RuntimeException;
use GuzzleHttp\Exception\BadResponseException;

/**
 * DNSOverHTTPS implements DNSValidatorInterface using Google's DNS-over-HTTPS service
 * @package Zwartpet\PHPCertificateToolbox\DNSValidator
 */
class DNSOverHTTPS implements DNSValidatorInterface
{

    const DNS_GOOGLE     = 'https://dns.google.com/resolve';
    const DNS_MOZILLA    = 'https://mozilla.cloudflare-dns.com/dns-query';
    const DNS_CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';

    /**
     * What DNS-over-HTTPS service to use
     *
     * @var null|string
     */
    private $baseURI;

    /**
     * Guzzle client handler
     *
     * @var Client object
     */
    private $client;

    /**
     * DNSOverHTTPS constructor.
     * @param string|null $baseURI
     */
    public function __construct(string $baseURI = null)
    {
        //Default to Google, seems like a safe bet...
        if ($baseURI === null) {
            $this->baseURI = self::DNS_GOOGLE;
        } else {
            $this->baseURI = $baseURI;
        }

        $this->client = new Client([
            'base_uri' => $this->baseURI
        ]);
    }

    public function checkChallenge($domain, $requiredDigest) : bool
    {
        $hostname = '_acme-challenge.' . str_replace('*.', '', $domain);

        $records = $this->get($hostname, 'TXT');
        if ($records->Status == 0) {
            foreach ($records->Answer as $record) {
                if ((rtrim($record->name, ".") == $hostname) &&
                    ($record->type == 16) &&
                    (trim($record->data, '"') == $requiredDigest)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param string $name
     * @param string $type per experimental spec this can be string OR int, we force string
     * @return \stdClass
     */
    public function get(string $name, string $type) : \stdClass
    {
        $query = [
            'query' => [
                'name'               => $name,
                'type'               => $type,
                'edns_client_subnet' => '0.0.0.0/0',            //disable geotagged dns results
                'ct'                 => 'application/dns-json', //cloudflare requires this
            ],
            'headers' => [
                'Accept' => 'application/dns-json'
            ]
        ];

        try {
            $response = $this->client->get(null, $query);
        } catch (BadResponseException $e) {
            throw new RuntimeException("GET {$this->baseURI} failed", 0, $e);
        }

        $decode = json_decode($response->getBody());

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException(
                'Attempted to decode expected JSON response, however server returned something unexpected.'
            );
        }

        return $decode;
    }
}
