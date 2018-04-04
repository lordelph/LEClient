<?php

/* DNSOverHTTPS
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

namespace Elphin\LEClient;

use GuzzleHttp\Client;
use Psr\Http\Message\ResponseInterface;

class DNSOverHTTPS
{

    const DNS_CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';
    const DNS_GOOGLE = 'https://dns.google.com/resolve';

    /**
     * Domain to query
     *
     * @var $name string
     */
    public $name;

    /**
     * Type of query
     *
     * @var $type string
     */
    public $type;

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
            'base_uri' => $this->baseURI,
            'Accept' => 'application/json'
        ]);
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
                'name' => $name,
                'type' => $type
            ]
        ];

        if (strpos($this->baseURI, 'cloudflare')) {
            $query['query']['ct'] = 'application/dns-json'; //CloudFlare forces this tag, Google ignores
        }

        $response = $this->client->get(null, $query);

        $this->checkError($response);

        return json_decode($response->getBody());
    }

    /**
     * @param ResponseInterface $response
     */
    private function checkError(ResponseInterface $response) : void
    {
        $json = json_decode($response->getBody());

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException();
        }

        if (isset($json->errors) && count($json->errors) >= 1) { //not current in spec
            throw new \RuntimeException($json->errors[0]->message, $json->errors[0]->code);
        }
    }
}
