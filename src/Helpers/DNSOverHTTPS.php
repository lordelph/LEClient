<?php

/*  DNSOverHTTPS
 *  ------------------------------------------
 *  Author: wutno (#/g/punk - Rizon)
 *  Last update: 4/4/2018 1:48PM -5GMT
 *
 *
 *  GNU License Agreement
 *  ---------------------
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 *  http://www.gnu.org/licenses/gpl-2.0.txt
 */

namespace Elphin\LEClient;

use GuzzleHttp\Client;
use Psr\Http\Message\ResponseInterface;

class DNSOverHTTPS{

    const CloudFlare = 'https://cloudflare-dns.com/dns-query';
    const Google = 'https://dns.google.com/resolve';

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
        if ($baseURI === null)
            $this->baseURI = 'https://dns.google.com/resolve';
        else
            $this->baseURI = $baseURI;

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

        if(strpos($this->baseURI, 'cloudflare'))
            $query['query']['ct'] = 'application/dns-json'; //CloudFlare forces this tag, Google ignores

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