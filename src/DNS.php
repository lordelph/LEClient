<?php

namespace Elphin\LEClient;

/**
 * Class DNS exists to provide an injectable service for DNS queries which we can mock for unit tests
 * @package Elphin\LEClient
 * @codeCoverageIgnore
 */
class DNS
{
    public function checkChallenge($domain, $requiredDigest)
    {
        $hostname = '_acme-challenge.' . str_replace('*.', '', $domain);

        $records = new DNSOverHTTPS(DNSOverHTTPS::Google);
        $records = $records->get($hostname, 'TXT');

        foreach ($records->Answer as $record) {
            if ($record->host == $hostname && $record->type == 16 && $record->data == $requiredDigest) {
                return true;
            }
        }
        return false;
    }
}
