<?php

namespace Zwartpet\PHPCertificateToolbox\DNSValidator;

/**
 * NativeDNS implements DNSValidatorInterface using locally available DNS services
 *
 * @package Zwartpet\PHPCertificateToolbox
 * @codeCoverageIgnore
 */
class NativeDNS implements DNSValidatorInterface
{
    public function checkChallenge($domain, $requiredDigest) : bool
    {
        $hostname = '_acme-challenge.' . str_replace('*.', '', $domain);
        $records =  dns_get_record($hostname, DNS_TXT);
        foreach ($records as $record) {
            if ($record['host'] == $hostname && $record['type'] == 'TXT' && $record['txt'] == $requiredDigest) {
                return true;
            }
        }
        return false;
    }
}
