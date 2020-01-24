<?php

namespace Zwartpet\PHPCertificateToolbox\DNSValidator;

/**
 * Interface DNSInterface provides a pluggable service for checking DNS challenges. Not only is
 * this useful for testing, you can swap in alternative implementations like using DNS-over-HTTPS
 *
 * @package Zwartpet\PHPCertificateToolbox\DNSValidator
 */
interface DNSValidatorInterface
{
    /**
     * This will strip any leading *. wildcard and prepend _acme-challenge. to form the challenge domain,
     * and will then request TXT record for that domain. If the record is found, and the content matches
     * the given digest, return true. Otherwise, return false
     *
     * @param $domain string base domain for certificate, which can include wildcard
     * @param $requiredDigest string expected digest value
     * @return bool
     */
    public function checkChallenge($domain, $requiredDigest) : bool;
}
