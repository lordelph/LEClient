<?php

namespace Zwartpet\PHPCertificateToolbox;

use Zwartpet\PHPCertificateToolbox\Exception\LogicException;
use Zwartpet\PHPCertificateToolbox\Exception\RuntimeException;

/**
 * LetsEncrypt Functions class, supplying the LetsEncrypt Client with supportive functions.
 *
 * @author     Youri van Weegberg <youri@yourivw.nl>
 * @copyright  2018 Youri van Weegberg
 * @license    https://opensource.org/licenses/mit-license.php  MIT License
 */
class LEFunctions
{
    /**
     * Generates a new RSA keypair and returns both
     *
     * @param integer $keySize RSA key size, must be between 2048 and 4096 (default is 4096)
     * @return array containing public and private indexes containing the new keys
     */
    public static function RSAGenerateKeys($keySize = 4096)
    {

        if ($keySize < 2048 || $keySize > 4096) {
            throw new LogicException("RSA key size must be between 2048 and 4096");
        }

        $res = openssl_pkey_new([
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "private_key_bits" => intval($keySize),
        ]);

        if (!openssl_pkey_export($res, $privateKey)) {
            throw new RuntimeException("RSA keypair export failed!"); //@codeCoverageIgnore
        }

        $details = openssl_pkey_get_details($res);

        $result = ['public' => $details['key'], 'private' => $privateKey];

        openssl_pkey_free($res);

        return $result;
    }


    /**
     * Generates a new EC prime256v1 keypair and saves both keys to a new file.
     *
     * @param integer $keySize EC key size, possible values are 256 (prime256v1) or 384 (secp384r1),
     *                               default is 256
     * @return array containing public and private indexes containing the new keys
     */
    public static function ECGenerateKeys($keySize = 256)
    {
        if (version_compare(PHP_VERSION, '7.1.0') == -1) {
            throw new RuntimeException("PHP 7.1+ required for EC keys"); //@codeCoverageIgnore
        }

        if ($keySize == 256) {
            $res = openssl_pkey_new([
                "private_key_type" => OPENSSL_KEYTYPE_EC,
                "curve_name" => "prime256v1",
            ]);
        } elseif ($keySize == 384) {
            $res = openssl_pkey_new([
                "private_key_type" => OPENSSL_KEYTYPE_EC,
                "curve_name" => "secp384r1",
            ]);
        } else {
            throw new LogicException("EC key size must be 256 or 384");
        }


        if (!openssl_pkey_export($res, $privateKey)) {
            throw new RuntimeException("EC keypair export failed!"); //@codeCoverageIgnore
        }

        $details = openssl_pkey_get_details($res);

        $result = ['public' => $details['key'], 'private' => $privateKey];

        openssl_pkey_free($res);

        return $result;
    }


    /**
     * Encodes a string input to a base64 encoded string which is URL safe.
     *
     * @param string $input The input string to encode.
     *
     * @return string   Returns a URL safe base64 encoded string.
     */
    public static function base64UrlSafeEncode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Decodes a string that is URL safe base64 encoded.
     *
     * @param string $input The encoded input string to decode.
     *
     * @return string   Returns the decoded input string.
     */
    public static function base64UrlSafeDecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
}
