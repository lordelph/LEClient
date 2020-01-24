<?php
namespace Zwartpet\PHPCertificateToolbox;

use Zwartpet\PHPCertificateToolbox\Exception\RuntimeException;
use Psr\Log\LoggerInterface;

/**
 * LetsEncrypt Account class, containing the functions and data associated with a LetsEncrypt account.
 *
 * @author     Youri van Weegberg <youri@yourivw.nl>
 * @copyright  2018 Youri van Weegberg
 * @license    https://opensource.org/licenses/mit-license.php  MIT License
 */
class LEAccount
{
    private $connector;

    public $id;
    public $key;
    public $contact;
    public $agreement;
    public $initialIp;
    public $createdAt;
    public $status;

    /** @var LoggerInterface  */
    private $log;

    /** @var CertificateStorageInterface */
    private $storage;

    /**
     * Initiates the LetsEncrypt Account class.
     *
     * @param LEConnector $connector The LetsEncrypt Connector instance to use for HTTP requests.
     * @param LoggerInterface $log   PSR-3 compatible logger
     * @param array $email           The array of strings containing e-mail addresses. Only used when creating a
     *                               new account.
     * @param CertificateStorageInterface $storage  storage for account keys
     */
    public function __construct($connector, LoggerInterface $log, $email, CertificateStorageInterface $storage)
    {
        $this->connector = $connector;
        $this->storage = $storage;
        $this->log = $log;

        if (empty($storage->getAccountPublicKey()) || empty($storage->getAccountPrivateKey())) {
            $this->log->notice("No account found for ".implode(',', $email).", attempting to create account");

            $accountKey = LEFunctions::RSAgenerateKeys();
            $storage->setAccountPublicKey($accountKey['public']);
            $storage->setAccountPrivateKey($accountKey['private']);

            $this->connector->accountURL = $this->createLEAccount($email);
        } else {
            $this->connector->accountURL = $this->getLEAccount();
        }
        if ($this->connector->accountURL === false) {
            throw new RuntimeException('Account not found or deactivated.');
        }
        $this->getLEAccountData();
    }

    /**
     * Creates a new LetsEncrypt account.
     *
     * @param array     $email  The array of strings containing e-mail addresses.
     *
     * @return string|bool   Returns the new account URL when the account was successfully created, false if not.
     */
    private function createLEAccount($email)
    {
        $contact = array_map(function ($addr) {
            return empty($addr) ? '' : (strpos($addr, 'mailto') === false ? 'mailto:' . $addr : $addr);
        }, $email);

        $sign = $this->connector->signRequestJWK(
            ['contact' => $contact, 'termsOfServiceAgreed' => true],
            $this->connector->newAccount
        );
        $post = $this->connector->post($this->connector->newAccount, $sign);
        if (strpos($post['header'], "201 Created") !== false) {
            if (preg_match('~Location: (\S+)~i', $post['header'], $matches)) {
                return trim($matches[1]);
            }
        }
        //@codeCoverageIgnoreStart
        return false;
        //@codeCoverageIgnoreEnd
    }

    /**
     * Gets the LetsEncrypt account URL associated with the stored account keys.
     *
     * @return string|bool   Returns the account URL if it is found, or false when none is found.
     */
    private function getLEAccount()
    {
        $sign = $this->connector->signRequestJWK(['onlyReturnExisting' => true], $this->connector->newAccount);
        $post = $this->connector->post($this->connector->newAccount, $sign);

        if (strpos($post['header'], "200 OK") !== false) {
            if (preg_match('~Location: (\S+)~i', $post['header'], $matches)) {
                return trim($matches[1]);
            }
        }
        return false;
    }

    /**
     * Gets the LetsEncrypt account data from the account URL.
     */
    private function getLEAccountData()
    {
        $sign = $this->connector->signRequestKid(
            ['' => ''],
            $this->connector->accountURL,
            $this->connector->accountURL
        );
        $post = $this->connector->post($this->connector->accountURL, $sign);
        if (strpos($post['header'], "200 OK") !== false) {
            $this->id = isset($post['body']['id']) ? $post['body']['id'] : '';
            $this->key = $post['body']['key'];
            $this->contact = $post['body']['contact'];
            $this->agreement = isset($post['body']['agreement']) ? $post['body']['agreement'] : null;
            $this->initialIp = $post['body']['initialIp'];
            $this->createdAt = $post['body']['createdAt'];
            $this->status = $post['body']['status'];
        } else {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('Account data cannot be found.');
            //@codeCoverageIgnoreEnd
        }
    }

    /**
     * Updates account data. Now just supporting new contact information.
     *
     * @param array     $email  The array of strings containing e-mail adresses.
     *
     * @return boolean  Returns true if the update is successful, false if not.
     */
    public function updateAccount($email)
    {
        $contact = array_map(function ($addr) {
            return empty($addr) ? '' : (strpos($addr, 'mailto') === false ? 'mailto:' . $addr : $addr);
        }, $email);

        $sign = $this->connector->signRequestKid(
            ['contact' => $contact],
            $this->connector->accountURL,
            $this->connector->accountURL
        );
        $post = $this->connector->post($this->connector->accountURL, $sign);
        if ($post['status'] !== 200) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('Unable to update account');
            //@codeCoverageIgnoreEnd
        }

        $this->id = isset($post['body']['id']) ? $post['body']['id'] : '';
        $this->key = $post['body']['key'];
        $this->contact = $post['body']['contact'];
        $this->agreement = isset($post['body']['agreement']) ? $post['body']['agreement'] : '';
        $this->initialIp = $post['body']['initialIp'];
        $this->createdAt = $post['body']['createdAt'];
        $this->status = $post['body']['status'];

        $this->log->notice('Account data updated');
        return true;
    }

    /**
     * Creates new RSA account keys and updates the keys with LetsEncrypt.
     *
     * @return boolean  Returns true if the update is successful, false if not.
     */
    public function changeAccountKeys()
    {
        $new=LEFunctions::RSAgenerateKeys();

        $privateKey = openssl_pkey_get_private($new['private']);
        if ($privateKey === false) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('Failed to open newly generated private key');
            //@codeCoverageIgnoreEnd
        }


        $details = openssl_pkey_get_details($privateKey);
        $innerPayload = ['account' => $this->connector->accountURL, 'newKey' => [
            "kty" => "RSA",
            "n" => LEFunctions::base64UrlSafeEncode($details["rsa"]["n"]),
            "e" => LEFunctions::base64UrlSafeEncode($details["rsa"]["e"])
        ]];
        $outerPayload = $this->connector->signRequestJWK(
            $innerPayload,
            $this->connector->keyChange,
            $new['private']
        );
        $sign = $this->connector->signRequestKid(
            $outerPayload,
            $this->connector->accountURL,
            $this->connector->keyChange
        );
        $post = $this->connector->post($this->connector->keyChange, $sign);
        if ($post['status'] !== 200) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('Unable to post new account keys');
            //@codeCoverageIgnoreEnd
        }

        $this->getLEAccountData();

        $this->storage->setAccountPublicKey($new['public']);
        $this->storage->setAccountPrivateKey($new['private']);

        $this->log->notice('Account keys changed');
        return true;
    }

    /**
     * Deactivates the LetsEncrypt account.
     *
     * @return boolean  Returns true if the deactivation is successful, false if not.
     */
    public function deactivateAccount()
    {
        $sign = $this->connector->signRequestKid(
            ['status' => 'deactivated'],
            $this->connector->accountURL,
            $this->connector->accountURL
        );
        $post = $this->connector->post($this->connector->accountURL, $sign);
        if ($post['status'] !== 200) {
            //@codeCoverageIgnoreStart
            $this->log->error('Account deactivation failed');
            return false;
            //@codeCoverageIgnoreEnd
        }

        $this->connector->accountDeactivated = true;
        $this->log->info('Account deactivated');
        return true;
    }
}
