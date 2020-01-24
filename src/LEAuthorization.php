<?php
namespace Zwartpet\PHPCertificateToolbox;

use Zwartpet\PHPCertificateToolbox\Exception\RuntimeException;
use Psr\Log\LoggerInterface;

/**
 * LetsEncrypt Authorization class, getting LetsEncrypt authorization data associated with a LetsEncrypt Order instance.
 *
 * @author     Youri van Weegberg <youri@yourivw.nl>
 * @copyright  2018 Youri van Weegberg
 * @license    https://opensource.org/licenses/mit-license.php  MIT License
 */
class LEAuthorization
{
    private $connector;

    public $authorizationURL;
    public $identifier;
    public $status;
    public $expires;
    public $challenges;

    /** @var LoggerInterface  */
    private $log;

    /**
     * Initiates the LetsEncrypt Authorization class. Child of a LetsEncrypt Order instance.
     *
     * @param LEConnector $connector The LetsEncrypt Connector instance to use for HTTP requests.
     * @param LoggerInterface $log PSR-3 logger
     * @param string $authorizationURL The URL of the authorization, given by a LetsEncrypt order request.
     */
    public function __construct($connector, LoggerInterface $log, $authorizationURL)
    {
        $this->connector = $connector;
        $this->log = $log;
        $this->authorizationURL = $authorizationURL;

        $get = $this->connector->get($this->authorizationURL);
        if ($get['status'] === 200) {
            $this->identifier = $get['body']['identifier'];
            $this->status = $get['body']['status'];
            $this->expires = $get['body']['expires'];
            $this->challenges = $get['body']['challenges'];
        } else {
            //@codeCoverageIgnoreStart
            $this->log->error("LEAuthorization::__construct cannot find authorization $authorizationURL");
            //@codeCoverageIgnoreEnd
        }
    }

    /**
     * Updates the data associated with the current LetsEncrypt Authorization instance.
     */

    public function updateData()
    {
        $get = $this->connector->get($this->authorizationURL);
        if ($get['status'] === 200) {
            $this->identifier = $get['body']['identifier'];
            $this->status = $get['body']['status'];
            $this->expires = $get['body']['expires'];
            $this->challenges = $get['body']['challenges'];
        } else {
            //@codeCoverageIgnoreStart
            $this->log->error("LEAuthorization::updateData cannot find authorization " . $this->authorizationURL);
            //@codeCoverageIgnoreEnd
        }
    }

    /**
     * Gets the challenge of the given $type for this LetsEncrypt Authorization instance.
     * Throws a Runtime Exception if the given $type is not found in this LetsEncrypt Authorization instance.
     *
     * @param string $type The type of verification.
     *                     Supporting LEOrder::CHALLENGE_TYPE_HTTP and LEOrder::CHALLENGE_TYPE_DNS.
     *
     * @return array Returns an array with the challenge of the requested $type.
     */
    public function getChallenge($type)
    {
        foreach ($this->challenges as $challenge) {
            if ($challenge['type'] == $type) {
                return $challenge;
            }
        }
        //@codeCoverageIgnoreStart
        throw new RuntimeException(
            'No challenge found for type \'' . $type . '\' and identifier \'' . $this->identifier['value'] . '\'.'
        );
        //@codeCoverageIgnoreEnd
    }
}
