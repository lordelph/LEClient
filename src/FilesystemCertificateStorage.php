<?php

namespace Zwartpet\PHPCertificateToolbox;

use Zwartpet\PHPCertificateToolbox\Exception\RuntimeException;

/**
 * A default storage implementation which stores information in a local filesystem
 * @package Zwartpet\PHPCertificateToolbox
 */
class FilesystemCertificateStorage implements CertificateStorageInterface
{
    private $dir;

    public function __construct($dir = null)
    {
        $this->dir = $dir ?? getcwd().DIRECTORY_SEPARATOR.'certificates';

        if (!is_dir($this->dir)) {
            /** @scrutinizer ignore-unhandled */ @mkdir($this->dir);
        }
        if (!is_writable($this->dir)) {
            throw new RuntimeException("{$this->dir} is not writable");
        }
    }


    /**
     * @inheritdoc
     */
    public function getAccountPublicKey()
    {
        return $this->getMetadata('account.public');
    }

    /**
     * @inheritdoc
     */
    public function setAccountPublicKey($key)
    {
        $this->setMetadata('account.public', $key);
    }

    /**
     * @inheritdoc
     */
    public function getAccountPrivateKey()
    {
        return $this->getMetadata('account.key');
    }

    /**
     * @inheritdoc
     */
    public function setAccountPrivateKey($key)
    {
        $this->setMetadata('account.key', $key);
    }

    private function getDomainKey($domain, $suffix)
    {
        return str_replace('*', 'wildcard', $domain).'.'.$suffix;
    }
    /**
     * @inheritdoc
     */
    public function getCertificate($domain)
    {
        return $this->getMetadata($this->getDomainKey($domain, 'crt'));
    }

    /**
     * @inheritdoc
     */
    public function setCertificate($domain, $certificate)
    {
        $this->setMetadata($this->getDomainKey($domain, 'crt'), $certificate);
    }

    /**
     * @inheritdoc
     */
    public function getFullChainCertificate($domain)
    {
        return $this->getMetadata($this->getDomainKey($domain, 'fullchain.crt'));
    }

    /**
     * @inheritdoc
     */
    public function setFullChainCertificate($domain, $certificate)
    {
        $this->setMetadata($this->getDomainKey($domain, 'fullchain.crt'), $certificate);
    }

    /**
     * @inheritdoc
     */
    public function getPrivateKey($domain)
    {
        return $this->getMetadata($this->getDomainKey($domain, 'key'));
    }

    /**
     * @inheritdoc
     */
    public function setPrivateKey($domain, $key)
    {
        $this->setMetadata($this->getDomainKey($domain, 'key'), $key);
    }

    /**
     * @inheritdoc
     */
    public function getPublicKey($domain)
    {
        return $this->getMetadata($this->getDomainKey($domain, 'public'));
    }

    /**
     * @inheritdoc
     */
    public function setPublicKey($domain, $key)
    {
        $this->setMetadata($this->getDomainKey($domain, 'public'), $key);
    }

    private function getMetadataFilename($key)
    {
        $key=str_replace('*', 'wildcard', $key);
        $file=$this->dir.DIRECTORY_SEPARATOR.$key;
        return $file;
    }
    /**
     * @inheritdoc
     */
    public function getMetadata($key)
    {
        $file=$this->getMetadataFilename($key);
        if (!file_exists($file)) {
            return null;
        }
        return file_get_contents($file);
    }

    /**
     * @inheritdoc
     */
    public function setMetadata($key, $value)
    {
        $file=$this->getMetadataFilename($key);
        if (is_null($value)) {
            //nothing to store, ensure file is removed
            if (file_exists($file)) {
                unlink($file);
            }
        } else {
            file_put_contents($file, $value);
        }
    }

    /**
     * @inheritdoc
     */
    public function hasMetadata($key)
    {
        $file=$this->getMetadataFilename($key);
        return file_exists($file);
    }
}
