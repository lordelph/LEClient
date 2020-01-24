<?php

namespace Zwartpet\PHPCertificateToolbox;

/**
 * In real world use, we want to sleep in between various actions. For testing, not so much.
 * So, we make it possible to inject a less sleepy service for testing
 *
 * @codeCoverageIgnore
 */
class Sleep
{
    public function for($seconds)
    {
        sleep($seconds);
    }
}
