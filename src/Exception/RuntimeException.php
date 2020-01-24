<?php

namespace Zwartpet\PHPCertificateToolbox\Exception;

/**
 * Class RuntimeException is fired for conditions which arise only at runtime, e.g. external services being down
 * running out of disc space etc...
 */
class RuntimeException extends \RuntimeException implements LEClientException
{
}
