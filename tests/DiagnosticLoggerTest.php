<?php

namespace Zwartpet\PHPCertificateToolbox;

use PHPUnit\Framework\TestCase;

class DiagnosticLoggerTest extends TestCase
{
    public function testLogger()
    {
        $logger = new DiagnosticLogger();

        $this->assertEquals(0, $logger->countLogs('info'));

        $logger->info('hello {noun}', ['noun' => 'world']);
        $this->assertEquals(1, $logger->countLogs('info'));

        ob_start();
        $logger->dumpConsole();
        $text  = ob_get_clean();
        $this->assertContains('hello world', $text);

        $html=$logger->dumpHTML(false);
        $this->assertContains('hello world', $html);

        $logger->cleanLogs();
        $this->assertEquals(0, $logger->countLogs('info'));
    }
}
