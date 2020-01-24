<?php

namespace Zwartpet\PHPCertificateToolbox;

use Psr\Log\AbstractLogger;

/**
 * A PSR-3 logger you can use for troubleshooting (note you can use any PSR-3 compatible logger)
 *
 * This retains logs in memory and you can dump them when it suits you. In a console app
 * use dumpConsole() which will output colour-coded logs (pass false to disable this). In a web app,
 * you can use dumpHTML() to output or obtain an HTML rendering of the logs.
 */
class DiagnosticLogger extends AbstractLogger
{
    private $logs = [];

    public function log($level, $message, array $context = [])
    {
        $this->logs[] = [$level, $message, $context];
    }

    public function dumpConsole($useColours = true)
    {
        $colours = [
            'alert' => "\e[97m\e[41m",
            'emergency' => "\e[97m\e[41m",
            'critical' => "\e[97m\e[41m",
            'error' => "\e[91m",
            'warning' => "\e[93m",
            'notice' => "\e[96m",
            'info' => "\e[92m",
            'debug' => "\e[2m",
        ];

        $reset = $useColours ? "\e[0m" : '';

        foreach ($this->logs as $log) {
            $col = $useColours ? $colours[$log[0]] : '';
            echo $col . $log[0] . ': ' . $this->interpolateMessage($log[1], $log[2]) . $reset . "\n";
        }
    }

    public function dumpHTML($echo = true)
    {
        $html = '<div class="liblynx-diagnostic-log">';
        $html .= '<table class="table"><thead><tr><th>Level</th><th>Message</th></tr></thead><tbody>';
        $html .= "\n";

        foreach ($this->logs as $log) {
            $html .= '<tr class="level-' . $log[0] . '"><td>' . $log[0] . '</td><td>' .
                htmlentities($this->interpolateMessage($log[1], $log[2])) .
                "</td></tr>\n";
        }
        $html .= "</tbody></table></div>\n";

        if ($echo) {
            echo $html; //@codeCoverageIgnore
        }
        return $html;
    }

    /**
     * Interpolates context values into the message placeholders.
     */
    private function interpolateMessage($message, array $context = [])
    {
        // build a replacement array with braces around the context keys
        $replace = [];
        foreach ($context as $key => $val) {
            // check that the value can be casted to string
            if (!is_array($val) && (!is_object($val) || method_exists($val, '__toString'))) {
                $replace['{' . $key . '}'] = $val;
            }
        }

        // interpolate replacement values into the message and return
        return strtr($message, $replace);
    }


    public function cleanLogs()
    {
        $logs = $this->logs;
        $this->logs = [];

        return $logs;
    }

    public function countLogs($level)
    {
        $count = 0;
        foreach ($this->logs as $log) {
            if ($log[0] == $level) {
                $count++;
            }
        }
        return $count;
    }
}
