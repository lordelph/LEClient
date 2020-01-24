<?php

namespace Zwartpet\PHPCertificateToolbox;

use Psr\Http\Message\ResponseInterface;

class TestResponseGenerator
{
    /**
     * Given an HTTP response, this can dump a function which will generate a Response object which can
     * be used during testing to simulate that response
     *
     * @param $method
     * @param $url
     * @param ResponseInterface $response
     * @codeCoverageIgnore
     */
    public static function dumpTestSimulation($method, $url, ResponseInterface $response)
    {
        static $count = 0;
        $count++;

        echo "/**\n";
        echo " * Simulate response for $method $url\n";
        echo " */\n";
        echo "protected function getAcmeResponse{$count}()\n";
        echo "{\n";

        echo "    \$date = new \DateTime;\n";
        echo "    \$now = \$date->format('D, j M Y H:i:s e');\n";

        //store body as heredoc
        $body = $response->getBody();
        if (strlen($body)) {
            $body = preg_replace('/^/m', '        ', $response->getBody());
            echo "    \$body = <<<JSON\n";
            echo $body;
            echo "\nJSON;\n";
        }
        echo "    \$body=trim(\$body);\n\n";

        //dump the header array, replacing dates with a current date
        echo "    \$headers=[\n";
        $headers = $response->getHeaders();
        foreach ($headers as $name => $values) {
            //most headers are single valued
            if (count($values) == 1) {
                $value = var_export($values[0], true);
            } else {
                $value = var_export($values, true);
            }

            //give date-related headers something current when testing
            if (in_array($name, ['Expires', 'Date'])) {
                $value = '$now';
            }

            //ensure content length is correct for our simulated body
            if ($name == 'Content-Length') {
                $value = 'strlen($body)';
            }

            echo "        '$name' => " . $value . ",\n";
        }
        echo "    ];\n";

        $status=$response->getStatusCode();

        echo "    return new Response($status, \$headers, \$body);\n";
        echo "}\n\n";
    }
}
