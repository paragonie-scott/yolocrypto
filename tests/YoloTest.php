<?php
declare(strict_types=1);

use \ParagonIE\YoloCrypto\YoloCrypto;

/**
 * Class YoloTest
 */
class YoloTest extends PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function testEncrypt()
    {
        $crypt = new YoloCrypto();
        $key = $crypt->createNewRandomKey();
        $message = $crypt->encrypt("Test message", $key);
        $this->assertEquals(
            $crypt->decrypt($message, $key),
            "Test message"
        );
    }

    /**
     *
     */
    public function testMACFailure()
    {
        $crypt = new YoloCrypto();
        $key = $crypt->createNewRandomKey();
        $message = $crypt->encrypt("Test message", $key);
        try {
            // Flip a bit
            $message[0] = \chr(
                \ord($message[0]) ^ 80
            );
            $decrypt = $crypt->decrypt($message, $key);
            $this->fail("MAC validation is not working");
        } catch (\Exception $ex) {
            $this->assertEquals(
                'Invalid message authentication code',
                $ex->getMessage()
            );
        }
    }
}
