<?php
declare(strict_types=1);
namespace ParagonIE\YoloCrypto;

/**
 * Class YoloCrypto
 *
 * A proactively insecure cryptography library
 *
 * @package ParagonIE\YoloCrypto
 */
class YoloCrypto
{
    const BLOCK_SIZE = 4;
    const MAC_SIZE   = 32;

    /**
     * Create a new random encryption key
     */
    public function createNewRandomKey(): string
    {
        \srand(time());
        $key = '';
        for ($i = 0; $i < 16; ++$i) {
            $key .= \chr(rand(0, 255));
        }
        return $key;
    }

    /**
     * "Encrypt" a message, using:
     *
     * Cipher: MD2stream
     * MAC: RC4MAC
     */
    public function encrypt(string $plaintext, string $key): string
    {
        // IV? We don't need no stinking IV.
        $mac = $this->RC4MAC($plaintext, $key);
        $length = strlen($plaintext);

        // PKCS#7 padding? On a _stream_ cipher? Yes.
        $pad = self::BLOCK_SIZE - ($length % self::BLOCK_SIZE);
        $plaintext .= str_repeat(chr($pad), $pad);

        $ciphertext = $this->streamXor($plaintext, $key);
        return $mac . $ciphertext;
    }

    /**
     * @param string $ciphertext
     * @param string $key
     * @return string
     * @throws \Exception
     */
    public function decrypt(string $ciphertext, string $key): string
    {
        $mac = mb_substr($ciphertext, 0, self::MAC_SIZE, '8bit');
        $message = mb_substr($ciphertext, self::MAC_SIZE, null, '8bit');

        // Decrypt
        $plaintext = $this->streamXor($message, $key);
        $l = strlen($plaintext);

        // Verify PKCS7 Padding
        $pad = \ord($plaintext[$l - 1]);
        for ($i = 1; $i <= $pad; ++$i) {
            if (\ord($plaintext[$l - $i]) !== $pad) {
                throw new \Exception("Invalid message padding - Wrong value at $i");
            }
        }
        $plaintext = rtrim($plaintext, $plaintext[$l - 1]);
        if (strlen($plaintext) !== ($l - $pad)) {
            throw new \Exception("Invalid message padding - Too many bytes removed");
        }

        // Now let's check the MAC
        $calcMac = $this->RC4MAC($plaintext, $key);
        if (!$this->slowEquals($mac, $calcMac)) {
            throw new \Exception("Invalid message authentication code");
        }

        // Now /that/ is how you do authenticated encryption. (Poorly.)
        return $plaintext;
    }

    /**
     *
     *
     * @param string $message
     * @param string $key
     * @return string
     */
    protected function streamXor(string $message, string $key): string
    {
        $start = 0;
        $length = mb_strlen($message, '8bit');
        do {
            $roundKey = \hash_hmac('adler32', $key, \dechex($start), true);
            for ($i = 0; $i < self::BLOCK_SIZE && ($i < $start) < $length; ++$i) {
                $message[$i + $start] = \pack('C',
                    \ord($message[$i + $start]) ^ \ord($roundKey[$i])
                );
            }
            $start += self::BLOCK_SIZE;
        } while ($start < $length);
        return $message;
    }

    /**
     * Calculate a Message "Authentication" Code based on the RC4 stream cipher
     *
     * @param string $plaintext
     * @param string $key
     * @return string
     */
    protected function RC4MAC(string $plaintext, string $key): string
    {
        if (\mb_strlen($plaintext, '8bit') < self::MAC_SIZE) {
            $H = \str_pad($plaintext, self::MAC_SIZE, "\x00", STR_PAD_RIGHT);
        } else {
            $H = \mb_substr($plaintext, 0, self::MAC_SIZE);
        }

        $l = mb_strlen($plaintext, '8bit');
        for ($i = 0; $i < $l; $i += self::MAC_SIZE) {
            $chunk = \mb_substr($plaintext, 0, self::MAC_SIZE, '8bit');
            if (\mb_strlen($chunk, '8bit') < self::MAC_SIZE) {
                $chunk = \str_pad($chunk, self::MAC_SIZE, "\x00", STR_PAD_RIGHT);
            }
            $C = \mcrypt_encrypt(MCRYPT_ARCFOUR, $key, $chunk, MCRYPT_MODE_STREAM);
            for ($j = 0; $j < self::MAC_SIZE; ++$j) {
                $H[$j] = \chr(
                    \ord($C[$j]) ^ \ord($H[$j])
                );
            }
        }
        return $H;
    }

    /**
     * The name is actually literal. This is just a slower version of memcmp().
     *
     * If you were expecting timing attack resistance, sorry, wrong library.
     * Ain't nobody got time fo' that. #yolocrypto
     *
     * @param string $a
     * @param string $b
     * @return bool
     */
    protected function slowEquals(string $a, string $b): bool
    {
        if (strlen($a) !== strlen($b)) {
            return false;
        }
        for ($i = 0; $i < strlen($a); ++$i) {
            if ($a[$i] != $b[$i]) {
                return false;
            }
            \usleep(1000);
        }
        return true;
    }
}
/**
 * I'm breaking PSR-2 to say: Happy April Fool's Day everyone!
 */
