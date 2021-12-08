<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\KeyConverter;

use function array_key_exists;
use function count;
use function extension_loaded;
use InvalidArgumentException;
use function is_array;
use function is_string;
use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;
use const OPENSSL_RAW_DATA;
use OpenSSLCertificate;
use ParagonIE\ConstantTime\Base64UrlSafe;
use const PHP_EOL;
use const PREG_PATTERN_ORDER;
use RuntimeException;
use Throwable;

/**
 * @internal
 */
final class KeyConverter
{
    public static function loadKeyFromCertificateFile(string $file): array
    {
        if (! file_exists($file)) {
            throw new InvalidArgumentException(sprintf('File "%s" does not exist.', $file));
        }
        $content = file_get_contents($file);
        if (! is_string($content)) {
            throw new InvalidArgumentException(sprintf('File "%s" cannot be read.', $file));
        }

        return self::loadKeyFromCertificate($content);
    }

    public static function loadKeyFromCertificate(string $certificate): array
    {
        if (! extension_loaded('openssl')) {
            throw new RuntimeException('Please install the OpenSSL extension');
        }

        try {
            $res = openssl_x509_read($certificate);
            if ($res === false) {
                throw new InvalidArgumentException('Unable to load the certificate.');
            }
        } catch (Throwable) {
            $certificate = self::convertDerToPem($certificate);
            $res = openssl_x509_read($certificate);
        }
        if ($res === false) {
            throw new InvalidArgumentException('Unable to load the certificate.');
        }

        return self::loadKeyFromX509Resource($res);
    }

    public static function loadKeyFromX509Resource(OpenSSLCertificate $res): array
    {
        if (! extension_loaded('openssl')) {
            throw new RuntimeException('Please install the OpenSSL extension');
        }
        $key = openssl_pkey_get_public($res);
        if ($key === false) {
            throw new InvalidArgumentException('Unable to load the certificate.');
        }
        $details = openssl_pkey_get_details($key);
        if (! is_array($details)) {
            throw new InvalidArgumentException('Unable to load the certificate');
        }
        if (isset($details['key'])) {
            $values = self::loadKeyFromPEM($details['key']);
            openssl_x509_export($res, $out);
            $x5c = preg_replace('#-.*-#', '', $out);
            $x5c = preg_replace('~\R~', PHP_EOL, $x5c);
            if (! is_string($x5c)) {
                throw new InvalidArgumentException('Unable to load the certificate');
            }
            $x5c = trim($x5c);

            $x5tsha1 = openssl_x509_fingerprint($res, 'sha1', true);
            $x5tsha256 = openssl_x509_fingerprint($res, 'sha256', true);
            if (! is_string($x5tsha1) || ! is_string($x5tsha256)) {
                throw new InvalidArgumentException('Unable to compute the certificate fingerprint');
            }

            $values['x5c'] = [$x5c];
            $values['x5t'] = Base64UrlSafe::encodeUnpadded($x5tsha1);
            $values['x5t#256'] = Base64UrlSafe::encodeUnpadded($x5tsha256);

            return $values;
        }

        throw new InvalidArgumentException('Unable to load the certificate');
    }

    public static function loadFromKeyFile(string $file, ?string $password = null): array
    {
        $content = file_get_contents($file);
        if (! is_string($content)) {
            throw new InvalidArgumentException('Unable to load the key from the file.');
        }

        return self::loadFromKey($content, $password);
    }

    public static function loadFromKey(string $key, ?string $password = null): array
    {
        try {
            return self::loadKeyFromDER($key, $password);
        } catch (Throwable) {
            return self::loadKeyFromPEM($key, $password);
        }
    }

    /**
     * Be careful! The certificate chain is loaded, but it is NOT VERIFIED by any mean! It is mandatory to verify the
     * root CA or intermediate  CA are trusted. If not done, it may lead to potential security issues.
     */
    public static function loadFromX5C(array $x5c): array
    {
        if (count($x5c) === 0) {
            throw new InvalidArgumentException('The certificate chain is empty');
        }
        foreach ($x5c as $id => $cert) {
            $x5c[$id] = '-----BEGIN CERTIFICATE-----' . PHP_EOL . chunk_split(
                $cert,
                64,
                PHP_EOL
            ) . '-----END CERTIFICATE-----';
            $x509 = openssl_x509_read($x5c[$id]);
            if ($x509 === false) {
                throw new InvalidArgumentException('Unable to load the certificate chain');
            }
            $parsed = openssl_x509_parse($x509);
            if ($parsed === false) {
                throw new InvalidArgumentException('Unable to load the certificate chain');
            }
        }

        return self::loadKeyFromCertificate(reset($x5c));
    }

    private static function loadKeyFromDER(string $der, ?string $password = null): array
    {
        $pem = self::convertDerToPem($der);

        return self::loadKeyFromPEM($pem, $password);
    }

    private static function loadKeyFromPEM(string $pem, ?string $password = null): array
    {
        if (preg_match('#DEK-Info: (.+),(.+)#', $pem, $matches) === 1) {
            $pem = self::decodePem($pem, $matches, $password);
        }

        if (! extension_loaded('openssl')) {
            throw new RuntimeException('Please install the OpenSSL extension');
        }

        if (preg_match('#BEGIN ENCRYPTED PRIVATE KEY(.+)(.+)#', $pem) === 1) {
            $decrypted = openssl_pkey_get_private($pem, $password);
            if ($decrypted === false) {
                throw new InvalidArgumentException('Unable to decrypt the key.');
            }
            openssl_pkey_export($decrypted, $pem);
        }

        self::sanitizePEM($pem);
        $res = openssl_pkey_get_private($pem);
        if ($res === false) {
            $res = openssl_pkey_get_public($pem);
        }
        if ($res === false) {
            throw new InvalidArgumentException('Unable to load the key.');
        }

        $details = openssl_pkey_get_details($res);
        if (! is_array($details) || ! array_key_exists('type', $details)) {
            throw new InvalidArgumentException('Unable to get details of the key');
        }

        switch ($details['type']) {
            case OPENSSL_KEYTYPE_EC:
                $ec_key = ECKey::createFromPEM($pem);

                return $ec_key->toArray();

            case OPENSSL_KEYTYPE_RSA:
                $rsa_key = RSAKey::createFromPEM($pem);

                return $rsa_key->toArray();

            default:
                throw new InvalidArgumentException('Unsupported key type');
        }
    }

    /**
     * This method modifies the PEM to get 64 char lines and fix bug with old OpenSSL versions.
     */
    private static function sanitizePEM(string &$pem): void
    {
        preg_match_all('#(-.*-)#', $pem, $matches, PREG_PATTERN_ORDER);
        $ciphertext = preg_replace('#-.*-|\r|\n| #', '', $pem);

        $pem = $matches[0][0] . PHP_EOL;
        $pem .= chunk_split($ciphertext, 64, PHP_EOL);
        $pem .= $matches[0][1] . PHP_EOL;
    }

    /**
     * @param string[] $matches
     */
    private static function decodePem(string $pem, array $matches, ?string $password = null): string
    {
        if ($password === null) {
            throw new InvalidArgumentException('Password required for encrypted keys.');
        }

        $iv = pack('H*', trim($matches[2]));
        $iv_sub = mb_substr($iv, 0, 8, '8bit');
        $symkey = pack('H*', md5($password . $iv_sub));
        $symkey .= pack('H*', md5($symkey . $password . $iv_sub));
        $key = preg_replace('#^(?:Proc-Type|DEK-Info): .*#m', '', $pem);
        $ciphertext = base64_decode(preg_replace('#-.*-|\r|\n#', '', $key), true);
        if (! is_string($ciphertext)) {
            throw new InvalidArgumentException('Unable to encode the data.');
        }

        $decoded = openssl_decrypt($ciphertext, mb_strtolower($matches[1]), $symkey, OPENSSL_RAW_DATA, $iv);
        if ($decoded === false) {
            throw new RuntimeException('Unable to decrypt the key');
        }
        $number = preg_match_all('#-{5}.*-{5}#', $pem, $result);
        if ($number !== 2) {
            throw new InvalidArgumentException('Unable to load the key');
        }

        $pem = $result[0][0] . PHP_EOL;
        $pem .= chunk_split(base64_encode($decoded), 64);
        $pem .= $result[0][1] . PHP_EOL;

        return $pem;
    }

    private static function convertDerToPem(string $der_data): string
    {
        $pem = chunk_split(base64_encode($der_data), 64, PHP_EOL);

        return '-----BEGIN CERTIFICATE-----' . PHP_EOL . $pem . '-----END CERTIFICATE-----' . PHP_EOL;
    }
}
