<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\KeyConverter;

use Assert\Assertion;
use Base64Url\Base64Url;
use function Safe\sprintf;
use function Safe\openssl_x509_read;
use function Safe\openssl_x509_fingerprint;
use function Safe\file_get_contents;
use function Safe\openssl_pkey_get_private;
use function Safe\openssl_pkey_get_public;
use function Safe\preg_replace;
use function Safe\preg_match;
use function Safe\preg_match_all;
use function Safe\base64_decode;
use function Safe\openssl_decrypt;
use function Safe\openssl_x509_export;
use function Safe\json_encode;

/**
 * @internal
 */
class KeyConverter
{
    public static function loadKeyFromCertificateFile(string $file): array
    {
        Assertion::file($file, sprintf('File "%s" does not exist.', $file));
        $content = file_get_contents($file);

        return self::loadKeyFromCertificate($content);
    }

    public static function loadKeyFromCertificate(string $certificate): array
    {
        try {
            $res = openssl_x509_read($certificate);
        } catch (\Throwable $throwable) {
            $certificate = self::convertDerToPem($certificate);
            try {
                $res = openssl_x509_read($certificate);
            } catch (\Throwable $throwable) {
                throw new \InvalidArgumentException('Unable to load the certificate.', $throwable->getCode(), $throwable);
            }
        }

        $values = self::loadKeyFromX509Resource($res);
        \openssl_x509_free($res);

        return $values;
    }

    /**
     * @param resource $res
     */
    public static function loadKeyFromX509Resource($res): array
    {
        $key = openssl_get_publickey($res);
        Assertion::isResource($key, 'Unable to load the certificate');
        $details = openssl_pkey_get_details($key);
        Assertion::isArray($details, 'Unable to load the certificate');
        if (isset($details['key'])) {
            $values = self::loadKeyFromPEM($details['key']);
            openssl_x509_export($res, $out);
            $x5c = preg_replace('#-.*-#', '', $out);
            $x5c = preg_replace('~\R~', PHP_EOL, $x5c);
            $x5c = \trim($x5c);

            $values['x5c'] = [$x5c];
            $values['x5t'] = Base64Url::encode(openssl_x509_fingerprint($res, 'sha1', true));
            $values['x5t#256'] = Base64Url::encode(openssl_x509_fingerprint($res, 'sha256', true));

            return $values;
        }

        throw new \InvalidArgumentException('Unable to load the certificate');
    }

    public static function loadFromKeyFile(string $file, ?string $password = null): array
    {
        $content = file_get_contents($file);

        return self::loadFromKey($content, $password);
    }

    public static function loadFromKey(string $key, ?string $password = null): array
    {
        try {
            return self::loadKeyFromDER($key, $password);
        } catch (\Exception $e) {
            return self::loadKeyFromPEM($key, $password);
        }
    }

    private static function loadKeyFromDER(string $der, ?string $password = null): array
    {
        $pem = self::convertDerToPem($der);

        return self::loadKeyFromPEM($pem, $password);
    }

    private static function loadKeyFromPEM(string $pem, ?string $password = null): array
    {
        if (1 === preg_match('#DEK-Info: (.+),(.+)#', $pem, $matches)) {
            $pem = self::decodePem($pem, $matches, $password);
        }

        self::sanitizePEM($pem);
        try {
            $res = openssl_pkey_get_private($pem);
        } catch (\Throwable $throwable) {
            try {
                $res = openssl_pkey_get_public($pem);
            } catch (\Throwable $throwable) {
                throw new \InvalidArgumentException('Unable to load the key.', $throwable->getCode(), $throwable);
            }
        }

        $details = \openssl_pkey_get_details($res);
        if (!\is_array($details) || !\array_key_exists('type', $details)) {
            throw new \InvalidArgumentException('Unable to get details of the key');
        }

        switch ($details['type']) {
            case OPENSSL_KEYTYPE_EC:
                $ec_key = ECKey::createFromPEM($pem);

                return $ec_key->toArray();
            case OPENSSL_KEYTYPE_RSA:
                 $rsa_key = RSAKey::createFromPEM($pem);
                $rsa_key->optimize();

                 return $rsa_key->toArray();
            default:
                throw new \InvalidArgumentException('Unsupported key type');
        }
    }

    /**
     * This method modifies the PEM to get 64 char lines and fix bug with old OpenSSL versions.
     */
    private static function sanitizePEM(string &$pem): void
    {
        preg_match_all('#(-.*-)#', $pem, $matches, PREG_PATTERN_ORDER);
        $ciphertext = preg_replace('#-.*-|\r|\n| #', '', $pem);

        $pem = $matches[0][0].PHP_EOL;
        $pem .= \chunk_split($ciphertext, 64, PHP_EOL);
        $pem .= $matches[0][1].PHP_EOL;
    }

    /**
     * Be careful! The certificate chain is loaded, but it is NOT VERIFIED by any mean!
     * It is mandatory to verify the root CA or intermediate  CA are trusted.
     * If not done, it may lead to potential security issues.
     */
    public static function loadFromX5C(array $x5c): array
    {
        Assertion::notEmpty($x5c, 'The certificate chain is empty');
        $certificate = null;
        $last_issuer = null;
        $last_subject = null;
        foreach ($x5c as $cert) {
            $current_cert = '-----BEGIN CERTIFICATE-----'.PHP_EOL.$cert.PHP_EOL.'-----END CERTIFICATE-----';
            try {
                $x509 = openssl_x509_read($current_cert);
            } catch (\Throwable $throwable) {
                throw new \InvalidArgumentException('Unable to load the certificate chain', $throwable->getCode(), $throwable);
            }
            $parsed = \openssl_x509_parse($x509);

            \openssl_x509_free($x509);
            if (false === $parsed) {
                throw new \InvalidArgumentException('Unable to load the certificate chain');
            }
            if (null === $last_subject) {
                $last_subject = $parsed['subject'];
                $last_issuer = $parsed['issuer'];
                $certificate = $current_cert;
            } else {
                if (json_encode($last_issuer) === json_encode($parsed['subject'])) {
                    $last_subject = $parsed['subject'];
                    $last_issuer = $parsed['issuer'];
                    continue;
                }
                throw new \InvalidArgumentException('Unable to load the certificate chain');
            }
        }

        return self::loadKeyFromCertificate($certificate);
    }

    /**
     * @param string[] $matches
     */
    private static function decodePem(string $pem, array $matches, ?string $password = null): string
    {
        if (null === $password) {
            throw new \InvalidArgumentException('Password required for encrypted keys.');
        }

        $iv = \pack('H*', \trim($matches[2]));
        $iv_sub = \mb_substr($iv, 0, 8, '8bit');
        $symkey = \pack('H*', \md5($password.$iv_sub));
        $symkey .= \pack('H*', \md5($symkey.$password.$iv_sub));
        $key = preg_replace('#^(?:Proc-Type|DEK-Info): .*#m', '', $pem);
        $ciphertext = base64_decode(preg_replace('#-.*-|\r|\n#', '', $key), true);

        $decoded = openssl_decrypt($ciphertext, \mb_strtolower($matches[1]), $symkey, OPENSSL_RAW_DATA, $iv);
        $number = preg_match_all('#-{5}.*-{5}#', $pem, $result);
        Assertion::eq(2, $number, 'Unable to load the key');

        $pem = $result[0][0].PHP_EOL;
        $pem .= \chunk_split(\base64_encode($decoded), 64);
        $pem .= $result[0][1].PHP_EOL;

        return $pem;
    }

    private static function convertDerToPem(string $der_data): string
    {
        $pem = \chunk_split(\base64_encode($der_data), 64, PHP_EOL);
        $pem = '-----BEGIN CERTIFICATE-----'.PHP_EOL.$pem.'-----END CERTIFICATE-----'.PHP_EOL;

        return $pem;
    }
}
