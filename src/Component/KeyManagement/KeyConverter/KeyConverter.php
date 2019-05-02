<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\KeyConverter;

use Base64Url\Base64Url;

/**
 * @internal
 */
class KeyConverter
{
    /**
     * @throws \InvalidArgumentException
     */
    public static function loadKeyFromCertificateFile(string $file): array
    {
        if (!\file_exists($file)) {
            throw new \InvalidArgumentException(\sprintf('File "%s" does not exist.', $file));
        }
        $content = \file_get_contents($file);

        return self::loadKeyFromCertificate($content);
    }

    /**
     * @throws \InvalidArgumentException
     */
    public static function loadKeyFromCertificate(string $certificate): array
    {
        try {
            $res = \openssl_x509_read($certificate);
        } catch (\Exception $e) {
            $certificate = self::convertDerToPem($certificate);
            $res = \openssl_x509_read($certificate);
        }
        if (false === $res) {
            throw new \InvalidArgumentException('Unable to load the certificate.');
        }

        $values = self::loadKeyFromX509Resource($res);
        \openssl_x509_free($res);

        return $values;
    }

    /**
     * @param resource $res
     *
     * @throws \Exception
     */
    public static function loadKeyFromX509Resource($res): array
    {
        $key = \openssl_get_publickey($res);

        $details = \openssl_pkey_get_details($key);
        if (isset($details['key'])) {
            $values = self::loadKeyFromPEM($details['key']);
            \openssl_x509_export($res, $out);
            $x5c = \preg_replace('#-.*-#', '', $out);
            $x5c = \preg_replace('~\R~', PHP_EOL, $x5c);
            $x5c = \trim($x5c);
            $values['x5c'] = [$x5c];

            $values['x5t'] = Base64Url::encode(\openssl_x509_fingerprint($res, 'sha1', true));
            $values['x5t#256'] = Base64Url::encode(\openssl_x509_fingerprint($res, 'sha256', true));

            return $values;
        }

        throw new \InvalidArgumentException('Unable to load the certificate');
    }

    /**
     * @throws \Exception
     */
    public static function loadFromKeyFile(string $file, ?string $password = null): array
    {
        $content = \file_get_contents($file);

        return self::loadFromKey($content, $password);
    }

    /**
     * @throws \Exception
     */
    public static function loadFromKey(string $key, ?string $password = null): array
    {
        try {
            return self::loadKeyFromDER($key, $password);
        } catch (\Exception $e) {
            return self::loadKeyFromPEM($key, $password);
        }
    }

    /**
     * @throws \Exception
     */
    private static function loadKeyFromDER(string $der, ?string $password = null): array
    {
        $pem = self::convertDerToPem($der);

        return self::loadKeyFromPEM($pem, $password);
    }

    /**
     * @throws \Exception
     */
    private static function loadKeyFromPEM(string $pem, ?string $password = null): array
    {
        if (\preg_match('#DEK-Info: (.+),(.+)#', $pem, $matches)) {
            $pem = self::decodePem($pem, $matches, $password);
        }

        self::sanitizePEM($pem);

        $res = \openssl_pkey_get_private($pem);
        if (false === $res) {
            $res = \openssl_pkey_get_public($pem);
        }
        if (false === $res) {
            throw new \InvalidArgumentException('Unable to load the key.');
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
    private static function sanitizePEM(string &$pem)
    {
        \preg_match_all('#(-.*-)#', $pem, $matches, PREG_PATTERN_ORDER);
        $ciphertext = \preg_replace('#-.*-|\r|\n| #', '', $pem);

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
        $certificate = null;
        $last_issuer = null;
        $last_subject = null;
        foreach ($x5c as $cert) {
            $current_cert = '-----BEGIN CERTIFICATE-----'.PHP_EOL.\chunk_split($cert,64,PHP_EOL).'-----END CERTIFICATE-----';
            $x509 = \openssl_x509_read($current_cert);
            if (false === $x509) {
                $last_issuer = null;
                $last_subject = null;

                break;
            }
            $parsed = \openssl_x509_parse($x509);

            \openssl_x509_free($x509);
            if (false === $parsed) {
                $last_issuer = null;
                $last_subject = null;

                break;
            }
            if (null === $last_subject) {
                $last_subject = $parsed['subject'];
                $last_issuer = $parsed['issuer'];
                $certificate = $current_cert;
            } else {
                if (\json_encode($last_issuer) === \json_encode($parsed['subject'])) {
                    $last_subject = $parsed['subject'];
                    $last_issuer = $parsed['issuer'];
                } else {
                    $last_issuer = null;
                    $last_subject = null;

                    break;
                }
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
        $key = \preg_replace('#^(?:Proc-Type|DEK-Info): .*#m', '', $pem);
        $ciphertext = \base64_decode(\preg_replace('#-.*-|\r|\n#', '', $key), true);

        $decoded = \openssl_decrypt($ciphertext, \mb_strtolower($matches[1]), $symkey, OPENSSL_RAW_DATA, $iv);
        if (!\is_string($decoded)) {
            throw new \InvalidArgumentException('Incorrect password. Key decryption failed.');
        }

        $number = \preg_match_all('#-{5}.*-{5}#', $pem, $result);
        if (2 !== $number) {
            throw new \InvalidArgumentException('Unable to load the key');
        }

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
