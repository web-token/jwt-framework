<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker;

use Jose\Component\Core\JWTInterface;
use Jose\Component\Encryption\JWE;
use Jose\Component\Signature\JWS;

/**
 * Class HeaderCheckerManager.
 */
final class HeaderCheckerManager
{
    /**
     * @var HeaderCheckerInterface[]
     */
    private $checkers = [];

    /**
     * HeaderCheckerManager constructor.
     *
     * @param HeaderCheckerInterface[] $checkers
     */
    private function __construct(array $checkers)
    {
        foreach ($checkers as $checker) {
            $this->add($checker);
        }
    }

    /**
     * @param HeaderCheckerInterface[] $checkers
     *
     * @return HeaderCheckerManager
     */
    public static function create(array $checkers): HeaderCheckerManager
    {
        return new self($checkers);
    }

    /**
     * @param HeaderCheckerInterface $checker
     *
     * @return HeaderCheckerManager
     */
    private function add(HeaderCheckerInterface $checker): HeaderCheckerManager
    {
        $header = $checker->supportedHeader();
        if (array_key_exists($header, $this->checkers)) {
            throw new \InvalidArgumentException(sprintf('The header checker "%s" is already supported.', $header));
        }

        $this->checkers[$header] = $checker;

        return $this;
    }

    /**
     * @param JWTInterface $jwt
     * @param int          $component
     */
    public function check(JWTInterface $jwt, int $component)
    {
        switch (true) {
            case $jwt instanceof JWS:
                $this->checkJWS($jwt, $component);

                break;
            case $jwt instanceof JWE:
                $this->checkJWE($jwt, $component);

                break;
            default:
                throw new \InvalidArgumentException('Unsupported argument');
        }
    }

    /**
     * @param JWS $jws
     * @param int $signature
     */
    public function checkJWS(JWS $jws, int $signature)
    {
        if ($signature > $jws->countSignatures()) {
            throw new \InvalidArgumentException('Unknown signature index.');
        }
        $protected = $jws->getSignature($signature)->getProtectedHeaders();
        $headers = $jws->getSignature($signature)->getHeaders();
        $this->checkDuplicatedHeaderParameters($protected, $headers);
        $this->checkHeaders($protected, $headers);
    }

    /**
     * @param JWE $jwe
     * @param int $recipient
     */
    public function checkJWE(JWE $jwe, int $recipient)
    {
        if ($recipient > $jwe->countRecipients()) {
            throw new \InvalidArgumentException('Unknown recipient index.');
        }
        $protected = $jwe->getSharedProtectedHeaders();
        $headers = $jwe->getSharedHeaders();
        $recipient = $jwe->getRecipient($recipient)->getHeaders();
        $this->checkDuplicatedHeaderParameters($protected, $headers);
        $this->checkDuplicatedHeaderParameters($protected, $recipient);
        $this->checkDuplicatedHeaderParameters($headers, $recipient);
        $unprotected = array_merge(
            $headers,
            $recipient
        );
        $this->checkHeaders($protected, $unprotected);
    }

    /**
     * @param array $header1
     * @param array $header2
     */
    private function checkDuplicatedHeaderParameters(array $header1, array $header2)
    {
        $inter = array_intersect_key($header1, $header2);
        if (!empty($inter)) {
            throw new \InvalidArgumentException(sprintf('The header contains duplicated entries: %s.', implode(', ', array_keys($inter))));
        }
    }

    /**
     * @param array $protected
     * @param array $headers
     */
    private function checkHeaders(array $protected, array $headers)
    {
        $checkedHeaders = [];
        foreach ($this->checkers as $header => $checker) {
            if ($checker->protectedHeaderOnly()) {
                if (array_key_exists($header, $protected)) {
                    $checker->checkHeader($protected[$header]);
                    $checkedHeaders[] = $header;
                } else {
                    throw new \InvalidArgumentException(sprintf('The header "%s" must be protected.', $header));
                }
            } else {
                if (array_key_exists($header, $protected)) {
                    $checker->checkHeader($protected[$header]);
                    $checkedHeaders[] = $header;
                } elseif (array_key_exists($header, $headers)) {
                    $checker->checkHeader($headers[$header]);
                    $checkedHeaders[] = $header;
                }
            }
        }

        if (array_key_exists('crit', $protected)) {
            if (!is_array($protected['crit'])) {
                throw new \InvalidArgumentException('The header "crit" mus be a list of header parameters.');
            }
            $diff = array_diff($protected['crit'], $checkedHeaders);
            if (!empty($diff)) {
                throw new \InvalidArgumentException(sprintf('One or more headers are marked as critical, but they are missing or have not been checked: %s.', implode(', ', array_values($diff))));
            }
        } elseif (array_key_exists('crit', $headers)) {
            throw new \InvalidArgumentException('The header parameter "crit" must be protected.');
        }
    }
}
