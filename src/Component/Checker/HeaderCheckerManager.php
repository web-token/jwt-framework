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

/**
 * Class HeaderCheckerManager.
 */
final class HeaderCheckerManager
{
    /**
     * @var HeaderChecker[]
     */
    private $checkers = [];

    /**
     * @var TokenTypeSupport[]
     */
    private $tokenTypes = [];

    /**
     * HeaderCheckerManager constructor.
     *
     * @param HeaderChecker[]    $checkers
     * @param TokenTypeSupport[] $tokenTypes
     */
    private function __construct(array $checkers, array $tokenTypes)
    {
        foreach ($checkers as $checker) {
            $this->add($checker);
        }
        foreach ($tokenTypes as $tokenType) {
            $this->addTokenTypeSupport($tokenType);
        }
    }

    /**
     * @param HeaderChecker[]    $checkers
     * @param TokenTypeSupport[] $tokenTypes
     *
     * @return HeaderCheckerManager
     */
    public static function create(array $checkers, array $tokenTypes): self
    {
        return new self($checkers, $tokenTypes);
    }

    /**
     * @param TokenTypeSupport $tokenType
     *
     * @return HeaderCheckerManager
     */
    private function addTokenTypeSupport(TokenTypeSupport $tokenType): self
    {
        $this->tokenTypes[] = $tokenType;

        return $this;
    }

    /**
     * @param HeaderChecker $checker
     *
     * @return HeaderCheckerManager
     */
    private function add(HeaderChecker $checker): self
    {
        $header = $checker->supportedHeader();
        $this->checkers[$header] = $checker;

        return $this;
    }

    /**
     * @param JWTInterface $jwt
     * @param int          $component
     */
    public function check(JWTInterface $jwt, int $component)
    {
        foreach ($this->tokenTypes as $tokenType) {
            if ($tokenType->supports($jwt)) {
                $protected = [];
                $unprotected = [];
                $tokenType->retrieveTokenHeaders($jwt, $component, $protected, $unprotected);
                $this->checkDuplicatedHeaderParameters($protected, $unprotected);
                $this->checkHeaders($protected, $unprotected);

                return;
            }
        }

        throw new \InvalidArgumentException('Unsupported token type.');
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
                } elseif (array_key_exists($header, $headers)) {
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
        $this->checkCriticalHeader($protected, $headers, $checkedHeaders);
    }

    /**
     * @param array $protected
     * @param array $headers
     * @param array $checkedHeaders
     */
    private function checkCriticalHeader(array $protected, array $headers, array $checkedHeaders)
    {
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
