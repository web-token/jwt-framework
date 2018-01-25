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

namespace Jose\Component\Checker;

use Jose\Component\Core\JWT;

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
     * @return HeaderChecker[]
     */
    public function getCheckers(): array
    {
        return $this->checkers;
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
     * @param JWT $jwt
     * @param int $component
     */
    public function check(JWT $jwt, int $component)
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
     * @param array $header
     *
     * @throws InvalidHeaderException
     */
    private function checkHeaders(array $protected, array $header)
    {
        $checkedHeaderParameters = [];
        foreach ($this->checkers as $headerParameter => $checker) {
            if ($checker->protectedHeaderOnly()) {
                if (array_key_exists($headerParameter, $protected)) {
                    $checker->checkHeader($protected[$headerParameter]);
                    $checkedHeaderParameters[] = $headerParameter;
                } elseif (array_key_exists($headerParameter, $header)) {
                    throw new InvalidHeaderException(sprintf('The headerParameter "%s" must be protected.', $headerParameter), $headerParameter, $header[$headerParameter]);
                }
            } else {
                if (array_key_exists($headerParameter, $protected)) {
                    $checker->checkHeader($protected[$headerParameter]);
                    $checkedHeaderParameters[] = $headerParameter;
                } elseif (array_key_exists($headerParameter, $header)) {
                    $checker->checkHeader($header[$headerParameter]);
                    $checkedHeaderParameters[] = $headerParameter;
                }
            }
        }
        $this->checkCriticalHeader($protected, $header, $checkedHeaderParameters);
    }

    /**
     * @param array $protected
     * @param array $header
     * @param array $checkedHeaderParameters
     *
     * @throws InvalidHeaderException
     */
    private function checkCriticalHeader(array $protected, array $header, array $checkedHeaderParameters)
    {
        if (array_key_exists('crit', $protected)) {
            if (!is_array($protected['crit'])) {
                throw new InvalidHeaderException('The header "crit" mus be a list of header parameters.', 'crit', $protected['crit']);
            }
            $diff = array_diff($protected['crit'], $checkedHeaderParameters);
            if (!empty($diff)) {
                throw new InvalidHeaderException(sprintf('One or more header parameters are marked as critical, but they are missing or have not been checked: %s.', implode(', ', array_values($diff))), 'crit', $protected['crit']);
            }
        } elseif (array_key_exists('crit', $header)) {
            throw new InvalidHeaderException('The header parameter "crit" must be protected.', 'crit', $header['crit']);
        }
    }
}
