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

class HeaderCheckerManager
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
     * This method creates the HeaderCheckerManager.
     * The first argument is a list of header parameter checkers objects.
     * The second argument is a list of token type support objects.
     * It is recommended to support only one token type per manager.
     *
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
     * This method returns all checkers handled by this manager.
     *
     * @return HeaderChecker[]
     */
    public function getCheckers(): array
    {
        return $this->checkers;
    }

    /**
     * @return HeaderCheckerManager
     */
    private function addTokenTypeSupport(TokenTypeSupport $tokenType): self
    {
        $this->tokenTypes[] = $tokenType;

        return $this;
    }

    /**
     * @return HeaderCheckerManager
     */
    private function add(HeaderChecker $checker): self
    {
        $header = $checker->supportedHeader();
        $this->checkers[$header] = $checker;

        return $this;
    }

    /**
     * This method checks all the header parameters passed as argument.
     * All header parameters are checked against the header parameter checkers.
     * If one fails, the InvalidHeaderException is thrown.
     *
     * @param string[] $mandatoryHeaderParameters
     *
     * @throws InvalidHeaderException
     * @throws MissingMandatoryHeaderParameterException
     */
    public function check(JWT $jwt, int $index, array $mandatoryHeaderParameters = [])
    {
        foreach ($this->tokenTypes as $tokenType) {
            if ($tokenType->supports($jwt)) {
                $protected = [];
                $unprotected = [];
                $tokenType->retrieveTokenHeaders($jwt, $index, $protected, $unprotected);
                $this->checkDuplicatedHeaderParameters($protected, $unprotected);
                $this->checkMandatoryHeaderParameters($mandatoryHeaderParameters, $protected, $unprotected);
                $this->checkHeaders($protected, $unprotected);

                return;
            }
        }

        throw new \InvalidArgumentException('Unsupported token type.');
    }

    private function checkDuplicatedHeaderParameters(array $header1, array $header2)
    {
        $inter = \array_intersect_key($header1, $header2);
        if (!empty($inter)) {
            throw new \InvalidArgumentException(\sprintf('The header contains duplicated entries: %s.', \implode(', ', \array_keys($inter))));
        }
    }

    /**
     * @param string[] $mandatoryHeaderParameters
     *
     * @throws MissingMandatoryHeaderParameterException
     */
    private function checkMandatoryHeaderParameters(array $mandatoryHeaderParameters, array $protected, array $unprotected)
    {
        if (empty($mandatoryHeaderParameters)) {
            return;
        }
        $diff = \array_keys(\array_diff_key(\array_flip($mandatoryHeaderParameters), \array_merge($protected, $unprotected)));

        if (!empty($diff)) {
            throw new MissingMandatoryHeaderParameterException(\sprintf('The following header parameters are mandatory: %s.', \implode(', ', $diff)), $diff);
        }
    }

    /**
     * @throws InvalidHeaderException
     */
    private function checkHeaders(array $protected, array $header)
    {
        $checkedHeaderParameters = [];
        foreach ($this->checkers as $headerParameter => $checker) {
            if ($checker->protectedHeaderOnly()) {
                if (\array_key_exists($headerParameter, $protected)) {
                    $checker->checkHeader($protected[$headerParameter]);
                    $checkedHeaderParameters[] = $headerParameter;
                } elseif (\array_key_exists($headerParameter, $header)) {
                    throw new InvalidHeaderException(\sprintf('The headerParameter "%s" must be protected.', $headerParameter), $headerParameter, $header[$headerParameter]);
                }
            } else {
                if (\array_key_exists($headerParameter, $protected)) {
                    $checker->checkHeader($protected[$headerParameter]);
                    $checkedHeaderParameters[] = $headerParameter;
                } elseif (\array_key_exists($headerParameter, $header)) {
                    $checker->checkHeader($header[$headerParameter]);
                    $checkedHeaderParameters[] = $headerParameter;
                }
            }
        }
        $this->checkCriticalHeader($protected, $header, $checkedHeaderParameters);
    }

    /**
     * @throws InvalidHeaderException
     */
    private function checkCriticalHeader(array $protected, array $header, array $checkedHeaderParameters)
    {
        if (\array_key_exists('crit', $protected)) {
            if (!\is_array($protected['crit'])) {
                throw new InvalidHeaderException('The header "crit" mus be a list of header parameters.', 'crit', $protected['crit']);
            }
            $diff = \array_diff($protected['crit'], $checkedHeaderParameters);
            if (!empty($diff)) {
                throw new InvalidHeaderException(\sprintf('One or more header parameters are marked as critical, but they are missing or have not been checked: %s.', \implode(', ', \array_values($diff))), 'crit', $protected['crit']);
            }
        } elseif (\array_key_exists('crit', $header)) {
            throw new InvalidHeaderException('The header parameter "crit" must be protected.', 'crit', $header['crit']);
        }
    }
}
