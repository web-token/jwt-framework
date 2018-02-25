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

class ClaimCheckerManager
{
    /**
     * @var ClaimChecker[]
     */
    private $checkers = [];

    /**
     * ClaimCheckerManager constructor.
     *
     * @param ClaimChecker[] $checkers
     */
    private function __construct(array $checkers)
    {
        foreach ($checkers as $checker) {
            $this->add($checker);
        }
    }

    /**
     * @param ClaimChecker[] $checkers
     *
     * @return ClaimCheckerManager
     */
    public static function create(array $checkers): self
    {
        return new self($checkers);
    }

    /**
     * @param ClaimChecker $checker
     *
     * @return ClaimCheckerManager
     */
    private function add(ClaimChecker $checker): self
    {
        $claim = $checker->supportedClaim();
        $this->checkers[$claim] = $checker;

        return $this;
    }

    /**
     * @return ClaimChecker[]
     */
    public function getCheckers(): array
    {
        return $this->checkers;
    }

    /**
     * @param array    $claims
     * @param string[] $mandatoryClaims
     *
     * @throws InvalidClaimException
     * @throws MissingMandatoryClaimException
     *
     * @return array
     */
    public function check(array $claims, array $mandatoryClaims = []): array
    {
        $this->checkMandatoryClaims($mandatoryClaims, $claims);
        $checkedClaims = [];
        foreach ($this->checkers as $claim => $checker) {
            if (array_key_exists($claim, $claims)) {
                $checker->checkClaim($claims[$claim]);
                $checkedClaims[$claim] = $claims[$claim];
            }
        }

        return $checkedClaims;
    }

    /**
     * @param string[] $mandatoryClaims
     * @param array    $claims
     *
     * @throws MissingMandatoryClaimException
     */
    private function checkMandatoryClaims(array $mandatoryClaims, array $claims)
    {
        if (empty($mandatoryClaims)) {
            return;
        }
        $diff = array_keys(array_diff_key(array_flip($mandatoryClaims), $claims));

        if (!empty($diff)) {
            throw new MissingMandatoryClaimException(sprintf('The following claims are mandatory: %s.', implode(', ', $diff)), $diff);
        }
    }
}
