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

/**
 * This manager handles as many claim checkers as needed.
 */
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
     * This method creates the ClaimCheckerManager.
     * The argument is a list of claim checkers objects.
     *
     * @param ClaimChecker[] $checkers
     *
     * @return ClaimCheckerManager
     */
    public static function create(array $checkers): self
    {
        return new self($checkers);
    }

    /**
     * @return ClaimCheckerManager
     */
    private function add(ClaimChecker $checker): self
    {
        $claim = $checker->supportedClaim();
        $this->checkers[$claim] = $checker;

        return $this;
    }

    /**
     * This method returns all checkers handled by this manager.
     *
     * @return ClaimChecker[]
     */
    public function getCheckers(): array
    {
        return $this->checkers;
    }

    /**
     * This method checks all the claims passed as argument.
     * All claims are checked against the claim checkers.
     * If one fails, the InvalidClaimException is thrown.
     *
     * This method returns an array with all checked claims.
     * It is up to the implementor to decide use the claims that have not been checked.
     *
     * @param string[] $mandatoryClaims
     *
     * @throws InvalidClaimException
     * @throws MissingMandatoryClaimException
     */
    public function check(array $claims, array $mandatoryClaims = []): array
    {
        $this->checkMandatoryClaims($mandatoryClaims, $claims);
        $checkedClaims = [];
        foreach ($this->checkers as $claim => $checker) {
            if (\array_key_exists($claim, $claims)) {
                $checker->checkClaim($claims[$claim]);
                $checkedClaims[$claim] = $claims[$claim];
            }
        }

        return $checkedClaims;
    }

    /**
     * @param string[] $mandatoryClaims
     *
     * @throws MissingMandatoryClaimException
     */
    private function checkMandatoryClaims(array $mandatoryClaims, array $claims)
    {
        if (empty($mandatoryClaims)) {
            return;
        }
        $diff = \array_keys(\array_diff_key(\array_flip($mandatoryClaims), $claims));

        if (!empty($diff)) {
            throw new MissingMandatoryClaimException(\sprintf('The following claims are mandatory: %s.', \implode(', ', $diff)), $diff);
        }
    }
}
