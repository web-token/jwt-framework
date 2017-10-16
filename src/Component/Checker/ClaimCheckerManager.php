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

/**
 * Class ClaimCheckerManager.
 */
final class ClaimCheckerManager
{
    /**
     * @var ClaimCheckerInterface[]
     */
    private $checkers = [];

    /**
     * ClaimCheckerManager constructor.
     *
     * @param ClaimCheckerInterface[] $checkers
     */
    private function __construct(array $checkers)
    {
        foreach ($checkers as $checker) {
            $this->add($checker);
        }
    }

    /**
     * @param ClaimCheckerInterface[] $checkers
     *
     * @return ClaimCheckerManager
     */
    public static function create(array $checkers): ClaimCheckerManager
    {
        return new self($checkers);
    }

    /**
     * @param ClaimCheckerInterface $checker
     *
     * @return ClaimCheckerManager
     */
    private function add(ClaimCheckerInterface $checker): ClaimCheckerManager
    {
        $claim = $checker->supportedClaim();
        if (array_key_exists($claim, $this->checkers)) {
            throw new \InvalidArgumentException(sprintf('The claim checker "%s" is already supported.', $claim));
        }

        $this->checkers[$claim] = $checker;

        return $this;
    }

    /**
     * @param array $claims
     *
     * @return array
     */
    public function check(array $claims): array
    {
        foreach ($this->checkers as $claim => $checker) {
            if (array_key_exists($claim, $claims)) {
                $checker->checkClaim($claims[$claim]);
            }
        }

        return $claims;
    }
}
