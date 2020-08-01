<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker;

use InvalidArgumentException;

class ClaimCheckerManagerFactory
{
    /**
     * @var ClaimChecker[]
     */
    private $checkers = [];

    /**
     * This method creates a Claim Checker Manager and populate it with the claim checkers found based on the alias.
     * If the alias is not supported, an InvalidArgumentException is thrown.
     *
     * @param string[] $aliases
     */
    public function create(array $aliases): ClaimCheckerManager
    {
        $checkers = [];
        foreach ($aliases as $alias) {
            if (!isset($this->checkers[$alias])) {
                throw new InvalidArgumentException(sprintf('The claim checker with the alias "%s" is not supported.', $alias));
            }
            $checkers[] = $this->checkers[$alias];
        }

        return new ClaimCheckerManager($checkers);
    }

    /**
     * This method adds a claim checker to this factory.
     */
    public function add(string $alias, ClaimChecker $checker): void
    {
        $this->checkers[$alias] = $checker;
    }

    /**
     * Returns all claim checker aliases supported by this factory.
     *
     * @return string[]
     */
    public function aliases(): array
    {
        return array_keys($this->checkers);
    }

    /**
     * Returns all claim checkers supported by this factory.
     *
     * @return ClaimChecker[]
     */
    public function all(): array
    {
        return $this->checkers;
    }
}
