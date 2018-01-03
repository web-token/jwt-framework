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
 * Class ClaimCheckerManagerFactory.
 */
final class ClaimCheckerManagerFactory
{
    /**
     * @var ClaimChecker[]
     */
    private $checkers = [];

    /**
     * @param string[] $aliases
     *
     * @return ClaimCheckerManager
     */
    public function create(array $aliases): ClaimCheckerManager
    {
        $checkers = [];
        foreach ($aliases as $alias) {
            if (array_key_exists($alias, $this->checkers)) {
                $checkers[] = $this->checkers[$alias];
            } else {
                throw new \InvalidArgumentException(sprintf('The claim checker with the alias "%s" is not supported.', $alias));
            }
        }

        return ClaimCheckerManager::create($checkers);
    }

    /**
     * @param string       $alias
     * @param ClaimChecker $checker
     *
     * @return ClaimCheckerManagerFactory
     */
    public function add(string $alias, ClaimChecker $checker): self
    {
        $this->checkers[$alias] = $checker;

        return $this;
    }

    /**
     * @return string[]
     */
    public function aliases(): array
    {
        return array_keys($this->checkers);
    }

    /**
     * @return ClaimChecker[]
     */
    public function all(): array
    {
        return $this->checkers;
    }
}
