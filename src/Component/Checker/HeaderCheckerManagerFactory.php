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

class HeaderCheckerManagerFactory
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
     * @param string[] $aliases
     *
     * @return HeaderCheckerManager
     */
    public function create(array $aliases): HeaderCheckerManager
    {
        $checkers = [];
        foreach ($aliases as $alias) {
            if (array_key_exists($alias, $this->checkers)) {
                $checkers[] = $this->checkers[$alias];
            } else {
                throw new \InvalidArgumentException(sprintf('The header checker with the alias "%s" is not supported.', $alias));
            }
        }

        return HeaderCheckerManager::create($checkers, $this->tokenTypes);
    }

    /**
     * @param string        $alias
     * @param HeaderChecker $checker
     *
     * @return HeaderCheckerManagerFactory
     */
    public function add(string $alias, HeaderChecker $checker): self
    {
        $this->checkers[$alias] = $checker;

        return $this;
    }

    /**
     * @param TokenTypeSupport $tokenType
     *
     * @return HeaderCheckerManagerFactory
     */
    public function addTokenTypeSupport(TokenTypeSupport $tokenType): self
    {
        $this->tokenTypes[] = $tokenType;

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
     * @return HeaderChecker[]
     */
    public function all(): array
    {
        return $this->checkers;
    }
}
