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
     * This method creates a Header Checker Manager and populate it with the header parameter checkers found based on the alias.
     * If the alias is not supported, an InvalidArgumentException is thrown.
     *
     * @param string[] $aliases
     */
    public function create(array $aliases): HeaderCheckerManager
    {
        $checkers = [];
        foreach ($aliases as $alias) {
            if (\array_key_exists($alias, $this->checkers)) {
                $checkers[] = $this->checkers[$alias];
            } else {
                throw new \InvalidArgumentException(\sprintf('The header checker with the alias "%s" is not supported.', $alias));
            }
        }

        return HeaderCheckerManager::create($checkers, $this->tokenTypes);
    }

    /**
     * This method adds a header parameter checker to this factory.
     * The checker is uniquely identified by an alias. This allows the same header parameter checker to be added twice (or more)
     * using several configuration options.
     *
     *
     * @return HeaderCheckerManagerFactory
     */
    public function add(string $alias, HeaderChecker $checker): self
    {
        $this->checkers[$alias] = $checker;

        return $this;
    }

    /**
     * This method adds a token type support to this factory.
     *
     *
     * @return HeaderCheckerManagerFactory
     */
    public function addTokenTypeSupport(TokenTypeSupport $tokenType): self
    {
        $this->tokenTypes[] = $tokenType;

        return $this;
    }

    /**
     * Returns all header parameter checker aliases supported by this factory.
     *
     * @return string[]
     */
    public function aliases(): array
    {
        return \array_keys($this->checkers);
    }

    /**
     * Returns all header parameter checkers supported by this factory.
     *
     * @return HeaderChecker[]
     */
    public function all(): array
    {
        return $this->checkers;
    }
}
