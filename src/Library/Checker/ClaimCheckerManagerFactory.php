<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

use Jose\Component\Core\Util\AliasedRegistry;

/**
 * This class is responsible for creating and managing claim checkers.
 * @see \Jose\Tests\Component\Checker\ClaimCheckerManagerFactoryTest
 */
class ClaimCheckerManagerFactory
{
    /**
     * @use AliasedRegistry<ClaimChecker>
     */
    use AliasedRegistry;

    /**
     * This method creates a Claim Checker Manager and populate it with the claim checkers found based on the alias. If
     * the alias is not supported, an InvalidArgumentException is thrown.
     *
     * @param string[] $aliases
     */
    public function create(array $aliases): ClaimCheckerManager
    {
        return new ClaimCheckerManager($this->select($aliases, 'claim checker'));
    }

    /**
     * This method adds a claim checker to this factory.
     */
    public function add(string $alias, ClaimChecker $checker): void
    {
        $this->register($alias, $checker);
    }
}
