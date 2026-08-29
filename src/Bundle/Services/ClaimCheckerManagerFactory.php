<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Core\Util\AliasedRegistry;
use Psr\EventDispatcher\EventDispatcherInterface;

final class ClaimCheckerManagerFactory
{
    /**
     * @use AliasedRegistry<ClaimChecker>
     */
    use AliasedRegistry;

    public function __construct(
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
    }

    /**
     * This method creates a Claim Checker Manager and populate it with the claim checkers found based on the alias. If
     * the alias is not supported, an InvalidArgumentException is thrown.
     *
     * @param string[] $aliases
     */
    public function create(array $aliases): ClaimCheckerManager
    {
        return new ClaimCheckerManager($this->select($aliases, 'claim checker'), $this->eventDispatcher);
    }

    /**
     * This method adds a claim checker to this factory.
     */
    public function add(string $alias, ClaimChecker $checker): void
    {
        $this->register($alias, $checker);
    }
}
