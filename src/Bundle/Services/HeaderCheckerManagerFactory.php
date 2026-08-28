<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\TokenTypeSupport;
use Jose\Component\Core\Util\AliasedRegistry;
use Psr\EventDispatcher\EventDispatcherInterface;

final class HeaderCheckerManagerFactory
{
    /**
     * @use AliasedRegistry<HeaderChecker>
     */
    use AliasedRegistry;

    /**
     * @var TokenTypeSupport[]
     */
    private array $tokenTypes = [];

    public function __construct(
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
    }

    /**
     * This method creates a Header Checker Manager and populate it with the header parameter checkers found based on
     * the alias. If the alias is not supported, an InvalidArgumentException is thrown.
     *
     * @param string[] $aliases
     */
    public function create(array $aliases): HeaderCheckerManager
    {
        return new HeaderCheckerManager(
            $this->select($aliases, 'header checker'),
            $this->tokenTypes,
            $this->eventDispatcher
        );
    }

    /**
     * This method adds a header parameter checker to this factory. The checker is uniquely identified by an alias. This
     * allows the same header parameter checker to be added twice (or more) using several configuration options.
     */
    public function add(string $alias, HeaderChecker $checker): void
    {
        $this->register($alias, $checker);
    }

    /**
     * This method adds a token type support to this factory.
     */
    public function addTokenTypeSupport(TokenTypeSupport $tokenType): void
    {
        $this->tokenTypes[] = $tokenType;
    }
}
