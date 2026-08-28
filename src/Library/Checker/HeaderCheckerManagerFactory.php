<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

use Jose\Component\Core\Util\AliasedRegistry;

/**
 * This class is a factory to create Header Checker Managers. It allows to add header parameter checkers and token type
 * supports. The factory is responsible to create a Header Checker Manager with the header parameter checkers found based
 * on the alias. If the alias is not supported, an InvalidArgumentException is thrown.
 * @see \Jose\Tests\Component\Checker\HeaderCheckerManagerFactoryTest
 */
class HeaderCheckerManagerFactory
{
    /**
     * @use AliasedRegistry<HeaderChecker>
     */
    use AliasedRegistry;

    /**
     * @var TokenTypeSupport[]
     */
    private array $tokenTypes = [];

    /**
     * This method creates a Header Checker Manager and populate it with the header parameter checkers found based on
     * the alias. If the alias is not supported, an InvalidArgumentException is thrown.
     *
     * @param string[] $aliases
     */
    public function create(array $aliases): HeaderCheckerManager
    {
        return new HeaderCheckerManager($this->select($aliases, 'header checker'), $this->tokenTypes);
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
