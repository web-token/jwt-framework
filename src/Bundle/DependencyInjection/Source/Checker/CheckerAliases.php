<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Checker;

/**
 * The checker lists of a service configured in several places add up, and ConfigurationHelper prepends a copy of the
 * first configuration, so the same alias can be listed more than once.
 *
 * @internal
 */
final readonly class CheckerAliases
{
    /**
     * @param array<array-key, scalar> $aliases
     *
     * @return list<scalar>
     */
    public static function unique(array $aliases): array
    {
        return array_values(array_unique($aliases));
    }
}
