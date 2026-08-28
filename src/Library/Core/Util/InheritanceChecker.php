<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use function str_starts_with;
use function trigger_deprecation;

/**
 * Raises the deprecation notice emitted when one of the services of the library is extended.
 *
 * Those services will be final in 5.0.0. The behaviour they used to be extended for is now available through the
 * interfaces they implement: a decorator implements the same interface, wraps the service and is injected in its
 * place. The event dispatching services of the bundle are the only subclasses shipped by the project; they are
 * deprecated as well and replaced by decorators, so they are left out of the notice to keep it actionable.
 *
 * @internal
 */
final class InheritanceChecker
{
    private const DEPRECATED_BUNDLE_SERVICES = 'Jose\\Bundle\\JoseFramework\\Services\\';

    public static function warnIfExtended(string $actualClass, string $finalClass, string $interface): void
    {
        if ($actualClass === $finalClass) {
            return;
        }
        if (str_starts_with($actualClass, self::DEPRECATED_BUNDLE_SERVICES)) {
            return;
        }

        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'Extending "%s" is deprecated: the class will be final in 5.0.0. Implement "%s" and decorate the '
            . 'service instead ("%s" does it).',
            $finalClass,
            $interface,
            $actualClass
        );
    }
}
