<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use function str_starts_with;
use function trigger_deprecation;

/**
 * Raises the deprecation notice emitted when one of the classes the library seals is extended.
 *
 * The services will be final in 5.0.0. The behaviour they used to be extended for is now available through the
 * interfaces they implement: a decorator implements the same interface, wraps the service and is injected in its
 * place. The value objects - the key, the key set, the two tokens and the signature - will be final and readonly as
 * well, and they have no interface to decorate: they carry no behaviour to change, and the state a subclass adds to
 * them cannot survive the constructor becoming the only way to populate them.
 *
 * The event dispatching services of the bundle are the only subclasses shipped by the project; they are deprecated as
 * well and replaced by decorators, so they are left out of the notice to keep it actionable.
 *
 * @internal
 */
final class InheritanceChecker
{
    private const DEPRECATED_BUNDLE_SERVICES = 'Jose\\Bundle\\JoseFramework\\Services\\';

    public static function warnIfExtended(string $actualClass, string $finalClass, string $interface): void
    {
        if (! self::isExtendedFromOutside($actualClass, $finalClass)) {
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

    /**
     * Same notice for the value objects, which have no interface to implement in place of the inheritance.
     */
    public static function warnIfValueObjectExtended(string $actualClass, string $finalClass): void
    {
        if (! self::isExtendedFromOutside($actualClass, $finalClass)) {
            return;
        }

        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'Extending "%s" is deprecated: the class will be final and readonly in 5.0.0. Build the object with its '
            . 'constructor and keep the state "%s" adds to it in the object of yours that uses it.',
            $finalClass,
            $actualClass
        );
    }

    private static function isExtendedFromOutside(string $actualClass, string $finalClass): bool
    {
        if ($actualClass === $finalClass) {
            return false;
        }

        return ! str_starts_with($actualClass, self::DEPRECATED_BUNDLE_SERVICES);
    }
}
