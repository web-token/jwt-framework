<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use function debug_backtrace;
use function is_a;
use function trigger_deprecation;
use const DEBUG_BACKTRACE_IGNORE_ARGS;

/**
 * Raises the deprecation notice emitted when a mutator reserved to the library is called from outside of it.
 *
 * The JWS and the JWE are not built in one go: the builders and the serializers create an empty object and then feed
 * it with the signatures, respectively with the decrypted payload. Those mutators had to be public for that reason,
 * which is also what leaves a token returned by a loader modifiable by anybody holding it. They are annotated
 * "@internal" but nothing enforced it, and no static analyser could report their use.
 *
 * The caller is the class owning the frame below the mutator; a call made from a plain function, from a closure
 * bound to no class or from the global scope has no such class and is therefore reported.
 *
 * @internal
 */
final class InternalCallChecker
{
    /**
     * @param list<class-string> $allowedCallers The classes and interfaces the method is reserved to; a subclass or an
     *                                           implementation of any of them is allowed as well
     * @param string             $advice         What the caller is expected to do instead, appended to the notice
     */
    public static function warnIfCalledFromOutside(string $method, array $allowedCallers, string $advice): void
    {
        // @phpstan-ignore ekinoBannedCode.function (the caller is only identifiable through the stack, and the arguments are not collected)
        $caller = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3)[2]['class'] ?? null;
        if ($caller !== null) {
            foreach ($allowedCallers as $allowedCaller) {
                if (is_a($caller, $allowedCaller, true)) {
                    return;
                }
            }
        }

        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s()" is internal to the library. Calling it is deprecated and it will not be possible in '
            . '5.0.0. %s',
            $method,
            $advice
        );
    }
}
