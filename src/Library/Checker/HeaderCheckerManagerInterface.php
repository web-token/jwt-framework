<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

use Jose\Component\Core\JWT;

/**
 * Checks the header parameters of a token.
 *
 * The interface is implemented by HeaderCheckerManager and by every object that decorates it. Decoration is the
 * supported way of plugging behaviour into the manager: HeaderCheckerManager is annotated as final and will be final
 * in 5.0.0.
 */
interface HeaderCheckerManagerInterface
{
    /**
     * Returns all the checkers handled by this manager.
     *
     * @return HeaderChecker[]
     */
    public function getCheckers(): array;

    /**
     * Checks all the header parameters of the given signature or recipient. All the header parameters are checked
     * against the header parameter checkers. If one fails, an InvalidHeaderException is thrown.
     *
     * @param string[] $mandatoryHeaderParameters
     */
    public function check(JWT $jwt, int $index, array $mandatoryHeaderParameters = []): void;
}
