<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

/**
 * Checks the claims of a token.
 *
 * The interface is implemented by ClaimCheckerManager and by every object that decorates it. Decoration is the
 * supported way of plugging behaviour into the manager: ClaimCheckerManager is annotated as final and will be final in
 * 5.0.0.
 */
interface ClaimCheckerManagerInterface
{
    /**
     * Returns all the checkers handled by this manager.
     *
     * @return ClaimChecker[]
     */
    public function getCheckers(): array;

    /**
     * Checks all the claims passed as argument. All the claims are checked against the claim checkers. If one fails,
     * an InvalidClaimException is thrown.
     *
     * @param array<string, mixed> $claims
     * @param string[] $mandatoryClaims
     *
     * @return array<string, mixed>
     */
    public function check(array $claims, array $mandatoryClaims = []): array;
}
