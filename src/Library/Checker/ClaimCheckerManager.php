<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Util\InheritanceChecker;
use function array_key_exists;
use function count;
use function get_debug_type;
use function sprintf;

/**
 * This class manages claim checkers and performs claim checks.
 *
 * The set of checkers is fixed at construction time: a manager expresses a policy that no consumer is allowed to widen
 * afterwards. It holds one checker per claim, so the rules of a claim belong in a single checker.
 *
 * @final The class will be final in 5.0.0: implement ClaimCheckerManagerInterface and decorate the service instead of
 * extending it.
 *
 * @see \Jose\Tests\Component\Checker\ClaimCheckerManagerTest
 */
class ClaimCheckerManager implements ClaimCheckerManagerInterface
{
    /**
     * @var ClaimChecker[]
     */
    private readonly array $checkers;

    /**
     * @param ClaimChecker[] $checkers
     */
    public function __construct(iterable $checkers)
    {
        InheritanceChecker::warnIfExtended(static::class, self::class, ClaimCheckerManagerInterface::class);
        $indexedCheckers = [];
        foreach ($checkers as $checker) {
            $claim = $checker->supportedClaim();
            if (isset($indexedCheckers[$claim]) && $indexedCheckers[$claim] !== $checker) {
                throw new InvalidArgumentException(sprintf(
                    'The claim "%s" is given two checkers, "%s" and "%s", but a claim checker manager takes a single checker per claim. Combine the rules of a claim in a single checker.',
                    $claim,
                    get_debug_type($indexedCheckers[$claim]),
                    get_debug_type($checker)
                ));
            }
            $indexedCheckers[$claim] = $checker;
        }
        $this->checkers = $indexedCheckers;
    }

    /**
     * This method returns all checkers handled by this manager.
     *
     * @return ClaimChecker[]
     */
    public function getCheckers(): array
    {
        return $this->checkers;
    }

    /**
     * This method checks all the claims passed as argument. All claims are checked against the claim checkers. If one
     * fails, the InvalidClaimException is thrown.
     *
     * This method returns an array with all checked claims. It is up to the implementor to decide use the claims that
     * have not been checked.
     *
     * @param string[] $mandatoryClaims
     */
    public function check(array $claims, array $mandatoryClaims = []): array
    {
        $this->checkMandatoryClaims($mandatoryClaims, $claims);
        $checkedClaims = [];
        foreach ($this->checkers as $claim => $checker) {
            if (array_key_exists($claim, $claims)) {
                $checker->checkClaim($claims[$claim]);
                $checkedClaims[$claim] = $claims[$claim];
            }
        }

        return $checkedClaims;
    }

    /**
     * @param string[] $mandatoryClaims
     */
    private function checkMandatoryClaims(array $mandatoryClaims, array $claims): void
    {
        if (count($mandatoryClaims) === 0) {
            return;
        }
        $diff = array_keys(array_diff_key(array_flip($mandatoryClaims), $claims));
        if (count($diff) !== 0) {
            throw new MissingMandatoryClaimException(sprintf(
                'The following claims are mandatory: %s.',
                implode(', ', $diff)
            ), $diff);
        }
    }
}
