<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Util;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;
use function count;
use function implode;
use function trigger_deprecation;

/**
 * The two algorithm managers the JWE builder and the JWE decrypter work with, extracted from the single manager they
 * receive: the one with the key encryption algorithms and the one with the content encryption algorithms.
 *
 * @internal
 */
final readonly class EncryptionAlgorithmManagers
{
    private function __construct(
        public AlgorithmManager $keyEncryption,
        public AlgorithmManager $contentEncryption
    ) {
    }

    /**
     * Splits the given manager. The caller is the class the manager was given to; it is only used to report the
     * algorithms that are neither key encryption nor content encryption algorithms.
     *
     * Those algorithms are dropped, which turns a misconfiguration into an "algorithm not supported" error much later.
     * Dropping them is deprecated since 4.3.0: in 5.0.0 the builder and the decrypter will be given the two managers
     * directly and will not have to guess anything.
     */
    public static function split(AlgorithmManager $algorithmManager, string $caller): self
    {
        $keyEncryptionAlgorithms = [];
        $contentEncryptionAlgorithms = [];
        $ignored = [];
        foreach ($algorithmManager->all() as $name => $algorithm) {
            $supported = false;
            if ($algorithm instanceof KeyEncryptionAlgorithm) {
                $keyEncryptionAlgorithms[$name] = $algorithm;
                $supported = true;
            }
            if ($algorithm instanceof ContentEncryptionAlgorithm) {
                $contentEncryptionAlgorithms[$name] = $algorithm;
                $supported = true;
            }
            if (! $supported) {
                $ignored[] = $name;
            }
        }
        if (count($ignored) !== 0) {
            trigger_deprecation(
                'web-token/jwt-framework',
                '4.3.0',
                'Passing algorithms that are neither key encryption nor content encryption algorithms to "%s" is deprecated. The following algorithms are currently ignored and will be rejected in 5.0.0: %s.',
                $caller,
                implode(', ', $ignored)
            );
        }

        return new self(new AlgorithmManager($keyEncryptionAlgorithms), new AlgorithmManager(
            $contentEncryptionAlgorithms
        ));
    }
}
