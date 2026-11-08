<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use AESKW\A128KW as Wrapper;
use ArrayObject;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2AESKW;

/**
 * PBES2-HS256+A128KW recording every call to unwrapKey(), that is every key derivation it is asked for.
 *
 * @internal
 */
final class CountingPBES2HS256A128KW extends PBES2AESKW
{
    /**
     * @param ArrayObject<int, true> $calls
     */
    public function __construct(
        private readonly ArrayObject $calls,
        int $maxCount
    ) {
        parent::__construct(64, 4096, $maxCount);
    }

    public function name(): string
    {
        return 'PBES2-HS256+A128KW';
    }

    public function unwrapKey(JWK $key, string $encrypted_cek, array $completeHeader): string
    {
        $this->calls->append(true);

        return parent::unwrapKey($key, $encrypted_cek, $completeHeader);
    }

    protected function getWrapper(): Wrapper
    {
        return new Wrapper();
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    protected function getKeySize(): int
    {
        return 16;
    }
}
