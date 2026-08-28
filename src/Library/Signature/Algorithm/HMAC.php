<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Override;
use ReflectionMethod;
use function in_array;
use function is_string;
use function trigger_deprecation;

abstract readonly class HMAC implements MacAlgorithm, SignatureAlgorithm
{
    #[Override]
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    #[Override]
    public function verify(JWK $key, string $input, string $signature): bool
    {
        return hash_equals($this->sign($key, $input), $signature);
    }

    #[Override]
    public function sign(JWK $key, string $input): string
    {
        if ($this->overridesHash()) {
            // @phpstan-ignore method.deprecated (the override of a subclass is honoured until 5.0.0)
            return $this->hash($key, $input);
        }

        return $this->computeMac($key, $input);
    }

    /**
     * @deprecated since 4.3.0, use sign() instead. Will be removed in 5.0.0.
     */
    #[Override]
    public function hash(JWK $key, string $input): string
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::hash()" is deprecated and will be removed in 5.0.0. Use "%s::sign()" instead.',
            static::class,
            static::class
        );

        return $this->computeMac($key, $input);
    }

    protected function computeMac(JWK $key, string $input): string
    {
        $k = $this->getKey($key);

        return hash_hmac($this->getHashAlgorithm(), $input, $k, true);
    }

    protected function getKey(JWK $key): string
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
        if (! $key->has('k')) {
            throw new InvalidArgumentException('The key parameter "k" is missing.');
        }
        $k = $key->get('k');
        if (! is_string($k)) {
            throw new InvalidArgumentException('The key parameter "k" is invalid.');
        }

        return Base64UrlSafe::decodeNoPadding($k);
    }

    abstract protected function getHashAlgorithm(): string;

    /**
     * Tells whether the concrete algorithm alters the signature by overriding the deprecated hash() method, as
     * subclasses had to do before sign() existed. Their override is honoured until 5.0.0, when hash() is removed.
     */
    private function overridesHash(): bool
    {
        /** @var array<class-string, bool> $overrides */
        static $overrides = [];

        return $overrides[static::class] ??= (new ReflectionMethod(static::class, 'hash'))->getDeclaringClass()
            ->getName() !== self::class;
    }
}
