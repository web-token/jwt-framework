<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Serializer;

use Jose\Component\Core\Exception\UnsupportedSerializerException;
use Jose\Component\Core\Util\AliasedRegistry;
use function trigger_deprecation;

final class JWSSerializerManagerFactory
{
    /**
     * @use AliasedRegistry<JWSSerializer>
     */
    use AliasedRegistry;

    /**
     * Creates a serializer manager using the given serializer names.
     *
     * @param string[] $names
     */
    public function create(array $names): JWSSerializerManager
    {
        return new JWSSerializerManager(
            $this->select($names, 'JWS serializer', UnsupportedSerializerException::class)
        );
    }

    /**
     * Returns the serializer names supported by this factory.
     *
     * @deprecated since 4.3.0, will be removed in 5.0.0. Please use "aliases()" instead.
     *
     * @return string[]
     */
    public function names(): array
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::names()" is deprecated and will be removed in 5.0.0. Please use "aliases()" instead.',
            self::class
        );

        return $this->aliases();
    }

    /**
     * Adds a serializer to this factory. The serializer is registered under its own name.
     */
    public function add(JWSSerializer $serializer): void
    {
        $this->register($serializer->name(), $serializer);
    }
}
