<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Normalizer;

use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

final class JWENormalizer implements NormalizerInterface, DenormalizerInterface
{
    public function supportsNormalization($data, $format = null)
    {
        return $data instanceof JWE && $this->componentInstalled();
    }

    public function supportsDenormalization($data, $type, $format = null)
    {
        return JWE::class === $type && $this->componentInstalled();
    }

    /**
     * @param mixed  $object Object to normalize
     * @param string $format Format the normalization result will be encoded as
     *
     * @return mixed
     */
    public function normalize($object, $format = null, array $context = [])
    {
        return $object;
    }

    /**
     * @param mixed  $data   Data to restore
     * @param string $type   The expected class to instantiate
     * @param string $format Format the given data was extracted from
     *
     * @return array|object
     */
    public function denormalize($data, $type, $format = null, array $context = [])
    {
        return $data;
    }

    /**
     * Check if encryption component is installed.
     */
    private function componentInstalled(): bool
    {
        return class_exists(JWESerializerManager::class);
    }
}
