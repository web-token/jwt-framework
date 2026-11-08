<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure\Stub;

use ArrayObject;

/**
 * An ArrayObject with a "_sd" property: the payload encoder only serializes its storage.
 *
 * @extends ArrayObject<string, string>
 */
final class ArrayObjectWithDigests extends ArrayObject
{
    /**
     * @param array<string, string> $storage
     * @param list<string> $_sd
     */
    public function __construct(
        array $storage,
        public array $_sd
    ) {
        parent::__construct($storage);
    }
}
