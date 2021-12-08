<?php

declare(strict_types=1);

namespace Jose\Easy;

use function in_array;
use function is_string;
use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\InvalidHeaderException;

/**
 * This class is a header parameter checker. When the "enc" header parameter is present, it will check if the value is
 * within the allowed ones.
 */
final class ContentEncryptionAlgorithmChecker implements HeaderChecker
{
    private const HEADER_NAME = 'enc';

    /**
     * @param string[] $supportedAlgorithms
     */
    public function __construct(
        private array $supportedAlgorithms,
        private bool $protectedHeader = false
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function checkHeader($value): void
    {
        if (! is_string($value)) {
            throw new InvalidHeaderException('"enc" must be a string.', self::HEADER_NAME, $value);
        }
        if (! in_array($value, $this->supportedAlgorithms, true)) {
            throw new InvalidHeaderException('Unsupported algorithm.', self::HEADER_NAME, $value);
        }
    }

    public function supportedHeader(): string
    {
        return self::HEADER_NAME;
    }

    public function protectedHeaderOnly(): bool
    {
        return $this->protectedHeader;
    }
}
