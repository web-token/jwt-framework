<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests\Stub;

use Jose\Component\Checker\ClaimCheckerInterface;
use Jose\Component\Checker\HeaderCheckerInterface;

/**
 * Class SubjectChecker.
 */
final class SubjectChecker implements ClaimCheckerInterface, HeaderCheckerInterface
{
    private const CLAIM_NAME = 'sub';

    /**
     * @var bool
     */
    private $protectedHeader = false;

    /**
     * SubjectChecker constructor.
     *
     * @param bool $protectedHeader
     */
    public function __construct(bool $protectedHeader = false)
    {
        $this->protectedHeader = $protectedHeader;
    }

    /**
     * {@inheritdoc}
     */
    public function checkClaim($value)
    {
        return $this->checkValue($value);
    }

    /**
     * {@inheritdoc}
     */
    public function checkHeader($value)
    {
        return $this->checkValue($value);
    }

    /**
     * @param $value
     *
     * @throws \InvalidArgumentException
     */
    private function checkValue($value)
    {
        if (!is_string($value)) {
            throw new \InvalidArgumentException('The claim "sub" must be an string.');
        }
        if (!$this->isSubjectAllowed($value)) {
            throw new \InvalidArgumentException(sprintf('The subject "%s" is not allowed.', $value));
        }
    }

    /**
     * {@inheritdoc}
     */
    public function supportedClaim(): string
    {
        return self::CLAIM_NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function supportedHeader(): string
    {
        return self::CLAIM_NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function protectedHeaderOnly(): bool
    {
        return $this->protectedHeader;
    }

    /**
     * @param string $sub
     *
     * @return bool
     */
    private function isSubjectAllowed(string $sub): bool
    {
        return in_array($sub, ['SUB1', 'SUB2']);
    }
}
