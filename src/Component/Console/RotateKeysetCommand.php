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

namespace Jose\Component\Console;

use function count;
use InvalidArgumentException;
use function is_array;
use function is_string;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class RotateKeysetCommand extends ObjectOutputCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('keyset:rotate')
            ->setDescription('Rotate a key set.')
            ->setHelp('This command removes the last key in a key set a place a new one at the beginning.')
            ->addArgument('jwkset', InputArgument::REQUIRED, 'The JWKSet object')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The new JWK object')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $jwkset = $this->getKeyset($input)->all();
        $jwk = $this->getKey($input);

        if (0 !== count($jwkset)) {
            array_pop($jwkset);
        }
        array_unshift($jwkset, $jwk);

        $this->prepareJsonOutput($input, $output, new JWKSet($jwkset));

        return self::SUCCESS;
    }

    /**
     * @throws InvalidArgumentException if the keyset is invalid
     */
    private function getKeyset(InputInterface $input): JWKSet
    {
        $jwkset = $input->getArgument('jwkset');
        if (!is_string($jwkset)) {
            throw new InvalidArgumentException('Invalid JWKSet');
        }
        $json = JsonConverter::decode($jwkset);
        if (!is_array($json)) {
            throw new InvalidArgumentException('Invalid JWKSet');
        }

        return JWKSet::createFromKeyData($json);
    }

    /**
     * @throws InvalidArgumentException if the key is invalid
     */
    private function getKey(InputInterface $input): JWK
    {
        $jwk = $input->getArgument('jwk');
        if (!is_string($jwk)) {
            throw new InvalidArgumentException('Invalid JWK');
        }
        $json = JsonConverter::decode($jwk);
        if (!is_array($json)) {
            throw new InvalidArgumentException('Invalid JWK');
        }

        return new JWK($json);
    }
}
