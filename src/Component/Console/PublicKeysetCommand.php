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

use InvalidArgumentException;
use function is_array;
use function is_string;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class PublicKeysetCommand extends ObjectOutputCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('keyset:convert:public')
            ->setDescription('Convert private keys in a key set into public keys. Symmetric keys (shared keys) are not changed.')
            ->setHelp('This command converts private keys in a key set into public keys.')
            ->addArgument('jwkset', InputArgument::REQUIRED, 'The JWKSet object')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $jwkset = $this->getKeyset($input);
        $newJwkset = new JWKSet([]);

        foreach ($jwkset->all() as $jwk) {
            $newJwkset = $newJwkset->with($jwk->toPublic());
        }
        $this->prepareJsonOutput($input, $output, $newJwkset);

        return 0;
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
}
