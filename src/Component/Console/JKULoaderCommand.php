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
use function is_string;
use Jose\Component\KeyManagement\JKUFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class JKULoaderCommand extends ObjectOutputCommand
{
    /**
     * @var JKUFactory
     */
    private $jkuFactory;

    public function __construct(JKUFactory $jkuFactory, ?string $name = null)
    {
        $this->jkuFactory = $jkuFactory;
        parent::__construct($name);
    }

    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('keyset:load:jku')
            ->setDescription('Loads a key set from an url.')
            ->setHelp('This command will try to get a key set from an URL. The distant key set is a JWKSet.')
            ->addArgument('url', InputArgument::REQUIRED, 'The URL')
        ;
    }

    /**
     * @throws InvalidArgumentException if the URL is invalid
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $url = $input->getArgument('url');
        if (!is_string($url)) {
            throw new InvalidArgumentException('Invalid URL');
        }
        $result = $this->jkuFactory->loadFromUrl($url);
        $this->prepareJsonOutput($input, $output, $result);

        return 0;
    }
}
