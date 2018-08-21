<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Console;

use Jose\Component\Core\Converter\JsonConverter;
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

    /**
     * JKULoaderCommand constructor.
     */
    public function __construct(JKUFactory $jkuFactory, JsonConverter $jsonConverter, ?string $name = null)
    {
        $this->jkuFactory = $jkuFactory;
        parent::__construct($jsonConverter, $name);
    }

    protected function configure()
    {
        parent::configure();
        $this
            ->setName('keyset:load:jku')
            ->setDescription('Loads a key set from an url.')
            ->setHelp('This command will try to get a key set from an URL. The distant key set is a JWKSet.')
            ->addArgument('url', InputArgument::REQUIRED, 'The URL');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $url = $input->getArgument('url');
        $result = $this->jkuFactory->loadFromUrl($url);
        $this->prepareJsonOutput($input, $output, $result);
    }
}
