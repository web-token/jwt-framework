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
use Jose\Component\KeyManagement\X5UFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class X5ULoaderCommand extends ObjectOutputCommand
{
    /**
     * @var X5UFactory
     */
    private $x5uFactory;

    /**
     * X5ULoaderCommand constructor.
     */
    public function __construct(X5UFactory $x5uFactory, JsonConverter $jsonConverter, ?string $name = null)
    {
        $this->x5uFactory = $x5uFactory;
        parent::__construct($jsonConverter, $name);
    }

    protected function configure()
    {
        parent::configure();
        $this
            ->setName('keyset:load:x5u')
            ->setDescription('Loads a key set from an url.')
            ->setHelp('This command will try to get a key set from an URL. The distant key set is list of X.509 certificates.')
            ->addArgument('url', InputArgument::REQUIRED, 'The URL');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $url = $input->getArgument('url');
        $result = $this->x5uFactory->loadFromUrl($url);
        $this->prepareJsonOutput($input, $output, $result);
    }
}
