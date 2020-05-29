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

    public function __construct(X5UFactory $x5uFactory, ?string $name = null)
    {
        $this->x5uFactory = $x5uFactory;
        parent::__construct($name);
    }

    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('keyset:load:x5u')
            ->setDescription('Loads a key set from an url.')
            ->setHelp('This command will try to get a key set from an URL. The distant key set is list of X.509 certificates.')
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
        $result = $this->x5uFactory->loadFromUrl($url);
        $this->prepareJsonOutput($input, $output, $result);

        return 0;
    }
}
