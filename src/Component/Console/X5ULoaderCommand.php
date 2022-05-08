<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use InvalidArgumentException;
use function is_string;
use Jose\Component\KeyManagement\X5UFactory;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(
    name: 'keyset:load:x5u',
    description: 'Loads a key set from an url.',
)]
final class X5ULoaderCommand extends ObjectOutputCommand
{
    public function __construct(
        private X5UFactory $x5uFactory,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        parent::configure();
        $this
            ->setHelp(
                'This command will try to get a key set from an URL. The distant key set is list of X.509 certificates.'
            )
            ->addArgument('url', InputArgument::REQUIRED, 'The URL')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $url = $input->getArgument('url');
        if (! is_string($url)) {
            throw new InvalidArgumentException('Invalid URL');
        }
        $result = $this->x5uFactory->loadFromUrl($url);
        $this->prepareJsonOutput($input, $output, $result);

        return 0;
    }
}
