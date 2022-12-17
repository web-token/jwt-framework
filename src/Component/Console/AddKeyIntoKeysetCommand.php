<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use InvalidArgumentException;
use function is_array;
use function is_string;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class AddKeyIntoKeysetCommand extends ObjectOutputCommand
{
    protected static $defaultName = 'keyset:add:key';

    protected static $defaultDescription = 'Add a key into a key set.';

    protected function configure(): void
    {
        parent::configure();
        $this->setHelp('This command adds a key at the end of a key set.')
            ->addArgument('jwkset', InputArgument::REQUIRED, 'The JWKSet object')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The new JWK object');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $jwkset = $this->getKeyset($input);
        $jwk = $this->getKey($input);
        $jwkset = $jwkset->with($jwk);
        $this->prepareJsonOutput($input, $output, $jwkset);

        return self::SUCCESS;
    }

    private function getKeyset(InputInterface $input): JWKSet
    {
        $jwkset = $input->getArgument('jwkset');
        if (! is_string($jwkset)) {
            throw new InvalidArgumentException('The argument must be a valid JWKSet.');
        }
        $json = JsonConverter::decode($jwkset);
        if (! is_array($json)) {
            throw new InvalidArgumentException('The argument must be a valid JWKSet.');
        }

        return JWKSet::createFromKeyData($json);
    }

    private function getKey(InputInterface $input): JWK
    {
        $jwk = $input->getArgument('jwk');
        if (! is_string($jwk)) {
            throw new InvalidArgumentException('The argument must be a valid JWK.');
        }
        $json = JsonConverter::decode($jwk);
        if (! is_array($json)) {
            throw new InvalidArgumentException('The argument must be a valid JWK.');
        }

        return new JWK($json);
    }
}
