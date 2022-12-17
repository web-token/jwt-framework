<?php

declare(strict_types=1);

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
    protected static $defaultName = 'keyset:convert:public';

    protected static $defaultDescription = 'Convert private keys in a key set into public keys. Symmetric keys (shared keys) are not changed.';

    protected function configure(): void
    {
        parent::configure();
        $this->setHelp('This command converts private keys in a key set into public keys.')
            ->addArgument('jwkset', InputArgument::REQUIRED, 'The JWKSet object');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $jwkset = $this->getKeyset($input);
        $newJwkset = new JWKSet([]);

        foreach ($jwkset->all() as $jwk) {
            $newJwkset = $newJwkset->with($jwk->toPublic());
        }
        $this->prepareJsonOutput($input, $output, $newJwkset);

        return self::SUCCESS;
    }

    private function getKeyset(InputInterface $input): JWKSet
    {
        $jwkset = $input->getArgument('jwkset');
        if (! is_string($jwkset)) {
            throw new InvalidArgumentException('Invalid JWKSet');
        }
        $json = JsonConverter::decode($jwkset);
        if (! is_array($json)) {
            throw new InvalidArgumentException('Invalid JWKSet');
        }

        return JWKSet::createFromKeyData($json);
    }
}
