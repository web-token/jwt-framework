<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\A128KW;
use AESKW\A192KW;
use AESKW\A256KW;

abstract class AbstractECDHAESKW implements KeyAgreementWithKeyWrapping
{
    public function allowedKeyTypes(): array
    {
        return ['EC', 'OKP'];
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_WRAP;
    }

    abstract protected function getWrapper(): A128KW|A192KW|A256KW;

    abstract protected function getKeyLength(): int;
}
