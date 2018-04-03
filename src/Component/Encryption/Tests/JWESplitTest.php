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

namespace Jose\Component\Encryption\Tests;

use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;

/**
 * @group JWE
 */
class JWESplitTest extends EncryptionTest
{
    /**
     * @test
     */
    public function aJweObjectWithMoreThanOneRecipientCanBeSplittedIntoSeveralJweObjects()
    {
        $input = '{"recipients":[{"encrypted_key":"dYOD28kab0Vvf4ODgxVAJXgHcSZICSOp8M51zjwj4w6Y5G4XJQsNNIBiqyvUUAOcpL7S7-cFe7Pio7gV_Q06WmCSa-vhW6me4bWrBf7cHwEQJdXihidAYWVajJIaKMXMvFRMV6iDlRr076DFthg2_AV0_tSiV6xSEIFqt1xnYPpmP91tc5WJDOGb-wqjw0-b-S1laS11QVbuP78dQ7Fa0zAVzzjHX-xvyM2wxj_otxr9clN1LnZMbeYSrRicJK5xodvWgkpIdkMHo4LvdhRRvzoKzlic89jFWPlnBq_V4n5trGuExtp_-dbHcGlihqc_wGgho9fLMK8JOArYLcMDNQ","header":{"alg":"RSA1_5","kid":"frodo.baggins@hobbiton.example"}},{"encrypted_key":"ExInT0io9BqBMYF6-maw5tZlgoZXThD1zWKsHixJuw_elY4gSSId_w","header":{"alg":"ECDH-ES+A256KW","kid":"peregrin.took@tuckborough.example","epk":{"kty":"EC","crv":"P-384","x":"Uzdvk3pi5wKCRc1izp5_r0OjeqT-I68i8g2b8mva8diRhsE2xAn2DtMRb25Ma2CX","y":"VDrRyFJh-Kwd1EjAgmj5Eo-CTHAZ53MC7PjjpLioy3ylEjI1pOMbw91fzZ84pbfm"}}},{"encrypted_key":"a7CclAejo_7JSuPB8zeagxXRam8dwCfmkt9-WyTpS1E","header":{"alg":"A256GCMKW","kid":"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d","tag":"59Nqh1LlYtVIhfD3pgRGvw","iv":"AvpeoPZ9Ncn9mkBn"}}],"unprotected":{"cty":"text/plain"},"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","iv":"VgEIHY20EnzUtZFl2RpB1g","ciphertext":"ajm2Q-OpPXCr7-MHXicknb1lsxLdXxK_yLds0KuhJzfWK04SjdxQeSw2L9mu3a_k1C55kCQ_3xlkcVKC5yr__Is48VOoK0k63_QRM9tBURMFqLByJ8vOYQX0oJW4VUHJLmGhF-tVQWB7Kz8mr8zeE7txF0MSaP6ga7-siYxStR7_G07Thd1jh-zGT0wxM5g-VRORtq0K6AXpLlwEqRp7pkt2zRM0ZAXqSpe1O6FJ7FHLDyEFnD-zDIZukLpCbzhzMDLLw2-8I14FQrgi-iEuzHgIJFIJn2wh9Tj0cg_kOZy9BqMRZbmYXMY9YQjorZ_P_JYG3ARAIF3OjDNqpdYe-K_5Q5crGJSDNyij_ygEiItR5jssQVH2ofDQdLChtazE","tag":"BESYyFN7T09KY7i8zKs5_g"}';
        $serializer = new JSONGeneralSerializer(new StandardConverter());
        $jwe = $serializer->unserialize($input);
        $split = $jwe->split();

        self::assertEquals(3, $jwe->countRecipients());
        self::assertEquals(3, count($split));

        for ($i = 0; $i < $jwe->countRecipients(); $i++) {
            $recipient1 = $jwe->getRecipient($i);
            $tempJwe = $split[$i];
            self::assertEquals(1, $tempJwe->countRecipients());
            self::assertEquals($jwe->getAAD(), $tempJwe->getAAD());
            self::assertEquals($jwe->getCiphertext(), $tempJwe->getCiphertext());
            self::assertEquals($jwe->getEncodedSharedProtectedHeader(), $tempJwe->getEncodedSharedProtectedHeader());
            self::assertEquals($jwe->getSharedProtectedHeader(), $tempJwe->getSharedProtectedHeader());
            self::assertEquals($jwe->getSharedHeader(), $tempJwe->getSharedHeader());
            self::assertEquals($jwe->getIV(), $tempJwe->getIV());
            self::assertEquals($jwe->getTag(), $tempJwe->getTag());
            self::assertEquals($jwe->isEncrypted(), $tempJwe->isEncrypted());

            $recipient2 = $tempJwe->getRecipient(0);
            self::assertEquals($recipient1->getHeader(), $recipient2->getHeader());
            self::assertEquals($recipient1->getEncryptedKey(), $recipient2->getEncryptedKey());
        }
    }
}
