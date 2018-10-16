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

namespace Jose\Performance\JWE;

/**
 * @Revs(256)
 * @Groups({"JWE", "ECDHES"})
 */
final class ECDHESBench extends EncryptionBench
{
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES', 'enc' => 'A128CBC-HS256'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES', 'enc' => 'A192CBC-HS384'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES', 'enc' => 'A256CBC-HS512'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES', 'enc' => 'A128GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES', 'enc' => 'A192GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES', 'enc' => 'A256GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
        ];
    }

    protected function getAAD(): ?string
    {
        return 'A,B,C,D';
    }

    public function dataInputs(): array
    {
        return [
            ['input' => '{"ciphertext":"KsRIKGTIm8Zf_AgLI5D1ymISA63OIamKsYk1VB7xsw4j2mwDuKR9MA1mhUbc-Ps_s7VIOzK0qaKwPhdEjDcIb-Vut2yQ0E_HxpFyjNr5T-RbbJ1kdy1hXK3THo-Fcdrw2i3SoLYKi7pTh06CmYyv42iePtr1tq2t68MiUeRI9ZElD4Maf4ONcPWsG9QwmQzzui8kGdEJ58IzpAaqLzXAzYsj6K6Dd6rFHA9Gdd8lCtA","iv":"Ssta2D7cbN7ohhZ_IEirGQ","tag":"FOYasMqq5L_D7McwEcFbUg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiItT3czODhtbDc0dEhkbDd6TDFwbENoTFFyVHdyOWRNRnN0VmlUUFFEWGJBIiwieSI6IjJSSmlpMF9xVmJxZGhtV3dWbUhzUDN6X2hFeFpRNUZJaElGWEg3d2hXRFkifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ"}'],
            ['input' => '{"ciphertext":"AbyYGNhmhfPp1losLrlcwLupvYHOpq_qUj3fCWYRGUwqE8z6G8ZKMC6kPaKfN7cepJIgxi6vP7Dxb_X-e0uJlD8mofiramMujc5w5gS91H_4LDfjA0hPsQNZsevvQ6H9Wb6KQfEH_ADw3Qo2lq-C9gjZdtpvOosvoph8D3E6jA9-DdC3Q1X0vSHgTKKwUVOiCAGXVUxclSvSIwkai1jIEKQDdch2So4ZGg2jGM9Mu0Q","iv":"QNuVRp1d7frRChaUKCFwOw","tag":"8zf7asVXbIBlD5M5_tGvynUDYCHkxCks","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJNWDhyTWthUHVzcHlMem12RFJUMWFzSmE4ZGVSQWZ0eEF5WVVqWFJWOUtvIiwieSI6ImlsaHFZRnF3eGRqZGM5UWQwYUp6Y0N5U1Y4U054endpVFdqUE9QWEtJa2sifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJDQkMtSFMzODQifQ"}'],
            ['input' => '{"ciphertext":"UTHlayhPiU24oSypsNfRxpcbbCEJCrF3AtjNShs0LwflvY2m6CgwBLhKulw8HHtnDaxcLYjXutm5pXgzbgflwtHoAwh5WOwpnXkceAYm9vVUkRPwcRCeczvYy8__FSAzjJXRfFloy4E9cZtv8culFh5I-kbaEEs_E-3RQD3fvlbo3JLB4rrhccWjgM-qyF8eIHGFhAWa2Ez87dXCde9d8dvnn6StnfV4u-lTleOe5wE","iv":"6AnITEM_hi0oTJSI1EroVQ","tag":"pgFbCS8Jchp1z0qrdIS2mgiheApFT3aG20iyFOXk7_U","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJzd0ktbThvY2tNZlg3MjhxQkRoRkJ6MjNta1JZS2xJSXd2S1ZObmdZYmpnIiwieSI6IjNIb05TWHZ0QkdRX3pKTlE1ZmM3RVNqUmVhVFU1WF9pc0kxVzV2MG0zUG8ifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ"}'],
            ['input' => '{"ciphertext":"j0e5K7z08DEb8rkYCdtQimnNlO5VJ8OCipL1LmBxDWJ3FIxq2yxunhbzqYr5OsbBu2nsi26enhgxdf9utxYcUMhXY1BV-VOSaFVZHkKowSCco0H95a6sNhJVVGaLHFE2dLUl-Ooxlc0g6tDJC-Lyi9cBFuJlm-KeDZwrhd25g2Dpk38DSFN5ZUujstiLq-gibsm97DB5FDZvhk-elgJ5sBsM-k8wz3s","iv":"KG2bIjAFOXMY2_A0","tag":"4lrGURacjerWUN_szorv5Q","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJTaUxhQ2cya0ZuRldoOHFvZTJoblM1UXhPQy1BbUY1X0I4UkVhSkZzZEVZIiwieSI6IjhEOXJPaXQwbjh4ZjcxekZsallXRnhjMVI2SjUySlpvNFNvaGNuNFNmUTQifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhHQ00ifQ"}'],
            ['input' => '{"ciphertext":"EmExZLBtuOMeu436MGmVpPGL1Oxl0pE8viy88rlyll-K4o7rWViqqxms7V4UgPs2FnZgdL8CJ6W_NY2QlPQlzrANPc9oUinD_OjScH-0Ff6Lb-LskWlGNebqyyl74XStzGO7K67jCnc0oXoU36yfuZFcjf5t3RI1Wh0hL_RL22OxVIk3k_WkurIgA-F2WkXDVuxlRW-nWkoNoxpRceZgDQmBVD0cfb0","iv":"lk2StauExilwOfql","tag":"1fXcCfufql4eRHvfsvRoNA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJqRG8wN0t6TkRuUjJrVERDVEFFWWZpclpKR1h6V2EwcE00UFlUWjg5ZUlrIiwieSI6IlNIaUpFNGdDUzBvZG1sdTNrcTF0VXNFenFoQnNvOWxtaHZpREE2Y2xoMVEifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJHQ00ifQ"}'],
            ['input' => '{"ciphertext":"m8LhdFezEohHDHP1MR8mY26PF2qP1Ay9KHfQGXeCGJmLwR2U_V50MFP9_ehlHq3QrMXlM6EpbGEaa7BSuiZg9bhNbVWAHx9_S-NmZ8NcimPuRAexc6303fNoIyIwMBkAHdHED4IbRMfzdsJg9v05aMTzv3SqW7dJezyTPN_rWuFpYDFlqPg-c5HK90OOY5BR_zW5OK5XAVz5bxsi21HW0Ti0yHBiCgg","iv":"X6u2KRH0g-OOH2M5","tag":"h_xvwqzXIu5HRJn5OTy6zQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJDZ25yYklpWmVXb00xUzJVRDdXcHVhRnNHeW50RzI2b1Y3Wm0tWHRRODVBIiwieSI6IkZiTkZLdEZDaDdoUTNyV2tfZWVTNnNiemUwQ01SZkNCbkdsOHBKbU5YMEEifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZHQ00ifQ"}'],
            ['input' => '{"ciphertext":"DmmkxBraJ0QZj5ZWb2QA0XMopoqxLVOC3DI1DmDLkrFOlqu1kTZhvI0Hx9EcST1YbvZ0Z77s9SpvXlHNW36vWBOqZQxWpGysh1lazijSYjN28lw5wKkhqBDEu_6_K__S6I-EA6PI8cl2wdA3LOIauA9_0smfmVcA2Ka3umN1EayDMIaMuwU2B45zuJrhHDxVk_9mV51fmVq7-lKyyAeu5sVy3KTn9FLWxcnkrZ3ajog","iv":"eoG62aPTiTdhUg1ZCt_QUw","tag":"IrYMVE6U87oo_LsNr0nHDg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJBNDZpY3FwRjNYX2h3R3RRQndkOUw2d1NlajdiZGk0WnlRaVBsLVNlMllBS1BMT0kwbU9hQmw0SFZNNl9uMWJPIiwieSI6Im44cjZjSEpKOTF0SlFLLWhscnlGUlROQXo1SVNfbThkR05wVHcyd1lxMXVnRlVfc19nSGczUkJhTnFiblZ1c3MifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ"}'],
            ['input' => '{"ciphertext":"S81Z4p-qRKFcMNqQwG-pKd8dGhy1wuYG5tQN8FvEyW0A3R2d9jmChe71LEU7p4cdljlZPI19f7eVH6GvJ8drY-bcck5MobZuePcs2bCJVR4u2UGGQKiowbaeuquzErDKSq8p59yRCsEuIKfEHOUEQiLILs7dMUTFUgrv22vn6UVI781h3qOrSa74tGuwthTdSvaTgTE17Wfc3jj7BTgngY828updPsXEsDdSLs-qrMo","iv":"JJeemphZk_34coLYqxoyNQ","tag":"dq93EO-2TId_55J3GJ5gLAPKVEsHLJoI","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJMNU9EYmRQdmZmOU9RZWROYU5sVmtPUk94VlNCY01RUEtLN29PWnRZU3RZaXpFTi1sZzhNbTFSMHR5bmtZVWwxIiwieSI6IjhTYmc1WXJZbnljVzl1QVBZYndCYXNvTERnbXdFUk12Y0VnUHN6dmFPNTdIMUxLWF9hTmpnXzg3aGw5ZUNJcXkifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJDQkMtSFMzODQifQ"}'],
            ['input' => '{"ciphertext":"r-Fr1h9QP-jkTQr_72bTxMEfZeL7loJSfuam2ifuR6nxkfWLsmPFvtuTPlNW2qpddP3b2vVl-MUFjzj5KSkM9FeTMlDzcYhrdWnsnPzpnKlR_dmqnQqtpH1mudHLjzBxOylL3TAao4RRZGFWhPSgplqjR-bkxI0TgMLi3UIjI_8xaTOE7OLfw-xf5a99oegPzodcKw2J1_Hbcg8XWwTXkNHdpVdm-p_OfZXsABYRKe8","iv":"vjiEqMMHjngniUPvbgBWDw","tag":"_wcGyo5Kgwu6Bx4gQtIC2B37br443LevIA6sveBG7_k","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJzenExTmtBN3MtanpfN3BmTENXMzgtR3hxcmRCc2drUHNVX0pheFBmanpwTmdoYkFCcGIxYzVJd0NDTG80VHRqIiwieSI6IlVxRlNtb2RDa3EtV1pqZzYxLXplQ21vMF9mb0tnQXItVzgzRlhYQWpONG9mQi1UUmt1d25HbFlVM3hEN2x6VGwifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ"}'],
            ['input' => '{"ciphertext":"YaBX6UK6DiJHZEx0VcHIiiLIIsgotyKhBpcXzKc5mGx-adCb29Fvz1mHz6NEaR-MGs_Lbyr1_Iz63fAgH4MHbeLVhLNR986suo9t6kIXghe6jBHFuzwubEW41w3HwFXTGTQAdAP1VdDzrNp3YiwTO9sxugGNaO7QcxUCoogT60a3sNc1bMe16Hf3adrj58eWYZccnpTRnNWULfiu_fb_e_0vDfKjtek","iv":"ExgS-jAeC0B8cFoe","tag":"eD6oYHjnAgbQivjazEpR_w","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiI1VHVGcE9GaUtWb0czdWRKd3ZVM1JfM01OSVdhdWxJZm44ekg2a3l4MEhscWE2QktISjFxWHlVNlVlWm5hdzVtIiwieSI6IjJTX0tfYkttN0xtdHI5MG14V1YxNHNTaW1Nczh5WUtDdWNqZnZpZmc2Q1UybjBMMTQ5cG5aamx1MEdBSnM5akUifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhHQ00ifQ"}'],
            ['input' => '{"ciphertext":"tsFjmeszfXnah0CPF2_2xAWHD_P8isIhVShnJ1AQ15IR4aTXB37l5nIo4kVXCLaNgR4N-CjR6pumn7NLNFzfgqQpbQeXFx8dqCMkbDlQBMAuPeu4AoxhVGaDqRsHM_k2H51WVayAjkFpgrItc6XEjIu2y4o8Hy0-_hD6c3-lK22U6ZRLg-10Cq-pDN1Nq6ZRxTZx3mvzWeRIrko8t-k9p4yKcJVmOpk","iv":"wD7u4GcP0EjHR_mm","tag":"I8g2nTz3UaLDqrLWsuN4pQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJ2V0dQOGJRRDVwdTZHTkxYWkpCNnlfN3hzQ1J0TjZCeDdDRU1DR1lRRWxuQTZUYjFXOUkzRklyak40eDFLZ3c4IiwieSI6ImVodWExdE05bzF5OHhXS3ljUU1sby0waVctell1bVBUYmxPbUlZaWxKVkVadDVpbGg4VU9FTDNZZjRrU1RxTFYifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJHQ00ifQ"}'],
            ['input' => '{"ciphertext":"ZT1Nli-gjvAtYCmEWyMsuQ792N6Shse-YVEcKBdg5iJzK5Xjpt8ZfhGnLoeBcpYZIiFxmNbXvwJLnRrtzl_Yvt5KYVu4XAQY5CyMUfJi5i35j3SY0C9PT-TymiwOj_8fLmmookDbQpgWeQs3RcHCUCR3OpjSrlR3Xf3nVzhFMaC4MYOoS1TTL6Cq0bSxPRE74i_lvL6cR9sBgPIIUvW5I4EkmzgCokk","iv":"Pw4u5IW-j6TCPEpP","tag":"kndBhMtDYRX4rEp01ndQFQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJkZUJOazd4ZUN0R1ZtUk1RSDJSVUw2Q2twNXFCWS1OU2Q3Tjd0TjNPbmwzRGMwaXJvMm1faGVqUG1KUGJyYkNkIiwieSI6Iks2S0RRMklwMENubTcwaGxkSnRMM2t5R0wzdGgtUjFYOTdQNVFVS3VnWlkwMnZ2QUpvbGE4Q1FZQ1AtTHlEYUUifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZHQ00ifQ"}'],
            ['input' => '{"ciphertext":"VP3msKx3uJKdWkeC6Cz5gM2thvDzSyGyccTgQbxHemaO6Egq8afzTnoj841yY5EczIRfBT9QsSlhu7nWFUY5i8RXHhIgAQHaBPv7sutT6_ISDRWdxgpd27tTMP5bzsPsAyX2jvtQx4gCvte1BI-RR19qCQRiRanq3JvbStpgYYRSzo5b4BhP5ik1WJy_b2_NK2mAXXtYo0WgBqjBDXm7t46euLxScMBhwRtuUWddGis","iv":"qfyMAIJhyeROiM_u5DBLHQ","tag":"CVs13nkHgx1IJ67NvcAYJw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBU3VpVEtOSzVsejZQcnBoWFlhNDdWcXZtT0RDbk84clRQUUU5aExkM19TRm5RQ2JoU1Rua3NYZktYb0RaZ2lTa3hqWkpXOGh4Q0VNVkFkWDlnUzl2M0x5IiwieSI6IkFPWXJEZ082VGFwQ2hzc0c4NFJEWXNGejVzT1NBR056MURsLWtHQnFSRVUwNkZYbkVkYUVxSF9vOXdkUkxmY01QZWxkaEpGR3ZnT0k1bGowU0p0OUZ4aXkifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ"}'],
            ['input' => '{"ciphertext":"JzSiCguosSsOArvPlmaLyZIfOfPIKjwU4bhHmkMtRmgFk2Go4spQT1WF9vHXBVZSf6itljYZAHSMrERLAjNwovX69anddc3eaZSNvgvKb1oH_bcHb-uDLVIcktEVqIopajbBaDOU57tQEWSuHN88odCJTjolchcwqSYmXtPjS6J1nOxy7ulapbWgMGqFMqiZtX0Iq6YcyzJVimvOvshERVy6Y3BwYAaLARrOugWSB2E","iv":"BM1ts9JitMS3izCW0YJy1Q","tag":"mcfyHYGEuiynDfnod-yHU8Uoe_SrSaHf","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBUU9pdklxVi0ycnU3MDNaYVRxTEpMQlRwVUVKdWhQMXhPaGNlOWdOS2lkLVJ5LUtEY1JCNVZkR3c0TE4xNHlNOGVHcmZUN2NqVXFVWlBaMkJqMUpSQVczIiwieSI6IkFXRGxrcHRXNWl0Q3h6MEEtbmN1SmpFWDhoWlUxUElwQ3RJWkRobDBYVThUMFVqeEFsdzUwRGx3TlRtUzdUcmM0dEtRdjd0cTRPNVFHdFdOWW96eHJxbE0ifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJDQkMtSFMzODQifQ"}'],
            ['input' => '{"ciphertext":"BriyWYaD3yOINglVHQmdOaveAUZYHU5zS46aTYvLA1pzP0-S5r_MBF3qgZOH9iLEdl8KgTCOolKBDjLXOG5YsL9KqMTHAmTBTxvIhIx-O57KBvl12MsGxb65TU6IX2bLVkc8Zg7A8-m6A2v2zb_DsfVZ1chxW7fsTKl218R6_0TTwtP_7T-4ctlc81vEZqOLquTpaieWoG-ASOehfB3CN4J7Dp_sJ-okeqNArmWq3tE","iv":"Ly3eUiXkIGMok1n4SjSfOg","tag":"RDj7osy5t7NREXO0I5eULOP5So1s_A3X2dbQHws9Qtk","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBYTQzUDdEblhyS2Fwc2hZNmZMWTJXbV9ScHRqUVc1MklpT20tb0VDV080elZtSVV1ZGtNeE4zSV9IY0psbThmR1hFeEp3NUx4MHp4V2lDZm9sRG05eGVmIiwieSI6IkFmSUNkY0dqTlEtdmZDUXl2M1k4bG1kckhVV1hZQjdoaU9rQUp4UUVlYVpJNjJuZnpMeHdBcUg1VnhIQTFNTHhYSWhJb3J4TkV5Y2RPRmo0aGZCbXhRT0EifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ"}'],
            ['input' => '{"ciphertext":"UbVIUUAKozSZNbzQd6PCP7WK6o_sE2bo30UYWdyn1YDw1_trpfmaI3w-YnlyOiGwPr-zC_vmZ454W_Ryn0AGXKXqiTaekS53WbG8Th8wDlwS14AQultrF9qk9OnOvkTrOJP_O5iQD2TcqRGKTayVuDCmqdoQuy75peY-9l0aFhEEvt11DaDxCPjghE2oeL7tJZeOkWJklW3C4fXhzO1JApC88yeNNGM","iv":"eQprJb7oLn_UofHS","tag":"nn2X8aNEZi4tyhFMa1wxfQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBWTBLc0JobmlJcmRzZUZNMWtYcTh4bmdyNFhkbEphZHNxTF96SjI2TUc2VWY2STFlbkhOTDN0R3ZrU3Bqa2Q4Sm1HR1pZR2pfQXI2cnd0V28tS2FVRmd2IiwieSI6IkFWN19fUzJqLXQ1TE9ndHRnNEtlLXQ0SlpaUVMzb1llak51anRYSTJLU2pGVXBhUkdGRUNxUmh6TlBoMnVpU1Jya3kwMEx4X18tSWNSS3htclhTVndaR0IifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhHQ00ifQ"}'],
            ['input' => '{"ciphertext":"kbNXtTo5NBpqdJB5eF4gq2wYrVfytSoq7fRsbZ8jCwMeHc3WwM3HsrHPwQk5FfQRPLlTkNsMausVpV28n-aYHevMXL4RI-8_IbuMgXVtJGY2aJ-9KhuEAV3O8Wr1Pcrc_2QF7GRQph0X3dVoQduPpiOqzclcKQqmWjKNx7LWMtUoAkKjMxLaMPkFGm0APFqaDyNomQp4Xtzw9r3PW88PSrne4LMGDYY","iv":"O5M7KXZc2lUSaMXz","tag":"z0BQpTdE94FETudknErpLQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBV0hfSFd2SDNXanIwOGx5OG5MRzlpUXlwb1JsVDNZS2JBc1h0YXdKcE5UYlhjVWJKOWpmYXlieWVRYzJmeWJYUEhCNF9CVnBodU1nQTBzSFBrandESFd6IiwieSI6IkFBSDJhaTZJdkdNYXRNTFZNa1RMSlplQTJuZC1rZm5Ydk93Yi10Q0pwMzRsVGozdlZYVmhMZWNqRTM5M2NrYTczWGQwYXh0VWpqdFRiR1ZacmJ6dkswd1YifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJHQ00ifQ"}'],
            ['input' => '{"ciphertext":"Va0dxUmDCHgUIILlr7ynQgIx7sejkmPc4C5KtTBx8mSPsOh0RHKuSpG_Kl0_T4xG7_kB6V1L0sr_3GZ1VQyOk55gzt5VuhJbaJGur8le_0tzxzxdunUPut2Dg28qCk4x0EIftxaqRojhne5okleBx9AJdbeAALVpiPnNU5AmThU3648Go9LnrcPDUS__pNxI7Jmoo3o6CtW8nCy-EZI-bBi9nx2sr1E","iv":"T_Wkl0uQ6EILdiGo","tag":"niqwhxpUw5T8nqXIIvkwag","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBVU5tRDJFbDZ6X3B6aFNhTE5qcDVuNUJtNDJDSDl0b0JiTmFCWko3eHJCUm15bFlWUmpfcHU4VVlfeTlsQ0Q5U19wWDFlRllwLTFaY1NYc09XSjBWM2FPIiwieSI6IkFSeDh5WkNmTHgxN2U0ZHAydS1mNmJ0eXg2eFZkY1l1Y0o5a1R6YU5RRGpEZ3NDNFc4cGN4UmlQeUduWnN2bHNSeG5aNXRLb3VSUldqWXpQaEZ1WnJ3TFMifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZHQ00ifQ"}'],
            ['input' => '{"ciphertext":"lpybkrid_-PJmz9mbc7tN0ILbiN7O_5p69Py8v7zdZ7eWsMpARzVsZDh4cS3Pr6PEo644h9cdonDZT3X-E5C_pLiquR44wti9djlZkz_DVuC8V2owUuY7J3KtNsJ0wgAzw4IKB52XAvZ_k8B8DkO_HizPh9GOlLvfiq0JZavLxUlDUa4liMM87d4Ab09A9syExrb2AF73f2h9Fh6t5zaoEut5qiwLKapaRNg_qm5zy4","iv":"Jf-mYDmKK3ted8lok_GIGw","tag":"DT90e1pDUOnMevNQA1CMDA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkRpMmFYalpMTDBvb2lJSW9uODVsOVh4WmJRQ2FHbVdLVlU4azJIeXRYR00ifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ"}'],
            ['input' => '{"ciphertext":"XMtu-ILvqQAw34cvWxFAjcla3BPp_b_V6I_4WG-htpcMpwgu-gG-LVrb_82b8PF52DhH6Ddb6LTXvgLo61Fmu3NnE9JKuxK9x3rKS1FwMaRjfLOHQxDjWfvc6sBhtCkXptcyb6PGu7Cf_Gqefc6EUtuv1mg8oFRcHHyh3oKwodfejhKv498BBOapYpMbShvJ_vFm_-POK166Ar6lXkT2J2v_hcLgvEqdg9cblhbq6fY","iv":"0-53nsstdwvjKg-2AiQ39w","tag":"5B6nXRG3VcnQ77uooFvuu6hbKkYW7buD","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IlBqTXhyNHpfcWp3NXJjQmFWMTBlS1MtWWJFLTBVQWVrYjNDWkpfOVptbncifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJDQkMtSFMzODQifQ"}'],
            ['input' => '{"ciphertext":"frDISfZ73cpq6Dr3fZrV30NFvVhpIg4BqW6sBHiGqKi69vsLyXKGvtrl1VHK27_6PO3xmApdLPfHITEFuwmyggOX4_bSVgArkWgpgXlUJzwbDgbCsJKf7FuVXK5O1wy4_I_JYSiO0J1YUONjUrt6Ex343Ibq3vDB2KiHeemoGRKLhoM6ejdyY_YPeHKr7fOopYviZGPPh2bt8dEXe8lNpAJVDh8cgGIkVvDrmjzDk6I","iv":"xzKxcIuy56ORbMN21dVk2g","tag":"Y_OPobOVDz_lIwDoMqsXcosVQFCvCfMSmWCpY3W7nN8","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Il96QzJ3QTUyYmZtTFllTUlObUc0NWVYRkJhWndpV3c2bWk1dm05NmM3WHcifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ"}'],
            ['input' => '{"ciphertext":"_5muNolwL4qVUB_a2Sc5jxJXDyLOoiXUWKGshvhtK9pnEEvlHKUirPuFV5hAd4x8nw4zt3vrh7ELEUBeMQ_z252svnMVrStFWg7Bg5qbI6h63IEM4o9XlnyXcwoYcm967H-3-UZ8j66Y2R9ztc2pRR2zs2pO0pNhJP78VjWL6j2tyRu3Qr3Ifxf3Y69tzDCZXzUs6y1KEsmay4X75OrUZbFrs7Kbg6Q","iv":"Ifn2b8VX6mfBEdmd","tag":"N60_66GG2jMw9NBYHIGaGw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IldVeHQwUGFUMmkzalp2Vkx2MHNac2ZOYkg1cnpPVGFnYmU3V2JpV0Z6bGMifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhHQ00ifQ"}'],
            ['input' => '{"ciphertext":"IUmY2ePgZiNynhrTxcNbDJtNBL59UEJ2ocggcuXrLF0ucFNORX0CVOO1GN28Ymre9C8SRQkMB1fLel7i33Zi03QT_znEguRo0Ytx2QpCWItxjqzbCuOd9506xSQjA09-ydriciNFHgbnxFMm91W-5ETNg-gNMCNBLg2fYNVjUFLXPSUe-yfcGViFTUcCJzPwnw60GhOTbxI5VkQPZicZM_u_hTVOWhk","iv":"YqKvjace4bjVQjjc","tag":"uhBYYEQ3SuIAFMzjhmT7Mg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImZya2RpdmdKZUFacHB5MGdSME9lcjM4ZXZ3TDVjbENmaXJxRXFDcFR5VFUifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJHQ00ifQ"}'],
            ['input' => '{"ciphertext":"QbcGBRt2ARS1K3k4A1mktK4ks4WYuoga06gHjGMvEIesam5sFMOS8bqgSI4rOa_a_TLkSNCHlSOXFy2gs_zaXg3YEgwTWNdtH1B47D3Wc8DRTygbwdTAsnGMB1aVnvj2qb2OvSRCk4uMg-oD8WvFkTgp0iyxYw97IKyhH8FU6PjzKwiYGAUTCNcia6iyAzTFStlicyH7VvhLzXInS49X4EzlptNjtS0","iv":"O3HOMyDYmyFi9-L1","tag":"dODnhRWtPxEBE_PtBZrENg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IndsYnVwRzJuaUpxOTR2U0pCaWt5RXl5NXoyRzNhcDhBWHJjWVdOdFgxZ28ifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZHQ00ifQ"}'],
            ['input' => '{"ciphertext":"ACg_nLboBecsud2uTRPZE9lhnGFXdNwdWzykX50dXKU2UBc68T1XSS_YsqGH_XuEKheWa-gwgMxbLsvBpbnelkm84UiavaefBlKGDjTZZZfzJmEE0UdWzSsfJ6DZQ66qk-denN-K_Va46Om7Pkv5Z2CNpIF7miAHeCCHnF2z4O7D6IRrw5pQUUnvHzrUz72lKPZDYj8JlOYENjFblP32cKl011ve1Cwk-pgAhoJ0FBE","iv":"aF28SnQOmrc-gEdIlTewWw","tag":"wTECGcrV42tlC7RON78stg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJ4MEJvVHhfXzJITnhRQVd2UDNBa1A5TDRFeHA1ZlJzdy10RjlfdEZMTk5RIiwieSI6IlNDREpNYXlJRlBrdW5URkIzV1FvQWZYbEc5MFN2ZkUxN1U4TkxMWTFib2sifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ"}'],
            ['input' => '{"ciphertext":"wzktIqgfTWJk5-6h9pt9_djnVmt9XL4Zf1kX84xg14_EmES9peZgu1dBq0omUfTP10QgXPPvHEwhzJn6tcLPEpmgvH4UenDvPul6ZoQemLxQKojERrJROD9FTRITKCKe1K0jrRAkKXlzeYs0et6Ju_rHtUHq3I97hmT6mQkwkeJFXQ-qkBaItRLVbXBq5Ph3TTYjDubOBoCHWAKZ-pPiJ-4f6Whx7fDDVsV_hXdooJc","iv":"bDZvQ89OmNYHEREWyBYPZw","tag":"k5NO-VRlL8MaijOD_C8jHSB9dq_0L3Wk","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJrdkNVbHF5aGY1YTM1N3YyN1ZwV1l3Y1RsdTdvLUtQUEt0QXBQN0ZLc0wwIiwieSI6IkxwdDlRalZwcW9JUEJzUFJQY1VCb0o0OFExR050cXg5QWxRM0ZoZHhIMGsifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJDQkMtSFMzODQifQ"}'],
            ['input' => '{"ciphertext":"d1au1N8eU8qMQ4D93HYnb5-cFtqyIdrJXV2OdaJCcA65s2g2rEM1k261lnnbJ-C_OgK60oQQxTc70d_YOXZOMsBDmraDmpjr2AODtwohSSe9e35QpyD0S2TT-FL64CiSk0TodtitlQ00UTCs0vHSDy7gesHvwG5cmiXKBr0_2ybW2LnOwpJZZpZGTIX5cuocfVVecoN_cS5G6RIVTEsT6YS0WAnVUAiWsifdvuJp1tg","iv":"XloO4Wm_70slo5FVj-lHUQ","tag":"LBuBOaorE7-XSFf0ed-s7cugHaNbtrsOmFCXa8lsZLM","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJvSmZobld0SjRGOGxCUENic1p5cGRWbjZUZERxUEZZX2dlWXdpQmxLZlRBIiwieSI6IjB5ckFhRXlnQkNhYW80bE51eEgtVUtXZUJuODVNNmEyTXdsTnhJQVpleEkifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ"}'],
            ['input' => '{"ciphertext":"vnoovMxbZ_Ie878pnkzg1MftrJOyKxlj53qwxtCdUduyQVx1IYZTcpmC3bqqLm3Tm4A1VPi3U1uFp8X_tHUNW_AkIlCQvtlISjUmlq2VZqvQodynYzcLE_bEf49b0gky39Jk-U7uq51pZdkCn_Dnm-2k8xQKtnrkISsl96JjTw69D_pGBR0DdQFcEfJO1HpUsUQlOOX8fsdW2DURmNsvEAtSBn0faCg","iv":"NstpkansL9xPOrad","tag":"cXTsEsWSV2Ipy1EGVzfcow","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJ1V2NLajVDdl9vdzZZTWlMdVlfLUNWMFJxeGhSZDdLQ3FWMC1LNmtwYlk0IiwieSI6IlItMlF0U1FxUWpSOEpYT0NYa1hkSnROM0VycHpDNjJEbVhoREl3b3dkWXMifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhHQ00ifQ"}'],
            ['input' => '{"ciphertext":"FR74oS4SHGmbgi2qb-DNgQ5i37g2JZlVy47AR40MoGfoVGgrcL0i_7sDlWBeC8RWCVCkBMBNUR7-fkp8rwNvwC9DN1E8GoiFVtmi5D-wYXVwMksx8oeFGT0FeDRKHDa2ZDUzcVttDSmU0xiYi_2wjkW6q1CozlZGB_1Mu9xEogd3e749LJx4FNm22EGI7JM4ioyKCxNQfBDMxt6XXFqtEaQFIUY4Y2g","iv":"KAJVHEqL0ZafC7Nf","tag":"_XkJWzjIqfW3AVlvl7fHww","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJ3d3RUUXN6MlFMX2t3aURIMkRVMXhzQ09lT19haFlvZU41NFhZa0xibXlvIiwieSI6Ik5CZ0RFV2syZTJlaGNramZXVnl5V3hCYy1fVk9zWVpadHJlZlhibTZGU1kifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJHQ00ifQ"}'],
            ['input' => '{"ciphertext":"1gjDAJA1A9K3IJ_nQZiZCND1kP94iTELtYwti-qX893MS7ggBYrlrCNqotCvwKgmn_CMRcWd9y04U2IMQnL-R2juVIkEC3vZvfOH9c_UTLxjKN-CPyRj9frk7uP2EyQWNet9rjPsMoO25cmorlwtSwusQ5AIuZRXhRjtE26W1O1wbBK5CBg0ybf4B37N50beFRo_DzcBiUQsvJJLJyo_ehDVxgjW4gg","iv":"h5m9rU_ULBMdfb45","tag":"LgYeq5xlP3TMXMG5PduO6A","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJ6TlhNU0RIdktSdmRkNzRvdHFHRzRwU1RPV09MR1RkVWlESTY1bXJWcHkwIiwieSI6InNCaTJSbXdHQmhjTC1IaS1PZVF1WWFCYndYLTlTaDV4ZXhGM2htaEtWbGMifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZHQ00ifQ"}'],
            ['input' => '{"ciphertext":"IxQQfxuR1TZ6ntuADjsnvtgZTL3yIHobBImiIhM2OXkh0yoM1MZXwSC_c1UlJdf6cGdacPIgmcJlsZdAbsi7WzZ5JxZQOL-pjAeab5t_L_4e2Lqtu10l812w_yXQ-szKc2meyj3o928lg9AwyNi48GVXCCGAuGZUBfAbXCp0ORC9UP4Q0pVIAo7XhWCVvxk8Vl2XR7kPVofEwr2mvMJ8OoCAmYAIKfnw3AfkkIzyLCw","iv":"r9WX61qWE40c5oqAu9b7Sg","tag":"vo65keQh_Q_ID8O4y0zINQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJiRGlIR0JRMmNmWGQzTm5ua1ZQcVdtYXpHUHJVcWwzVGRMYXNDcDJVQUhwMXVlUWtxU2xpdjhSUnIxQ0U3SjZBIiwieSI6IlBzU0p2ekJCRDRPUU1qLWFXMHZaalBySFlwU1NhYnZMWGtaUmxZSXA4Mm11cTFZaUg0OE1ha3MwTXNvSnk5UGEifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ"}'],
            ['input' => '{"ciphertext":"m50AsW6xfm1_u5fGHbPRg6Im8bpWA-uNjl6sek90seFgGuV21HQssW4n6ksAFH-1CGloNngHxQUAO6nYgAPuGJpGJyYARLEjIZhP6RYcW2wk8TVK-8MHQ3o07Uhui_jb6vVvwX8NHWNlZQDupeEfS19GEzE6s---C4IA_U8BP9Vd_UVjgtE9TyOCPntIuUr0frJTDAEffesDvPQEgtUNtMr4M-uhb0G0M7BkaIvgSJU","iv":"C4923TvD5M_TIie45JPBHA","tag":"HoMhtMrjJ5GDsMLGjo_WUryqilRnRsLA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJNbEZVdWVEWmYxZlFma2I0ZFUwdFQ0eGlOdHVlbDAtQ1htdVE5VktOVjh1S3NaS19ORmFuRjlSODYwYUptS3dGIiwieSI6IlNMRUZCX0FnMjhhWWRwaUJ4SlU4NzBYaVRkXy1DeURRNTVZTWluZWhBd2FpNGJNWFlqMUdHMmd5ai1EQ0h6TFYifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJDQkMtSFMzODQifQ"}'],
            ['input' => '{"ciphertext":"_7FRQBjsuN4kY2iOBO4ObmO5AlMoCzSsNXPJsdryxgjTpPLR84xN2oYoU4g_oPAssTFzUJh8yXp-Fx-AH0mnf5lVP_NIexF_NHLrFar35F9d94PJBkwiv7CtNefXeuO_XsMjZn7TWB0Qhw_oX52JWVsybS23M3zSM8iSVrYCDUgLdivrc4x5-BCMBgUmHz_Efee-iFjnPRUGPg-oqwYZ9RzmVdMjV9-zbyfWGs9T2bM","iv":"gCKV_Z0VgExxHOfkxNJ5dg","tag":"ALFmpaym_S7k4eGPfUpJGm9GG-JbH_N9xOd_JJ_RpRk","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiItakhrN2FtbTI5OXExdHd1UVJaS0JnbWU1Ny1Td2lJdjVQZWNta2VHOWVNMi0wb0NkWExHWDRXUnFLQUttNXQxIiwieSI6IlNkeXl4MWVjZThpY01FT0pNZ2ljMjhrMWdzUjkzQmJJa281UFptSFN0ajRqbHZPYVFZYlJNVm9vSFotYVA4M1MifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ"}'],
            ['input' => '{"ciphertext":"eajyqCw1RJ8ev7RuWyhaqaRIJg72QibdSryd36CMxhhOUB2fIzGX9gZ8hHp_D7Pd7tRHFGt4ydavddqGaaCBjaMizHFdcZxMJQ6t_57BFFTTn3t_Vh08HVyE5caBariXMKb-0YGBwh8shLrBHEYTYE_LMbEJI-sBWePbtCbXb6n8ObzI7hVNq5Brq7ZmKBrGVZGPp1w64bJzGNPol9IRY_sBekHMmcw","iv":"-4w0zo1ACWTWK_lw","tag":"OPBIsx9UaSjxE2mrPlb88g","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJ6T1NOcE1EOE9aMkR3YWVFamFDTFFCNXZ5NlFWaklGYmNmbE0wOXMwRmZqRlduQUpwNFk3ckVPWl9CYkszVlAzIiwieSI6Ii03SEt0Um5kNlN5LVd6c01KVHBNSzltSU5adFVSSE82dmZKV1N5MWR0NWdPWWVqZmxKLXgxcWE1dE13SUVER2EifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhHQ00ifQ"}'],
            ['input' => '{"ciphertext":"SRBspbq8aCKsLjyb4ZwkU7bNf5387pvKDJt95MonIP2IVsI_yLQyn9RC0cOe_INnF9kfaE2nPyjYX7d4D4i70kdxOkmWK9UBWMyXUOHuyolWPJ8zooTbV6TgN-of21Xty_S2d_fxpQmrpwrrNfTFW2NRxiiRZeeIUVzuQD5CVqMEut1H0WgRGbUsKKMFEAhSMSfY3sGeZGsbAfRjneGJrEiA6A9FZWw","iv":"KgtjGk7lEaJVhvXe","tag":"1TtHcxNEG1Ie12vHEHxikw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiIzLVJ2QmdsQWhta211QjNaNUk0NHMxQ0stY25hX1YzaUFlWlgwUVhBZWoxVF9XN2Y5RDFsNXZMcmlJUWJTMl9KIiwieSI6InhJRTJORHQzNW1VN0QyVzhQUHA5SHlrVVJRWnN2NEJOVHBCamRidVZ5TzJWYWxjdlFmQkg0ZjJla2hQb3hvRW4ifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJHQ00ifQ"}'],
            ['input' => '{"ciphertext":"uRubb-NLklXJ9LeTeT7SbOUBj8iWksOohM0EAbxFSP7U7Q--SSNzp4kJxjTDweT1njB7soMNEPPIKHe3Je7e6JofQVhG17SmNKOo3VKvDCYRB8B_Ky2o4y5ZKpm8RzgvnfWLXRMu6497m_jNaQifaiWCCVsTedJiBT8F71gE_HYCQ-0mpAnbNwGwrQHCbNjXf2xjUbHWROF2hVASIjHCon_vXQPb0BI","iv":"K2PUZUoPd4v5gajx","tag":"IP9kcdZ7PWVaIJwTYDub4g","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJOZndiVF9BcnVzRk1pNkdKWkFiR0dHQXlPZ2ZkQVNaaDg4RXNEMkJReEFKRy1xOGFEcHAtc1NOYTViRy1kMDhBIiwieSI6Imwzei11b1daUzhzT1Y3SHZiVkZwTDF5VnhPY0duYkhiWEMyVlBHUVV6aV82VEpPLXdYT0dKcHlPaFJTVmdfSmYifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZHQ00ifQ"}'],
            ['input' => '{"ciphertext":"evFbDMHEqVePkdpNlexRjAyX5mf0RCjYH2SfEI5BrW1Qz09z5T8OvsQDdy2UDvoDKnJQXZNAyEicA-N1QMjsAeMD6xRZ7WcPb4jbGWsnk5Da2xYdVvKOlqa35D7s2eQsmxFI8nzPydT0V9I-M6J-sljp6kIbQYhkRzlF-1Yj3P0pD6ExNOEJiqqneei0CpxiUMDo_mH3Yqxv4aLevfhOLSGfL_RNlA41wvL7pqvmpnU","iv":"0gChfHukWucTP9jDU2sOHA","tag":"jytdfKao99CTm-QxlgUADg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBVHNOSWdJNFgzLVk2dXNBT2tRTHhjemtTX2k5amtWQnhiRHBmQlVzMEl1QjJpR1BwNWZkUFl5RHh4Y0QxMHhXdXZpVFF4TW1GODExS2NTaXNlUVlGX2dWIiwieSI6IkFHT1ltc0ZRY0UwOVFZYTZxQWFNbVh4bS1BRGMwcTVPSHk0aUdnNUppVTZ6UHRrQUFyQlVoaGNvR2pfUm85OUloTEJqbEVtc0J3amtsUzZPLWdaYkk4X3AifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ"}'],
            ['input' => '{"ciphertext":"sQGLMdFoGIU6hBqLqd5mScIvv7JL5YOVX_a2fPdk1nSMhT6Qzp16Gfc_hCUAUCjrhgMOXYt6ENH0efgCR9WTOp6OI2PUJY-cF425yW7w2uQ7cng86FzqEr6gx0JOhSMED3BJ2lwUNJ1hX3XyZi9zm7SeMYxibbEtrioFzvr5QriESsSw9O46_pJg_JmrUywJECJtmGhve-4xjhbX3J3WfFvQIB69S8t5N9FynjZ_Cx8","iv":"E3J-49EPWe3yG_S5uXXDpA","tag":"wO0cMmpjutiE5QMvJl-jj-GqGld0otfg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBV0JWR05GdzBYR1RaVEhyYlpTNFJrOTZlLW52M25WVTdzLWwxY1lJeXJmVi1sZXpvc2h6bF9SN1M3ejg5ajhxWVFhY25kOGN0V3F1d2F4aW1zZHlBYzRyIiwieSI6IkFFRzcxWWVweWMwZlNtZVo2VGxGaTNENUVnMVBYdWg5SnZ5ZXJVOEVZMkt3Wkx4Y25ydG1rQng1ZllRNlVkcGRTbDJESjkwNFhnMWhoMVRPY2tSTTFhV1MifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJDQkMtSFMzODQifQ"}'],
            ['input' => '{"ciphertext":"SQBbU-lyu_CtmFf7pHYukUfAEo8T-ck2WslHQ62APpJ480LuM9yZwzPlwTHG1uvQextL4cbFj9vvyLMeh3wYLj5AEhUHEVrpdvtlRi1rbEFqQiZUEooEPN2qJoxH2mWtn8nh2DjsuWpod8UDee-8hOrW3xc-qHcZvcSrmehZmpVWbBLEiylEAineyRPYYwTMvlLA3PcHqXARPO-41K8xUzrrXJI7xBiNLmOQlYA1z6s","iv":"jw_8tRsVnCFVKGS9IIzG4g","tag":"OcFTJXfkTicHumLC50Gmb63D8nDqwanhIOxH6fMLKNc","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBT1hpa3dFRTZ6Q3JBaEc1aU9tLXV6c0hmZjBHTnhxOXdWVTFFbWtobEh1OG04Zm5wRTlRS2hfdEc1cHhRMkR2N0ZCemFkR3RzajJESXlzT0wyMUdKNXNYIiwieSI6IkFhd0FZcjV0UzVLQ2NfSXJfLS1qN3ZjeDRFVzJpeTVRWVV1b1FQUlJvRmpGREFqT0twX3ZaLWhYTnFHbnlqREQ1VnV1QzlrdDNPVUJjVHNZeTVfallESkgifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ"}'],
            ['input' => '{"ciphertext":"MReNRX6Nce0_UQYaLxDa4AR2b-db9_FMVUXD73qAvENn-oXx4jJog4X76oVfl1-nqta5RBWg5mCT04TMRG7QtGxCEgpsS0w5ELKTJughVn9XHuPx3XXrjgSbiZZgYr69wx2hS7qnxTgdmVH1xo1Cpp-SH_9aE5CT9PwROcJOYkg5GhUTkKmDHXb1jdPMlrUzLxTaVl9Ric-YpGxcNy84Llgm6JA2FhA","iv":"uTLsVACz4yoGmTC3","tag":"igbfFg0uysWev5Uk5qm5lw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBT0luVjk4a2tjUW9sTUVWTk5wQlhQUkUzdXkyZm00ZzZKU1RKMnJYSFpYMnlac0lic2lqLU1tNEpXNVlJeUpJY3kzRTdheFFuRENpeDZUMEpKdGhWMXNIIiwieSI6IkFDVFJaTkNxYllSeTgySTR2b1pubktVVV8yTEdyVXNUZjVIOGxCTDdSZ1NfNVJ0UEFqU3RQSjRraU41QUtneWkteDB3VXBEX2JXUllKa096SmdFeHB5clkifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhHQ00ifQ"}'],
            ['input' => '{"ciphertext":"JrZd5PNga94b7YDyXyqNOrcPhEr2zEKyjC4e-iqdqcJw2zgjK_7zzw3e-MBVJ5JWRh8iepeveux8sMbZJoXB9v8R_72ykjadHXhXgwliPqcFA4wDg1NKGG99ZKnvPydlg2_0SAqxvX8C0aJVG25x4CdU2D2k4AWISgJMU1sgEk3buMGG3UuIYqwtOv6uhGsY0OMxMy4D-_02mR4V9NZDTHql9kXYESQ","iv":"b2W4yc1XDBs56hDP","tag":"VJD86DkO8ZEMsP4Xp3MJ-g","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBVmYxc1NWekVsZzNkNVJvMVJDdzI2by1hdi1kRjVVdENwQXJiMlJfVkRjZ1hCbWthakdOdTZnLXBDTHlBS04tVkc3dWJKNzd1WWxjSnNaS0tYa2l3aGhmIiwieSI6IkFLc1pheGQzOU92N3VMT1drU2tzYjZnRTY4c3NMRGpTekt1NGVhaWlZYUlpelhXNGFxUEM3TWl1LXg0bzcxOTlUV3J4MU10b2pRQ05SelZBcVJkTmhDT2IifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJHQ00ifQ"}'],
            ['input' => '{"ciphertext":"QLLxRxkzsJIaVXT5fjX8Nq0qsXOB4hRcxu-91dDvVji3nruAlMYEeHEZOZIUqq0Y1AaJRJQmN2kDZL2mmdRuRcpzvHXI4pbwlLnZLtIqnAA77lEVMHXzWPYHvQ0kHWtnkr0-6Iq0TvVduJOZQUaTDhjWy7wIDN-bsZV6XIjcNRMgI7df6L3h5D5CrKR2DIPEiFKg-Ijl3lwcvgV7q1tMySQmiV5xRTw","iv":"vnVi5xfl5HFCclqT","tag":"eqT0exOdsEPeULmdG-wklw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBSzEtYk9DSVoxV2JFaFE0ODR2THRzLWliTGdNOU43eG0yUTBnLVpxMWkzcjhXdF8tdTZBenRCMzNWMjhRVjh0MGJ3TmZYZUE4cVZjZnJSR1hGNXZSeHRLIiwieSI6IkFQcFk0V3M0Y01UQU5GNURiTzRZN0QtSDZ0UjVOWnQ4aGR2bWsza1dHYlJKeXNpdkE4ZVk3aFFlV3BmbVdQQm9IQ0FUYTdUQmRhcHlqQS1VZ1lIMWRRVEcifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZHQ00ifQ"}'],
            ['input' => '{"ciphertext":"cy6eI7vOAEC1PXvkVQcea1rl73JB_Se3busbGZ4PUy7VPVeIzYFcdHbe9qzqE2xwNigmja79m3DaduWyD5GDrywm0kUG3FVnNF5FkKsKzKBpdX5ubEDfXisfh4CGIu6ncESr7llGX5d4rCHd6If7NBvE9dsmonnOr28D6LpsrGFHS1vTs1mZW0IJ9ZIJJODO6l4nnTtpW4qw6WhIs5ZHVrTf18QtRdV0Zn2dqIlbjw4","iv":"JfjmVUk0rt5wgjxtJG9dcQ","tag":"dWe9-40TN3xItxfaVDJOvA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IlFORWtJZmtMamozVjhxV1l6VFBob3c2T3dRY0JSb3RVb0RiX0RvTDYtVzQifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ"}'],
            ['input' => '{"ciphertext":"o1AEWAYqwcfcK9gdrK9BJMc1-3sbbQsfmNbDRiFYPLM-ikkbhkkwvR5Jj-E_qwKhvix6D4nK6NMvO8h0Rjjg4taj1EPtvBOA-Ppl_tI023O-VOlOBVaaiPNTuRjeHdWnFnbZ2NOf7r9SUaXnKQlhboBqmzAlV_9iId04A2U52jV9YCe-QRC4PMiwiB7QaLOIWAp3pZDg_cdVqIOFegrHiZx2gcwhPTdCRl6xjF86YTQ","iv":"sgrJT1GnLW6GPZxQ2sE4fA","tag":"M4WVnIMxLAK3oVaqsVKZ4KqvgGObGAw9","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IlJYWFZQNHoyS2RjR1Zfb1Nrc0c5emdKQVhLWlJTR1ZfSWl2NDZHRklDaG8ifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJDQkMtSFMzODQifQ"}'],
            ['input' => '{"ciphertext":"1b0hOYd2iw-p6_BEkP6bwkc-ghNzU-8c0oz9Lk9-ksIKn3_uO3jaiCSPpgzrIWdtwM2shJuiS2awtVsVqqap2kUBI_mLxMUkNu8vIdLVMDOG4JnGu8xQekzOyEJnh3t8iJqukVeHXBOHSahuOSJm1wT9I7c94qziBxWcBfUTnPhk2erZID51iUcgXXT6ccnX3bVhGh7MRAh7Ayub9N7vhIlET_drNv1-nDytpP1VHI8","iv":"XfKwJSAkFOMfbhIzok1ViQ","tag":"b_kD9-BadXRR7VVlArO2NbJ57JDk5q69d-6V9izO8pU","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImdLSHp0UW1IdzgwcE05MkhjMkxZVUtzN2RGU2hEWWtBRkhWZ21nU3JReE0ifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ"}'],
            ['input' => '{"ciphertext":"XR-qBJ6l7-VNRgTzLsVkniRY7oDNd0r_ooUofbMqNDSXTHqcSQWhBayA88gfRybwITBuM2TcOClRQ1LPiGW8PceWgu-kXzRU3U0oUkhgwRdk19ZMbtBHkg-g8GX3VEr4rawUri4ofCFBL7dV9WshLolOY6R_L4IGXSGhpH7HPTht4It773TfAo2LPTFllfN0NYcRJD180VSAYtTEpK-BiwneRhHd6O0","iv":"T8_T58NnIjrQ3v0B","tag":"Xg2J1jQNHlpVGow6NWEopQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6InI1TXJlSmlFNDdLSkcydGdzTWI0LUkzajgtS3lLbzNMU3E3SHM0aFoyakEifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhHQ00ifQ"}'],
            ['input' => '{"ciphertext":"fkavWJbNKcmu6HkbHjOyjAEylDh2EyLcJSLry-bHi8t2g31UZimNTW7aKPgGVN97T3_jJkOpSdOYoRWs9nparpNce0Fqd79LaGgB0a_XOeRZNRzkfXZkTr71r-o7XRC2xTNHdqMQEd8mWXeFmsZD9I_ZTjyF6FCW_ljWtccJ1VBPe4bvTdnuHCFNzHLcp334LJTxuc0sgwlTb4Mby8acJkS4LNt1S8o","iv":"-eYt0kU6UUhUZccg","tag":"P-PGnb40IoWdhX2VluueSw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IlVnLWlGcWdpWHJ4VmlCWGxaUEN6UXVydWR2T2U2LW1UaHd6YzJJVlZyMzQifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJHQ00ifQ"}'],
            ['input' => '{"ciphertext":"u42pqwl2jiwX6oRjilAdTjlE8-0I6WXXi5DxjdT3NjAG1F6tFhn0WHDRZZVmzLfA5JKciwW7_GhBFL8EqWksLDu84PWATcsJwS2PEp3P3B9QGkqgoNoRstExXpYHHpPoFsgBhyO7mxGJ-0RWdKLPf9Ck2Z6Hn8JoSVLbIa28FGTNj46rhYg5Aep8BxYJf9csTRfPQQ33ZgupifET9oamSF32HVq6gO4","iv":"0cIuo8Jv_Vv0kyiV","tag":"8lebqo_Vzy8Xf8OPiuNNVA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImpMR09HTUl6QmtRVzkxWElSV0VtM1pyV25WOEpqRExlZjFsRVBvRTBNa1kifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZHQ00ifQ"}'],
        ];
    }

    public function dataPrivateKeys(): array
    {
        return [
            [
                'recipient_keys' => ['keys' => [[
                    'crv' => 'P-256',
                    'kty' => 'EC',
                    'd' => '_gUgAjx9zU5BKlHq--TiCjZmsdNQAgrv536DCTUM2vo',
                    'x' => 'Kuh77MGkweIENgR_3WjzJ4gEF47yn6yQWAeeNqYC5qo',
                    'y' => '1koAqIfb5C2PkCT1GYEcW4IcIEdrgOdMcua6G0Eyhtc',
                ], [
                    'crv' => 'P-384',
                    'kty' => 'EC',
                    'd' => 'Fn_Le74znJfY33TkqCoskx1pkgA_1sLnKvfvM_78lTZT2zfj4XC6uY_L8iRknOii',
                    'x' => 'o5CqgE0jIlCVwGKMXDsQmkOgxohJcod4hv7jo4h7qeRoysAV0YPtokMgv7CUpSCG',
                    'y' => 'Z3ZGVhyv3T-MudQI5fYNmkO1BzqlHQJHCQ9RQzqa05QOsUZo39gjVC2EhRv1Z9kz',
                ], [
                    'crv' => 'P-521',
                    'kty' => 'EC',
                    'd' => 'ACebnk5N5RV4VFhrCmvp-5w6rsQJvHdvvBdJkIKmq3pDDreKC0vU-K2oYrQaX5vPuI1umnVw9qxFq6QCsShJ38Fh',
                    'x' => 'AR05Z1Xe74_lcrJbhKg12jijs5LPbLwcpHDGETssYKRgbO3-4l7egk_WtLjSeXmDvRfkww9kKpFdKHTqmDYSIzxf',
                    'y' => 'AL7NyrGpwcXqfvmQb4d7N6vO7REegUaFv8ea-_EXyA2eJciZJSmvipwpxRnoSfkNuJ5yJUGdjg_FtaddKaLdJEf_',
                ], [
                    'crv' => 'X25519',
                    'kty' => 'OKP',
                    'x' => 'LD7PfRPxq03bd0WJyf_1z-LQevmrbcYx7jJafep3gmk',
                    'd' => 'pSdgXFRYMvOa7giAm3Rrf5Mf8GnvLz7HtZKu_KN06KY',
                ]]],
            ],
        ];
    }

    public function dataRecipientPublicKeys(): array
    {
        return [
            [
                'recipient_key' => [
                    'crv' => 'P-256',
                    'kty' => 'EC',
                    'x' => 'Kuh77MGkweIENgR_3WjzJ4gEF47yn6yQWAeeNqYC5qo',
                    'y' => '1koAqIfb5C2PkCT1GYEcW4IcIEdrgOdMcua6G0Eyhtc',
                ],
            ],
            [
                'recipient_key' => [
                    'crv' => 'P-384',
                    'kty' => 'EC',
                    'x' => 'o5CqgE0jIlCVwGKMXDsQmkOgxohJcod4hv7jo4h7qeRoysAV0YPtokMgv7CUpSCG',
                    'y' => 'Z3ZGVhyv3T-MudQI5fYNmkO1BzqlHQJHCQ9RQzqa05QOsUZo39gjVC2EhRv1Z9kz',
                ],
            ],
            [
                'recipient_key' => [
                    'crv' => 'P-521',
                    'kty' => 'EC',
                    'x' => 'AR05Z1Xe74_lcrJbhKg12jijs5LPbLwcpHDGETssYKRgbO3-4l7egk_WtLjSeXmDvRfkww9kKpFdKHTqmDYSIzxf',
                    'y' => 'AL7NyrGpwcXqfvmQb4d7N6vO7REegUaFv8ea-_EXyA2eJciZJSmvipwpxRnoSfkNuJ5yJUGdjg_FtaddKaLdJEf_',
                ],
            ],
            [
                'recipient_key' => [
                    'crv' => 'X25519',
                    'kty' => 'OKP',
                    'x' => 'LD7PfRPxq03bd0WJyf_1z-LQevmrbcYx7jJafep3gmk',
                ],
            ],
        ];
    }
}
