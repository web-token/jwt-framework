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
 * @Revs(1024)
 * @Groups({"JWE", "RSAEnc", "RSA-OAEP"})
 */
final class RSAOAEPBench extends EncryptionBench
{
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => ['alg' => 'RSA-OAEP', 'enc' => 'A128CBC-HS256'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA-OAEP', 'enc' => 'A192CBC-HS384'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA-OAEP', 'enc' => 'A256CBC-HS512'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA-OAEP', 'enc' => 'A128GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA-OAEP', 'enc' => 'A192GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA-OAEP', 'enc' => 'A256GCM'],
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
            ['input' => '{"ciphertext":"JtdnkBM9DBLdMaPn5atpj3bT3ljoN8VhCPrdmx4zkpy_KHAE9qD6nKi6dxH7fBESp1S63_bYUIva4KZVT6wF4iGsQQJp3E5IdljeY5J470Ar4nBg2WB6MW6oUPqtnHhs87fLQSpwbDlGNygVUIo3_sGh09eGQyL3_96vQ1Sj3eOxuHyfelYw6COZTWW8o7ikaAgBY_RfMNX9jtlAfKywZJLo17YinA3wFwQpP-Twyk0","iv":"HQiumBYcqqSskMxGpmDWxA","tag":"xV5FQiaG3jTof2bWxegZlA","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ","encrypted_key":"PBxpGWgGiM5aq-rUwl23M13r8we8q99HbUsTtY-maCsDM7AMrnBKctPgm0WdxncERN9hwrypI6bnI4NreTpGvPoLtKK92jeJXbkrEhCK7CxVQbShkFSCOPh2B0J8zRsgPDVs9JGU5nU47ywdw_bjqWjP6zKzPJGIz240zuTeANs"}'],
            ['input' => '{"ciphertext":"Qb6T8ZcChbQF2hf2dBsTJg7E4eSd6eYIaUO7wFjMq0JZabR-T6MSUvJpd5sBvuwee0CCIMJfeDO1tWv2dSYcZZJ6_JFmUtGI4iXtK4t60fV3-ryTbU-kVtIzQoPs0WdPoH2Ly78PoQBXom5Jmd5b0s8HKY1WYDMPOTAFp6Kw3QNJDN-vYVugOh4ae8ppJw-Q-kaJsBui-y-8d6XLTPQT6ZySz4BBKLEMXxWhhTY4ghw","iv":"EK1j9a1II8gJJALo3VK4Wg","tag":"T_H6BfOD1OuQ_HHl2AJbrYGsp6j6hg2T","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJDQkMtSFMzODQifQ","encrypted_key":"TQMM8tef2w86BTdibSdNCc1OM-S3SOZ02zu304wGuE956jQD6kHUsI4ZEpbA8XXRA58ywUCkyJEE0j1IcRzah4ORAbl2Spxd56I2sU2vfpsvz7YtR8N63F0BSpvn8UcINXPbed9ECw9zwUyI-DZMoTkfLA62jIUHXl-t78l34m4"}'],
            ['input' => '{"ciphertext":"VUBZeGk_obcIv9HtWPXC7JPLHuMdIuw6XRktelYczWUYhCwlCDUQ7LpDdVCV6fvqoWjoraejWZ8rvguv2k1jVnCKn6U8McjKbJybWb5GD-4KahDXo-PprZXNcPxovZ8tEvAeaaX9BFVWPVOEJPP8MWJm3STkfYWKjS9QK-icIFfSOIz9t51K5cb97woYeN9SVA7-5E6Fb6BJuqAPimkh8asPt8w3iU1iUjSkXBfsPPU","iv":"pW_0kqz1zoN1FrFIDsltUg","tag":"uCaFoOdSymyx0JGC1MEFH71kOKlsuNZa--ZN4EsdrBU","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ","encrypted_key":"n96w0hogHs8kd7DlzLyMrSsPdNHhU9Pvc8jWfFFuKC3S1qPsjngzUSsXsELSVzpc1qbl-dk8YSV1hxK7uFeTjYpCIm1tzypNsGnQCvGCsRdcOw2llgg0TrFsKROI9vUrzoUxz-5PgCAqsy-bONLVvIhuJ1I-2nosXcRTDSthFpk"}'],
            ['input' => '{"ciphertext":"sYe1briI2Z2fKvfRGqK-XvCiQ6mvfwwRf_E-fOqhEhf-e72nxnmKQQWHtiBBo538s4FzVdu2J9SXAzy3KrL1lIpM3B1Pg979_u15OuiMCh8sbzahMwrtLLVJJA3p46YgVvtEJNOgPDnF9Mglzyb1dL7YN8gd9jEaXC2wChh7ihKTKAAm3HN_I6XF7XDWk0nFiZC1jzk9bgSRHfOOpGIQbVsgH7hVsek","iv":"dEajjY72o58b8hNz","tag":"qfF-5Ife5-KARIlXCDAQNg","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ","encrypted_key":"RGgVxfkKItz0jztVQNX-P8r4nKz1e_4ytc14Zki4dNUu3ZiO7KnBAQxI4GEWpCMWTu-jHHQS9IMYnagPkQHdRKdl4oEG_I2-_7JzTfcE5b7CbBLyY2yHnQvgbHkkMegglZyHDfw3tQGpZT7LvFG0RzYb6_MAkvGHfLtYsMwxEpk"}'],
            ['input' => '{"ciphertext":"m1F54FNjz7KYT6re99lW1EDZXaViHL2mNvjH84X2xF_A3mKibZ5KYxEytKwDKOG11wQaCbbIXlPfKqA2zRta2rAMTz5SHhwA_qNeS3ikHSfaoBhBpH1TVav5tnvgG3moSSEnX-GSHZKUzMyJODG1kGg9tnk0ln9Dp41KP_vNxcOmeKvQX27tUfgB3iDFbFaEXlS24wu0_SbF1YeX7r5yDtBpfVcakXo","iv":"MroHZRvd66Dmckxy","tag":"NyH_KPznDOXlf9izvo5sxg","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJHQ00ifQ","encrypted_key":"JfnmYf1fP9weDBXzGdxrJb8VhDKVuDwdh9-uYZJAD4xGuQEP1uq1OmZ-H0V4mcQB9ZOhQoxQQ_cpUEO1pAIn99vo8OMh-uJM5Kxz-DCLV3xqdcPqjnvW8UBrU7FEV9eyu8vTkTXxKqwPF5S-3xHjp6lgU12iogbqu6JfjEqx60M"}'],
            ['input' => '{"ciphertext":"HpGXQ8qM96o2dfH4Ky5XnGqT3to12AOVx3HTjPvldr__Jf2fZ5UZS1602k6X6oilBenYzs306Bnge6tQ4K1FmMXBqClCbPIzf7ul4giVi_8xq3s78uV9YcLLxQnxDcaY2JzifwmTnz0BNr9YbhoBhjsl7jjrp5ISe7m8GSneyfYDLmsRuHhjZS4c6JdjH5036LAG-oFLWScTGyLUx5s8i2VdcZI_AJw","iv":"1crBLrp08Au5BbXl","tag":"EFCk9naEr477Pv8X74zKYQ","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","encrypted_key":"G6DYOpfCRSBboaciGt7-LQf2KrwEBWYbHz8a-F2-O_Cv5qpgT8eEPsEqyC8H4isXUTN_wyybii8nsIkNBFCF02WaxxUT6EgrryBhqo7BpoggL88nOTsHHuZjMONIVb3kQ3PmzsQehe9NGySOUKwgHRtw-wj0lwa9HIGB2vEDxig"}'],
            ['input' => '{"ciphertext":"dxjvQRhPrS3dF_xvP7ygBeshHEepkHhJ7VF3kJJRs4tA-3IFjmgJBmmtlyCYubE-1b62yY4G7wa4xagro5Q8NYVoF2o0ghmb-mPiq0J-NvSgSB5-9KwBGN5gGc5QbU0vVEeAGxBdp4LBX4Xdq_L6-Cb2era7bqVx5LIJSf1mqxXffHRExUxt4EISVwY9CpiPnhGmuFoYR3LrlYbQy11CCaESCayH7rg39GxLHuMSz24","iv":"xoOM_UxZby4fl_nO63rqyw","tag":"CJ2b-KjT-OYRmDZJqxEJ9w","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ","encrypted_key":"bgteY2DzdUHC7CAp1pj4hEBet_sEwlcZLbQ7P3Fl41PMntmfsrPjTZX1wMm_6rrlrmVbj4Jg91DtUqRUdRbm7fUNRBK9aYFiknpEtc5i3fulVXNrBsWlqroNoha7wobqJOeK7tNrftim0xKo4njGtUizDIBSG5KahhPUMYY5j36Ij4jwViM1bax4Fp-KqoLmm4uNQCkPFgbob_Hhvl5LqsymEM3BayK6hCZY6gjkXPYy-qetscJ8wK8ndk0c2PmVl56vcmbrDbLAjrXkB-FjFY0yDmljAkNAYG2ONwPWk6UFg97367AeJEzfbelgr3SP1pnTXhyAQawsumGXIVr_RQ"}'],
            ['input' => '{"ciphertext":"LX-i9m2eIjTrpjCsuTNPO6ELSduvRqF9FLG4UPN_qydlcFZeBavQSc-du8IXLZEtw8tLgMu4raGOYkpvXJzmEz9TJqnaO_sfVB_NyFUVOcsDRgdY5K4Bmp46WGVfd7L3RM3FoJWZaCA-Z-csw68_8fXiq8ZCl33aqU8WEFagOu8dSll7SiQUpl6B_Bx7-kq2OTfX5r5XPmOpMlpsJiW5n9j1SJpZTQUfZCENK39BAVg","iv":"96IFzit5OiPyS11KtUbNIQ","tag":"kWMtlRys8X668OT3StMvReWEkRQqezSy","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJDQkMtSFMzODQifQ","encrypted_key":"jVZUuMlQdN1FsekWSzdla4UihupJCJpDHtmW4WCFyOmmard7jUdKMpXWkTCcHOoIs9DsWcOmoEVzNh-YNcCzDZsWJj08cyF7J8w_74fRx3lGLSKr86qs0cGyj2qkeSrrM2nSLPOI8JnGxZMC0utVtCu9-8goJ2ETBB3bYgd73mI8krrsY_WFCkqpoSEWcpNJzykC6_FCLELt49XH8simr0jfQkswAlJaUyf1L6S-NwUxlrLljrpz-Pf5HriD5f_C_3W2KnpOm62-hqQCV-6pvqQ4bN93UWLhqsPzSW5i-m1CBJOMZJNMn1IIpL79leKSEEwHUakvy9uGS_Yyp7iixA"}'],
            ['input' => '{"ciphertext":"gAdBQ7hjuMX5YtjCBfBK05PIi_nI70F2MvkXBg_ZVKsVvk7eHJh-SChbxgXBL9jj8geeDmeAmWEq2EHnKeJWijDwCVWKOYcik77sZTVt6rE2G6TO_voznLhBe2APUNIsC_PnMoXoqooQt56Nmk_RFkWF-C1y7JV-n7VyCn5_RkoTAbnsdP5oKgygpBuLCpR0RQQ4vTwaagp8YCcMY39SsxyDDu39QxNhMIKHpJFkQhg","iv":"0Toz-1TbKoLMgZY4sF8Kzg","tag":"TPjfXltcP0YiWpIkfGpMtYeCTEjzycOLLoKNb_AFaXw","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ","encrypted_key":"DGz8FIspXhuS0d42vh_zGr8c1moS4aXSHQQwv_N0TGMnsi5VWy6Pb6q74hjppisC57cEDZPBihhwoKP-VCwo9q8Bmh14PB4Q_BatRYBmeuthf9zEWWU6vuMb3T-Oscf4W7Y-j6BRF-j_3vmzh_zpvPbBlCS8_PMtSIhyXUXQHm2Mms3gLPS9J0HO5TvSxlhl87E2YnF97_r6aj_Z2Q1dt1gbn40ul2mHZT2BVsqfFSGsaRZWT9TDxx2AapfVp6QpKbDGm4xof5pmcHaQLWWsxcSMfgZk4-WR3GyAb2uhGdgEwXZpA3x5CI5xYGlCfQN3G4eLhl_S8fVcAK948HNC-A"}'],
            ['input' => '{"ciphertext":"ASzuUXMVZMB1u4sARjXgFy8TOLHbxRnSH83E-AqPDPEi4Vys4GGPMb586OptbihnljtSjluMXO74Ts8STpQRYh-Ayuf3_BexjZ0J5qPs48dQ4L3XATHaZJPmOfuq5oQPIBUf8yfu5HIg3pdt0NpHSHhMtIDk4qzGw04jzNjiRrO-XOvEuaUtdxyG6SzJLkC9vjGQIoqCc3lkNt_nCYdYvlawmSpVSOg","iv":"J2Gv1duwjMpYBiZl","tag":"-WIRo4aQY1u8LnuCU-U6Pw","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ","encrypted_key":"dG5fw2ecXqZdzv9u1B1ycHB8WsZz6xjEVXHPKmXfX58Tjnt6ib0ujjJhiiJ1h3DAJme0J3mNGj7HPgxFgfRYjMGqKMlsflgHRSQq2Lax6L813Zlh1sW2pargM3D_Kvot8B6Anvzw7B91f7YWM0o2KtjtW-vaN_dI8IZYtzeGwTt5cw5wpSmN7GQDOwjPXCPCvZW_t0_SrOBRR_t4lJMXM9dk04cVG5EzMBUpej5VZWK4QmFQE0rQIhXEwg1D7DfPaQaD2BCYrix_xiKKGAq668F7buxblY6qcZ3xlZ5OWb_ACBQbPqUXRQjACzhhoJOUUH03naUCbFaRAKhgRuqUKQ"}'],
            ['input' => '{"ciphertext":"xpRJ9HfjZNhiwa4lB3AP6zlTH73VoKbFFkxe18ZGBbwMUGnvyPDMUXqhd6xYAO6bB4jyqYPnCzrGsqSQJuMfUP1tJYWzpXp3XtfJhltc4YFZTC0B9XBs_cr5cLkKG8lMRWPjLMJJNRykRub3vd9quiRx975V7B8kaMea8VxuhqO7jiyysMrrPEJ0XD4S_cqsO0mx35V-nADDEFSPG42hRyd0eGfHZvY","iv":"p8ZRC-ygp0ZPD4I5","tag":"LpgaGEK8QNJFhWIQfeJZvQ","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJHQ00ifQ","encrypted_key":"FqPsHMY4Cf_nBfOX3ydQnvQ_r9uFcWPtvlMDsso0tOy3GsnXzjtMHV1MW5intPU1nrnDQ96-qkV823bvxvGMhnp4gGdPGFX75Rab8WtakrhYCR1slO2JQ1kLzWId-Q2AbrHLU12LPK10H92jIQNfhKV-S6H5Z5aM75KIPNrMltjujssBp-O0FpfuZIrEr1M2egnOvGJpTvg9rhCzqGB8mppvSqNGQzfxG9bsIaOSOgkNXbDaLJd2bDB67bx5fANrtzhH2ufPqsURcVHckSLV2jciAi6usZP0kJKF9bDAEh9TPPykN8OraFe6V43ZyBJraZPotKXwYSAz-CKeUyZnUA"}'],
            ['input' => '{"ciphertext":"a0cEWXJTR2qhbkE4mQe_o6tnw5lIPIH5ta3qO0etKMME_BqAAW8psDljIIcwHdnPXwSUHk2ersqQnnUoJcgoKchsqbzv3lcr1htqjiMlAsekxXCqeIop_lGCfh8oms7J5Pdzxcf2lYWxy3jaRw46NIH-vCIfAJ6vG2n7bN_tiGwBoTkW6e8Ka03DbD5qCy7yLVgocMMeMW44fKj4NF2F0fiJiLHmbEQ","iv":"nf5j40aPEBokKvyV","tag":"dozonj7NaDgtujKnEVcjzw","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","encrypted_key":"QlCvG7s2llqAPRW8ssnH-U8BSpldsjw6HoGNzfUWmks7oGbi_4KwqqXdtdfnkbJu5VhK1tRy-f1fNCrP85Z95iTnHh1m07h7SXNlVtz_e-VRInwZaCRocYe-ysSwXdhHyBObGvACyYgE3H45l_wjSem1VxZMwvKz3Pj5s3CqYYrzI8nBjBePmxYaTwgFwJ5757V1wma81iywqc-bxRVg6CDaD6D9JThycJGFPpaYjl7JKUKlsshxjj4BPOPh5gRE6SYGQmg0fJSIMaTTz1XFYn842GzeYWTAHU0Uxap-dYTen6Sx50eNj1dxA-BiMc4sLqgrRrZ4VtJNea8upfzdJg"}'],
            ['input' => '{"ciphertext":"Pj6dOq86y3q_fWIYEbm4HeWvxmrOxQaTfR0Ks8TIVQCy1FmWRmA8qa4eZIr11o_2r2TeuffvhcgHbF-vBSYctFBizgQNaV-ohmJ8R8QjhQk61GGJfOYSzsJb9zArPppCxAMqwhs6EyxYqyOywEw0lWmmLiaNvnIBnXxKJOIeiuuVUSUsBUFwQX0JOG7VxhRrblR9DSbF_HxKYHWP0K3zNiTmq0zikIESUpXS2xSVrAA","iv":"VR-xf2ijkZ6lbJLXHA_GwA","tag":"50nZKsL8ZclrlCOSi0k7Lw","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ","encrypted_key":"Js33J-239Ph1hoL_dAqJeI4unEMgpyVZufkZsqVCapRWyn54ZSjVyhzsF6fVwWrCnLKZmwXX2eazsIX0eVsWpGfhvb7JuOmEwaTCtub-IqCKHP-twnCMO_dM_XdFtr8ch15TuMqCUbf_PIzKglj3uUhJbDmt_TLl0VBoAcFAuIoUYUnzxer1PIfT6WVcJ2dxvkYY-KCLUwPNpKJ9Vu7DwNbNm7HwTZlivUuMhLyb6Oc_4ssOWHHs96e_4Q0ZPJs8bhZ5oCgbugzLqYzfUirCw0xJHMimxwfMT2T8ftxr7swD94PnwNE_zpDOlY9rSv8NHnP0X_WAitwqn94-kVfVAAcrvtIbJRcaJdVDFxYiePypJYVeVYFxueWiLyUQz2nIx7fidzgFwcAFykxYjE1S_EE4gqCgtomtxuDz_daR9TM5LX8E_MWKoJC5X-BEKQDBO63pSZN13nfPWxJ_876Un_BsHjuNZIBYunqwEQ8FAKdH0kjo4WrDET1XVuBskylXpZw4JzsThRLU0sVotUwtlZZ-P3v6ATILUl63UDpQAOQxixsnpJkUiy65MmXbznVjG_PlJtXYSdDrcrLmkEdjP5Hh7BX2_kxT9Thhpt7wev_3oAnrMloLWnM3TAh0-eWGfXN85u42sgnNY8aHp0YiUFPKIM9SdRiSbd56RH5S91E"}'],
            ['input' => '{"ciphertext":"SCJCZj_IpM6VC-RCQiSSScXTx6i01Rmy1MevZvpJ37AQaCZiyCajQQ4fo_Sbs83WmXVrT1Mh_h7k39uH-cy1wqqDVBuocNLynLeO5gimCv9Gc2QiP6V0B0hcParhnttkYZU_eIIxYNRSvZbZxVHDasmm5oZ71vPXOLQcakk56iUxN430SjXcd8SeK733vx6q3YOo-0rmGT0tJLI3_V7VNYtBJ6WlHQXn9eUhVUK9OxQ","iv":"6bfRRLiAJ69GJRt8ItKpcA","tag":"_AwOo7Ns-4nS1D_OYxxsePH94IYUFVg8","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJDQkMtSFMzODQifQ","encrypted_key":"pKls_LCbXnBCTOWtEkn04ymw6ci4Yw7ha5BUCtfCGYz9LvCKfEgUh8As6Ss1LYRW8wq3-3ugdK4iPFQFkO_yh4_vMwUxrCFRA6dNC-xc43h91abSL1XjNKx38glmHdrTP9se-xF3Pnzum4dmzg1SgHBe9YD6uTJRtpmggfElBcSTaNSDathKcTqbHcf4OZccVEwqOelWZo38nid5fusQ8qRNjo82KDBv_2g1yB6nHanDHqw7DLDFKC1lIlU5KB8ejdfmrh0bIKMLlu4yKLNlX15vFJnPSsusxEVwKyB2cbFJBNPvGY86r1yNAvqGc1EIqL92MT9t_S_cGL40CrwgHZAXPMTw9r6f6UwEaA5ecWJe9bsH2J-I4E5Bj-3KvODm8uKLg0K6GUTiDQl25hufZz27bX0ZQ9PYLvj0zYB_KrcG9Gf9-B2XHAPNo24GtH5zDoPBpJsJxZz-l1MxKc_UcZo7J77GSglUOHJt92-P5Vrrzzf0VMRgqPSQMRi-GjYJt22l923rdZRYdLvbEIrEemaEjOzeIPczqgTFlz8fUIZg1869IY0k-PTg9xbOxdl0g-d6lwMOcPZpztDCqFd3s12Qez2FRUWAtBwlIwayQJk34vTsAyJ0psEsfMmYXXepx2SpiLfCXbbosXzY7NzfRTq-pqb3xnylYzZNRmzsUjs"}'],
            ['input' => '{"ciphertext":"I6oiXBKDe6u_kE6fbTWgU7p9PAxRAOzcHg8BY9u6yZS8hc2Bu6CpX0aDj0YZLkP6uwyJ3Yog34PR1Gx_x84gCUg3zuDYg3yHkfwc0HmFOE-4TsEPz1qBlPyZQjc-a1cY-XG5rzI6a3Z1WwdivsrbHPr_LoGmNrkNdjiDgR6qBYuhHN3o3uyCVoUGCZQLnjsD4eVqDaKqWHWzwUprhXQ_MqN3MUfUut6PXKreqx-HaSk","iv":"o93T2Wb6aPWwCaGu9x8V9Q","tag":"FT9xSVAHai49FE3vCxHLyLQ5nG0ANjxqglwC53a3AY0","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ","encrypted_key":"HvJIBCziPg3SEH-AcBOMvd8dF70XQ95ILE8BEYolxhB1Aug-HFPDjHEwGysz-5Avq3bvub6FxQb9NBACJkZXqFiHp5X4SQXs82P-4w1YtYgV2rRXvmUv9_vrlTpTjEFtDZ_BbImsyV4Nua_CHQPplEdtKCrHTKyTA5XKHw536WioVBeJVtlddedqCt2cNBEnOXDqe7B9etEElY-nM1UpFEujOA5-U9gGWCeFDkHz6iTD8EpxIPIGuWuiyliDyYekT0rauLmIxkFJufSKpw0ltjsiE57JYzfHqNHmq1w-5YVi7I6eFwcDjBcb-hWEHASX-m8ta3QCYfrba6Zha9Gpi5tiQ6tHS212EkSW83KhK2UZ9h8XqFJuYjaEH4n1RJuwD4QXhwL6tTyQBNR1F2KukZQ7XTXbQnbi8vx5NmjlF4li0APLrEcdwQOBk3KThTAptitixkgYzOf8eaYlLvxS0YjDpUU1pAw33ijhlzTm6sftUjGw1BlRFNTezk5xut5A90VP3-5KnB4DszmziZhX5B-e0C33TfyZns3gnU-xnv7PuGtqTK6FZnWNd-tgRiBAZa9jZkC9eZhFmTscnnzYg2IfbdF69uRuqrPmzczmHh9CysiW-yjY7IaYdfm6EiM_4kHaGp3rgGvqi8ner8leq7ATRmVaoTAIMuzWNGFDL00"}'],
            ['input' => '{"ciphertext":"ndvL_g0t83KLzuklzpJ4KXartd1efSz3YIsI05epP1o_1KEzUizcaHarNe2g3U3dfjpeClNTG4upsjxwUJiTqLRU564CfhUrPnC0TyO8rW6y8iJgEIo3dAc907QlsLMAj5_6QMaxTOswyPMOt1wBjC6rktjuxQyWMnEo0RQKgsXf1f9bG3HGQEjdi7HpLSTOu2SrpFcMjXq3CLvV86wx5fkfHLjDABg","iv":"sT87oRGv_jLy0kRe","tag":"JhT9pf99SRCGaZniWxb5dw","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ","encrypted_key":"gU3dKyI6hYr6NmJ8bPuXgacnajdum4LpRNGrYVs-WTla7izvUs070lWnwtpRgG-cdnZRn8GEXJta51p6_60njdUTfw_7dDchilJLvc3Xwhlu7LMW9X9gt7IYsoXUiRPfTKBsFE0rzIRr56TWDvpSJtrAo2k8O-1K3uLOBYTFEyEsL579TynqDCMcu7fo2-ss2yph8-NmXsxMG7GXjJwZrdqNJlJIw71x6K4eZ_t219amRFubkWMMY_pbcv0X4cwbRw0D51Oa3cFEmRthqVkUgkmATZLTWnvNukNzCuAjIbfWseRj-Sp090AIxZs34ir2GWmlf8oMDY-oX9wIK-GikSe8wSbAgUSxpu3IbeSc7GQfzRY0ah4Byh10tk13KcrOvgKwIbWyFSuS1RFbAJuHtm1_cYIDzgvyFpPMo61hmsxJxjpO-Am8SN84R1c6xtPtuzU0LCURssMRXpbS2KzJ0khWL2o18maVaN3QPyI27AAzfI3lhQT3b1OHeOigI4f7PtTkPHO1bV7h2XvTZhMDIFYjqBibV4xmJpTDTKdlSkrd5a6eHAhjoIUPsfJQSmtoSVcbNncwXL3VlwxG1u_4yv7Oad5UQp3bs5bDgGe29BzCdrAP29kJirT8uNrPERANpOS-HCxoalOeh-Wutt8cSMwGVCb4_9ImtqM3C__Turc"}'],
            ['input' => '{"ciphertext":"BlH1xIp0sl06avNU6ilbAFYazGI2McXYuMVbaK5HT3G6R5Nslu4c5Pk1HdqDio48h0dzJSyg7tXQfBjiDoB6fW2M00mQYB9i1QQbuj2axdycE5R5l2NhoVhp-28DBynWAStkBiie4ND2YpAJGObFXAAHbi1OVzz-N8pnK8SguWRezQapljC-besKyQSKYcHaJFq_hhxGHBskTC89o3xBwpWQ2lchSvA","iv":"3Ilx73gx6nhs3cGy","tag":"vjk7-Ogspz8hsw37gJ-9ig","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJHQ00ifQ","encrypted_key":"EjGYVkdnnTFJ-zVcDUw0XD4PK6iKzaG_Qd0tLycGKmEY4-YXX71ld4sFaXW8bmLsrTPKeGNg44r1ZYAdM6V_1DBMc98uOksq6aYxB3I3M0l6JNOgp4CvFbDE05e10v2bLY81a3O6yav4yLq94hl2eRnlFg5meNK4xhpwRKo_VsKTbNLvbx6BARwy4-tpkJrKw9G5JiGJSrQMhx888sp-GoKLb-TWv2_5SYxpGGPKU6jAJaJXijWNfnWxHjhXJhWSLFu4As64i8uHRhF3FVSz9g-hDuU9HwPPwSxEOm_TwfZdO5BU5N16RE8l6pgDJNmvO1Rwtvthc8Ngf-9v_LDFK8radc_Ne3NJc4kORRd25Cl-rxu9_1e8SYFpEhHL9_MXylBe4rxrXg-GCutwdpm9_RotogJALd-qQKy0zBdMRQyVVoJpC8lxeOo15q9Ztnr3hkoqtPVOAh39itIlQHOzG2PEjrmcXezHAFxb6ezFOTZVUNyWRqV7jZDi17YtDUDQfPQRpy6wydCRpmkR19W-6cUJ-LQJvtU7YhN-2vc4MWZL98RCoiJ72hTgocStquEa2YWX7RZcKKBAjqw41ZZ5JtCUiIBm-4aSWRra_FNcGbIwkbt81HphLoEyCIr3U-fP0gG1H5QEXDCml7lAgcWKXHbpKuVQt2HNslCcaLBPVLs"}'],
            ['input' => '{"ciphertext":"iTzfPt_ytyL-OGKtXaJLY7Y3A1tLnYuYpZoR2IWLi2xINT3U-Rw8p6KTVBUUwO0O6PrAzXr2jypJQ2g1KvFkigu1GGQgTBbvaQXAxvQjlZMqJxRkxLUofL1a_hW2X9NzSHM0v3ATFlJWyeXeEaEKknK5L7Q077zVcjO2RRVxw57WAg1rgN8mHOqKOdvqfXvvW9Vkp5kKZ6LJjiDH5YJhw9liVKEO36Q","iv":"lZGMh_o3obcO5XaG","tag":"iQB1Xd-uWtPw1uBhO9uxYg","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","encrypted_key":"pCgocOLTFZYWbxfrtR_AqKGDI7EkgVL6uBMTybiCo-ws74pcCwS21N-SOmPAZ6olnXZtoZNnVQMHhj2IKSZNOdmjnvzdJgLCmk8PyBrj4WZTU-ebPArKyeYjwSRpOKRFFpBbk78KatR8lu7wfmgKhSAjYBLZ-eSlWL9J8SUXs1zX9wyPFzvkGOSwrP__WnZdv5-J_9bggexerK1NVnZJrm8quVqmD97udcd8KSVF6ijxC81ZAcViJ6WVgFfynhaNjesuR_T6MCDyuhoMYlwkzvcou3MgYfblyLeDzbdnSdzYkzqqgZbFErKJnD7tErRqpk4w1pCmwgDdDGSp8-Y_h459-CL11xxVVkLCsPPOdpsUxMem0zmrSA7LzjTU1dld6nupcWM0ZlUEFz1pfrkVuMRmL1b-9o1AJxsLtEbx0MwFPJMKnPZCdnPITTK5MvEdG1-7CRBtjxwE98JMQ6AYEf2VKog2ji1PauDo-EZ5v8BvTbwPUrYNF-ofM_S-dzFXEt4mMRJSQWV6oCZX-OWyfULNvZywd35Y2nuQeZHzvtoBU8d8SB20iAezl135TgOKuwoNosvgUxXdwsVwyWdXoDOwcYURVgpef0qR8RfrBN3khIuhfqQOopKSJpzgFVnj121Db5qV6-0nu0Y6hkyj0EBvLug70wZF_oAfi0kCPr8"}'],
        ];
    }

    public function dataPrivateKeys(): array
    {
        return [
            [
                'recipient_keys' => ['keys' => [[
                    'kty' => 'RSA',
                    'n' => 'p_Gffumd-Rj-hrWEKMZdfOw0JZci3dfVCkLYYISt60ajg8aktRR6Rc_1m_NMPIP2_BK5kXwWb74lqLh-x0iunfpgxHWnw4Wy00V2YwR0MtgbRW4JYyJjw9Fj7QooWdqRV7OoJb3VIpmBqr-JKjTV-91W6jPWcQNsUFYL5JsJ-sM',
                    'e' => 'AQAB',
                    'd' => 'pYj2sexpJj8pmfPOaTZkrZ5QJAEdf9aeiTer-S6uEqqUv22LqWSexLMfHvEn4rocNwfp2umZX9jnW69GXv1YBouBqrnN4vANPnjFp8y7ejKO_XDzKrf2c5YMgm7l4eE6aCHzEn2kFy971f97HN07KfiHNTln9boNGVsA6TpVrhk',
                    'p' => '2zIyk5fQMKC7vHqDCGQ-xEXRgiTZsQ2fN5gQ7rDsvGJdDBfpeWA8H3_bidSCNfAskSyhLoEFwQplARblm74BVQ',
                    'q' => 'xCRtcvPKTJ_uRZ2kxn8zMlETXcq1CBbuMLhZDl4QT6ksgAoOqnqITwckSXL2sTXTmDwgtuB1HYXk4TAXhwbrtw',
                    'dp' => 'EVJfMtCtcBpTm6pmznP1jdcinlFBLr-v1FndBK_QlXaEed8t4Rycw7R76eF0RMTtEK_hMOabSM0EfFiN3ofeXQ',
                    'dq' => 'rA5MWEcU0YyFhlnYHiucrGnEdEUJ8pOy09gSfvDym_6Jw7OO0-rywWhBY5DOZ_sQpv0vsVxKP-ChOwxlxxPCFw',
                    'qi' => 'FKqVgknFuntcWE0b4NSoqROngDbxLd-lQ2DWg9z7G-knJTizDwj_7tSlNbqYlcbXXNf5vRnhQCePb4KqKyPh8Q',
                ], [
                    'kty' => 'RSA',
                    'n' => 'slVGbcg7Mr_tQmfDJAIWrlWjBWpi_JzGTjCCVZGOikH3ekkUEH8TN39WJ2HXBwSNmT4bh8eRJsUyBKYr8yz3UdEUJxloo2SVZEN0rXh2Jb84OdObom1CFbPg4yQOvLN57pE06zc7GzQ1MKF2dqRFvyEyibKcs3V6J2DjvDXbxJAnTOmxWjLRKa6v9aKrNCakK_qSRzEwR-IbNnGHSrQr1RaDQ2gQ7FuVuNOJe8rrdlP1dIdg3ElzvDgjg3NY54b8SqwThXt8gRM1VKg5O-6fRdHLPS4L0DOElDlc8lboqA6oI1187cbLq__4P8c1pordIBmHXdbSd-4Q1BYnNVqfoQ',
                    'e' => 'AQAB',
                    'd' => 'rhaTB06lg5ha3C2BESC81XkiCIJfmWzOJbwzL6dFd_CHz6eRX709nDrBdvaLO_2U4VkA9R67sxZkCqfRVbW6xfMN8lFalc72C4fSWhmzdIvkLodFcl2oWplb20Dy5gFq8ZptB4XGPHtNxWiJxa39rGSS-lsToBj5o4FxL-V_4bSZOLWLfUIaFS5xJ4xZ6rLAH1gd8AlUbQfcwToDCjzyWSZDHFqCtOr10tD_3OeK_SdQoG4FGpnNo4WdUstTRTIYGaN8N_ThJh-f7bWUomEuBFhKT6FCXkxHbPfq1t3q9YhQBmg2_Jw9gUWD4lukPDpvdp-_blMRqs-9JNkL8plEsQ',
                    'p' => '53OBPF6RmswOMkuK8MhXjLT5NNCaFce9rKkpK-8KHK7UqVHqW006mzJ3kYVm2nIFODCqSO6RZcmEhLgrpZhAqbOl07lvh5nhhiXJyjaw6rcCumKTbjfX8dksnxHG2ik0Y8-1PHJwhIRHrjAeuf17XHgaATKOSxDVYSk-A7MClFU',
                    'q' => 'xT96R1C3y4zakgYWdThV9fn4sFgrlUFWrcMiis5dldl2k8aQrRCXRzWUNMK9G12ibBnXipVT24ZOQKJ0bqeoMU6aopY4DlsyWSzCEfJ6ojSE6Jd-Wnwb5TglNhXTq2wPjkpdbGTum7UeXYhdCJdwhc1GUkIU3ctTquY4isuyih0',
                    'dp' => 'f6oJbfgnzj-h0QI0KC4JhJZKI2SwqTTcnYFNMWuPo1SX_rEtWKEXo4VJyJ3RpspfsKe_Na1Jy-BE1UQU5yk8-Z4a6NcO-rfZWro7POu_2CeMPKyk75Wj6kXFRBR1H968hBWMvUPOZnnkY-Ms_6AezFl-1oxBSoyFditehoHV-WU',
                    'dq' => 'eoEtMaOpMwt9KFoNkqn1gXrKAMQR9XYKHotmJa17pDjWk3ssmcAHJJvbO1WDW76wxNDb9F9AIMRuT2hWRe9s34rBMZ94mzn6sDXDJqBhl-JkdYy5Vftk290eB1RRDVNk6eu30D1zkFNR06eAmHht0zwlo6sVCJdilG69yT4v2eU',
                    'qi' => '5vefHlL9JtiX-FBMYT6CSo51c-tonow5cj3Jl1crRuxod6zjXM13dr4bki40MT_ZQ8x1kjerFuoA1fYyktTAQnRgcafjYyZJIkh3RdGLf-_kDQ_up6v-k4IEile3RM_XST5lyq1ei6UuRO5NQDa5L9OctY5QWDz-rw9_51iKSUg',
                ], [
                    'kty' => 'RSA',
                    'n' => 'zBlgpPT7LeCKZbaRoX5iENY338bavaU-d_vw6xF4hYhqSBYoH2mt5WPeIW-lz9o1xlbxw-W6YnlHMuJfefnXOvZfFUNOK5-QGBq8ZJY7sfNJ0vxHJ2FJ8cNvpChTEqG7CRU6ZK_V2h5XuQFg4FGASbEgiJjRoPHrXwwts_e1ICIsW0Lg_YGBOk8RqlzguD-NcexYpO_N0VV-J5J5jlVxAEdVgddT-d9sGBx2Vq3PE3D8ZMTZ6UXTvmmdGK_CA-0Y7ep3UgYKVRmv2XLwwsmPWYJy8Ky9wqTnt58Lz5H6iZAGmgEztaf7hB-hRymDTFRWn2-zFhd1-TdqQ6xgZyfA4Qp7vFe1s9LZr_A-jFN2ZO7sP2x6e0dVDszzo0dJ41jrY4aP19hpOnPcXQ0sqjzahLmajekmtM3GjqBd9-bODXqCWiOhzc5Tl4Ru7_N1FEqUXVwBJhWelChez6DVTMeNdIJVw36ARtVNdsBwNTLK8q8n72cc_zwBmhFkGBdxHercMjmD1YJAaRfXfh8OJBbFJDSZkMp4N5PwK2iM4oy79xTsB61OZfEcwf1F4LKSDyyvJC5Mg1_Imc311nAdsDohBQMZquh-V73c6DhhBBRaAKk1esQoGUgLVBXsfR2RABr28WFM8RmOZKRdpI9AJO-6Z8X7a4JHCldljpyOX4mwWG8',
                    'e' => 'AQAB',
                    'd' => 'WS-lua-Lqyp5j6TN0oIFnFHfrJuarlBtEcU4K6BAyCkqOEHmWoO1h42yXW4KSN-TrA4GK5JRdgKFCEk_a2-vi4ZpWkNE_28EamQUeufjQgmL8vRmq2CqDUlXmaY9VuDxeDCcia8EhgHIV4GwsZUruAf8rXQJ9oiAT9JkjkXqEhacx2xcIKrcq3wtvgJD-H9c8bFTsw9PIvB25hftojLX5EVHqitL-N6Wv5qAY7Qjzt0KjYYvqu3mb0h7a3QyFcEfqadRaLhW_4TwANdnOdcWGwkT7POvIEUrNGP9p0Ck-EPFfrqTvAehssSXlx8eztXz3EvVOAwcc0Cx4MyMe8c1UtmKaXu7_v719irOXtECAtr7FfK_ycFA9dVQbKKBkj4MAidfgSLm5m9Ago8QnuyPHHktCcMzOeQNe6eY97rrBNpI3XEJJM97hnaIn1_g-poQgrnpYSZhTsDaKe9-ls8sD6RMqWHnVGe_bXsNfdi5G3iMqXAY94l0Eqrr_jTXdkmA-xTBCFfHcCLm5RDRBgc1zVYkl5d8rW822pyN4hfJsV1JR0KAltUQ2TCFR6fo0e6Ne-YbZDBHHPAD_s3m-2zSXSlODIG-bqR7beb8Ta9kjZo0advMbo4HjcY_qqd5KIY3HuyQWUGMABg96w_JxgFXEQVp3a6XQJaewQSRhsxTtGE',
                    'p' => '6l8TYYzb7VxrUFtKBbF1dTFjsRmAOajL6BGNB0Yyw0smZUEZL-HHeW3NzN4qB03oVUnNeAKKOde3-8mgDxi1qzB6ytqhJqrv0iRpsDJax7OP_F47um33nWcsipCHmzczM7f8HBmzD_beoMPGvsoUAzNIv9Ka0dz-1hQqz5etiKSMMwozAnUj_TqPLedc4DG6EaW8x_vgNfW-_puK-IzwsT5YjltQ8weufNxLlrT2sx9QT05jbxe2YR2ijNgvKxo-G0wz9A8pn5wiPB3NsdsHAy3mrtjMEjwv_Z65y0XPPO1W1Bp68XICknzghgTc7nZR_31NSrtEPmQBlJqoJPis-Q',
                    'q' => '3u8h8WiXSx6AtPGQpvmNebZqi66ITQcAhvdF8O_I1LdjswBTZwpXqKXb5kLBPXOAH6YqgxURNwZZ4M5Ys6iv66jVzPbSU_MMHlsiXzgeVfUxwbdOHpiZhRzoB2gzznfFDKR8bu1S07tYePeaEwplsSg2Vb5tC81uNIM1sshfeuDO5cZOH8DmuJzTjhGjb8CWmbgLnFOSBuPl-Vcr3oYVCnWzvEfCgUIy5tC9KeBC8Qe3O841SjbN3yZ8EEXwcUmo9lOt19s3LKBmtT94SXtok6-wHVWlL3YbzRg1kl8SVjN28NJd990mjPhjqBK8KyChCxoPn8lIXEUwGwFmIz4Spw',
                    'dp' => 'tYIqXVscnAf-KD565kvX_ongfjCUqJL8T97_zIlmGO8jbjlrSzTdKkKKpsXL4NpKO3srwGyfJkrVdw9ggTCOyWSDRITrVyn9D08Z9tYYjh6XPUixkyFFKkbULP_ftaqbYct0WULh9VQoeHMGgY24z_2wsrZlJnCzf5Ig0aLTR0bAOWsFtDqKQ7xNVKygthRs2Ov1dx-vNbr7Tu2hQ_rLEUmKhb1cxMrHLHXjqHS_tlti8_huc4P2v-GWmON4LDZnsPZkKfhwMOdXcB1Yxwwssx6iT_kgmmK4e_-oPi_zXmkk3KEhY8n7Cf3iWIh9ncROnsIo0N6U7IjA3Jil7fQU6Q',
                    'dq' => 'kYMy-5jST_Tr-69FRMfU4WIA74WPb_-nB3F1VIue4cGGMPuAdNxaVTlVbFmcOlkegwn566-fmfPqTINDgJkVotOEIhHlPWiCO3ou2EoP-vldbd0Q_4WJh0pT5SnNzvF8TAE9O0Zq7sr1N5geGFmMAPOHa7YtBSwkx9_w9-4z7Ee6pF4o9i76KfwrVisLK9FgO5vW8EXYJekxXevZNZj9OOOU2stYGPi1stUC88duylbH8iBpxjQ5cnNzPUf5Zmi3AXmjGib7P4S_JYT1JbmIjAV8Bdm2RWFpShiINy8ZD-ztsMkPDs9p70_d9IGuEtRsaYusMRa3xYpfmPDz0wMcNw',
                    'qi' => 'sEHok5K2HG0q6JdNzHB7FsM9EJxY7c6Gkya3Lfr1Rr5OYPcAosEIZpl-1_hCQ3MLGKT9UlYjZrlyt6SOUvCkxFX9slDZQeagmlSNMyWs18U0MxhFpEGthqLthS6ik0kFlschiSpMMyKVI8kgQR3OjMDcA_Mr92gZ9fl-mhtl2yfXJsBIkFBD7yOyxRxawy7v05RehoDHmdy2cnzaakPvg3Cekma2mfdjYgN5JnS0A20pC1zfoqi0D3B4KGrYVZhyJRnBakOUmwvE8rfmcjThx169LiAea6SYs7k9jwUCVWrNexXItxGdbQbbrb-FUotAcAQSDr6hHU8H79gN63WoOQ',
                ]]],
            ],
        ];
    }

    public function dataRecipientPublicKeys(): array
    {
        return [
            [
                'recipient_key' => [
                    'kty' => 'RSA',
                    'n' => 'p_Gffumd-Rj-hrWEKMZdfOw0JZci3dfVCkLYYISt60ajg8aktRR6Rc_1m_NMPIP2_BK5kXwWb74lqLh-x0iunfpgxHWnw4Wy00V2YwR0MtgbRW4JYyJjw9Fj7QooWdqRV7OoJb3VIpmBqr-JKjTV-91W6jPWcQNsUFYL5JsJ-sM',
                    'e' => 'AQAB',
                ],
            ],
            [
                'recipient_key' => [
                    'kty' => 'RSA',
                    'n' => 'slVGbcg7Mr_tQmfDJAIWrlWjBWpi_JzGTjCCVZGOikH3ekkUEH8TN39WJ2HXBwSNmT4bh8eRJsUyBKYr8yz3UdEUJxloo2SVZEN0rXh2Jb84OdObom1CFbPg4yQOvLN57pE06zc7GzQ1MKF2dqRFvyEyibKcs3V6J2DjvDXbxJAnTOmxWjLRKa6v9aKrNCakK_qSRzEwR-IbNnGHSrQr1RaDQ2gQ7FuVuNOJe8rrdlP1dIdg3ElzvDgjg3NY54b8SqwThXt8gRM1VKg5O-6fRdHLPS4L0DOElDlc8lboqA6oI1187cbLq__4P8c1pordIBmHXdbSd-4Q1BYnNVqfoQ',
                    'e' => 'AQAB',
                ],
            ],
            [
                'recipient_key' => [
                    'kty' => 'RSA',
                    'n' => 'zBlgpPT7LeCKZbaRoX5iENY338bavaU-d_vw6xF4hYhqSBYoH2mt5WPeIW-lz9o1xlbxw-W6YnlHMuJfefnXOvZfFUNOK5-QGBq8ZJY7sfNJ0vxHJ2FJ8cNvpChTEqG7CRU6ZK_V2h5XuQFg4FGASbEgiJjRoPHrXwwts_e1ICIsW0Lg_YGBOk8RqlzguD-NcexYpO_N0VV-J5J5jlVxAEdVgddT-d9sGBx2Vq3PE3D8ZMTZ6UXTvmmdGK_CA-0Y7ep3UgYKVRmv2XLwwsmPWYJy8Ky9wqTnt58Lz5H6iZAGmgEztaf7hB-hRymDTFRWn2-zFhd1-TdqQ6xgZyfA4Qp7vFe1s9LZr_A-jFN2ZO7sP2x6e0dVDszzo0dJ41jrY4aP19hpOnPcXQ0sqjzahLmajekmtM3GjqBd9-bODXqCWiOhzc5Tl4Ru7_N1FEqUXVwBJhWelChez6DVTMeNdIJVw36ARtVNdsBwNTLK8q8n72cc_zwBmhFkGBdxHercMjmD1YJAaRfXfh8OJBbFJDSZkMp4N5PwK2iM4oy79xTsB61OZfEcwf1F4LKSDyyvJC5Mg1_Imc311nAdsDohBQMZquh-V73c6DhhBBRaAKk1esQoGUgLVBXsfR2RABr28WFM8RmOZKRdpI9AJO-6Z8X7a4JHCldljpyOX4mwWG8',
                    'e' => 'AQAB',
                ],
            ],
        ];
    }
}
