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
 * @Groups({"JWE", "ECDHES", "ECDHESKW", "ECDHESA128KW"})
 */
final class ECDHESA128KWBench extends EncryptionBench
{
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A128KW', 'enc' => 'A128CBC-HS256'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A128KW', 'enc' => 'A192CBC-HS384'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A128KW', 'enc' => 'A256CBC-HS512'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A128KW', 'enc' => 'A128GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A128KW', 'enc' => 'A192GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A128KW', 'enc' => 'A256GCM'],
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
            ['input' => '{"ciphertext":"8WWzoKIrl16O3boPiTvVivn28js5b6S3JbOMySZ-ujmMCvOeyoEIdLXSxycB0gQeTFsHZ6g-oZqkuJDPNBTbSZznmLjRZQoarfVfxe5jzzJfvK3t89Rkd-phVyUgD4-RNXjuUItMjje3fMTTpw_E1ai6PuGmrZedvscj6BuSkvS4qWzxcZ9234xZzlCRgMzEBG3h4IUu5sWhXwictyMwVUHMBeq0mLSBJO9FEk_TyHI","iv":"aSNbaiq7SIh-6u9FjvhV_w","tag":"uf32NOEXoG-kHG19cc3T6A","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiI3bUFZY0VKWkJXYTR5Yk0tT1JsaFBnSUtMeFh4OEszNXU2S0FjNzZBUFVJIiwieSI6InhESzQ3eVJFYlI1OGdHNF9FTVdCTnZ0UThZVXRCN2dTc2pSeld1aG1iQVEifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"TTZg275GMEwpqiuHVwBi_1vu1hmR5juJOPRB_pPWjUUQ7zUtDAIp3w"}'],
            ['input' => '{"ciphertext":"--WXckNnEfBZgO50CgXLkNSwAHnWhzBlwyMl-JlPYzicmw_P5I9oX5kb-Hz8nstSyhwgrepcX1Q0ALDOD3Pdbf-wVuA-AryGP-dT9aWkgtopsHZv0bI1Hvreb6tmtI2qDq5zwM03bBlKzVMort6g3NXqvIBto1wskRsTmfDVnBwGXbEPWVPAHDHCxFJGZ6iQ8DeGjEgwQNdt565ZgOsgTqBV3dNUY0hhnXYDkEmteiE","iv":"L8ZADssAMXIy8bSmHF7B4Q","tag":"l0fPMEEIiml_GoAPppneYQafGgrvCHvM","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJoT3NXMzRIeWRTZEswcHNmd09sbW81ZFlMaU9UNllBX2tOU3RUN1BxQ0I4IiwieSI6ImE0c2RqMTBJakYzcUpCVWJwcS13NEh6QzI2ODF1UjY5TXl2MVFYNVFQX1UifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"6edmcKAhRI1HkZssnFGMDHkYwwlzZ_d8Ij6ZoW27BMtOmueRI7JXivdikiB4Te7HzGPyoygN3X0"}'],
            ['input' => '{"ciphertext":"ElP-FfX2PlRU6xQL4auDQejBqnwYcDLXMpyY7snEtoSj4ITHwJmNpGSD1yh0N_yDeSPf5HFqLDlzM8JZZQ83pOY_Sn5iO452WFeWtjNYOD9XB1AwPOQdBg25MSZxIdwKvzbYAs3FILw1swuHgXfdomGDJhIKQbKSBinAziGuvrCAio1phqwLrRG2vJApmWBHXjbuJzwv_K2ZBDLf8SDFvmTbuZZ6mm4fPZSWyEo71p4","iv":"w2LROvAqZDdkyiTv5CTMIg","tag":"QF0y2Be8wRWiAONqVwYFfoPQjc0NRrL8lO3if-SpBq4","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiIxTWtRWlc3MzRqZ1l1V0tFSjFrWXdNa1lGclZJeXd2QVJaMXdvTEhNOUg0IiwieSI6ImdSTktaOFZpQ2hJM3Y0RXhiVzUzYmNSY3diS1MxYlQxLVRQc0p5TURfaU0ifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"r0cwT0y_zzbV4zVXEY5Sh66bKtX32971vZ5ygeoCTtpN1oEuTANEZ9bWzJMuC3EPnuYO4XWopaac5FFJxBQt3hX4wvah9kkJ"}'],
            ['input' => '{"ciphertext":"vxE_6ULATftYhRAW86hSchRc49VscHXtg3bLhSFHZns3tVd6zIMo0xG0q6psAEGRmGs2Z4DwUAbrrZ-6YSPn1xjMEgMhSyXqZSM7rEca0bFeaM5N9cIKuiaSOLKGNiJ8SATtoUlg9wu3CU_ycCYoXo1dlmfwaRHD419ycqVDI2DVZDg6iuhPR2rIW4FZujn-psbQhZClozNOWkORkJSp2lJGIOs0jkI","iv":"lAOeapEH6BRLDmQl","tag":"6RoKYl11I-iu_-nn_qxTPQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiItSHlUVWhHUXR1dDVxTUJrdGIyLUVyQTRrRnFQZ2dYU1ppN2ZkMjJ6YXZVIiwieSI6ImpsUGhad0w3S0I4YmJtZ1Y2eC05R2JJZFh0N1NaaFJlZldFYUVCWTN5YXcifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"HzkOCsTSv-V9-QwEJbMt7rpHoU-rPgIE"}'],
            ['input' => '{"ciphertext":"L2Z_gtDHQyWWcI6VMZzje4dxVbKGX6tS6DsJITn5HzkaaQlXK8w2h4RD7VGNVbA2lg1yeGWf3i2Z_3gZPTYKLUMtDEUIJMSOyNZHzRWvcaCkgBLp3vBbkJevH0Wc-P1QIdhIByUvgPTo6OrTKMT1yonlQ8U3g6_xovTID1yoc2qdEVB0inx3Tq7HVRlto7nMI6Z48VT9CN5r4SmS3jXAZsortsG2k54","iv":"wol3soUEVXh0OYxF","tag":"tYvCovXomiyroVCYT74iig","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJhQXQ2V1FIVFduVDdUV0JPaHBPNEN4ZmNXUUFUNFhMcFl6Y3lpTTluZmZjIiwieSI6IjFwWEpmVkZwamQ1QWdSTEY4UUprNEZ5QUN3TElJaE90U0plb1FIQnU1NWsifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"FiU_lrERwsTL4qvnevyf2DxkjhxQ5v-ArGaHg7G4D24"}'],
            ['input' => '{"ciphertext":"6G-SHyO3wk8rAnYTGwxIOmG-1Aq7ujSC__aqG5iaDI6RX9YtcZdOAqIjtzKG_itRHa1uxGMzJqROG7haHEJpA62NGt8et5njC6oqsYNl2RC8YwwtJysK6_hvcHlxaIDFKp7ZQ3vgKvips4Ro8AkR58XpH1GF_Rk1RsFbJONWMDe_vK98tf6CSruK9LLu6LYU8JlwL0bUGptsdHPJRKQkM02yg4jA9nM","iv":"ih0vR-rb80lr_WVg","tag":"L7-8h3JG_st0sedwDHC4iA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJOWU1lbjlQcmE0Nm5XZFlBbW5KQ0FmcmNtZjBfT243cEVkWllkMFhBSmZjIiwieSI6InZYYXZxQmlNblhUUkZud2N3OXg5WVc5NDk1enQ3X3hBbDNFN2ZBdkxvYTAifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"Bgdqgux6pY8oUbufB7iHfMgb-EsffDBtOIOEDOqS45K85QY5dmotPw"}'],
            ['input' => '{"ciphertext":"f3sJ-VeUMSCDCs6_ym7mG0bGOJZwD54qu6xTULFgV_LZHLhLpzUFG1MX38EHSLay70c6g1Ob9nxFYc-EYiULNkfUfvpTFK6E146zQZmuKCS2u04KpDHrriBPutvJue60HWVuejkscDiP2-wzRuU4qskGzWCDTzj-YvZw5ftdhYztgolCZQDDfe67yC6ywpdOS4WLsk6s4yZJfK4TIRlsVxCPueU6wyQvkvO_EF8_PY0","iv":"eGtwRbrxNeaBdTp6yIiZtg","tag":"ur27HEz8ch7Oqs2uZKpybw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJ2b1dyQkd5SGJ2R1ZJR0piOU5lV3lPcm9VRkZZWl83ZkN6TE1sV1dlQUROSU8za09BMU4zNkZnelVaYW93eUdkIiwieSI6InlqWGtWUVdKQi0yWWl3azdDRFpySk1yd2NPald6dEV2czVUVzdYV2pZSVFYTTMtOFZncW1BMGt4d3ZsSjZFQm8ifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"d8JZuYKkoEYF-DveajkvDTUouMun6X4OmsAGDb9p1qOMX2KmwNfvUQ"}'],
            ['input' => '{"ciphertext":"TiMVN3-mo0Rcu2SG04FNiYqDSIk60BH-soXYLQgq4J457UFWDCMPBf6oVRAYTZJwiDEONWdc2iFEW7CfRU_dMc2DsO0kHMME3w5Uqptm5Nay5dcIJrcoICptnlPxupM_qyDgKOmF-x5oelgWdy5erSrQ-JX7bxTTw5TAHQ-iRlSZFb_eecYaf92V8CKqS9K2KqPTiZ_1fIiZnqQHyLmggqmifeWPHiO8ox3kI-LtebA","iv":"B9a80FX3up3SuV1Qqs9ydQ","tag":"rsvZ-bvbD2pMoCvYT8Hsag4STmKjcAi2","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiI3SDhjU0xzeWFmck5McFlZWFRTWmRLMlIwLURZUFFfVkkzNFA5WkgtM0VPSGV3aU0tdk41SkxxSE1HMzRFay1VIiwieSI6ImoxR0FmMjVCNm1SUE1lT3lwS2VpQk50ZmphNVZYMV9DRE1YcGIyRmlaajhxckc1WnBFOWtKZlV2Q3M0VC1PVU4ifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"yELqAjD6BDP4BjRf8Wbfb9vLj4tWpjjUiYLyb69Zo7x2BP7Dp1LhpWSDwKugswmRK5Tmhlqt1OM"}'],
            ['input' => '{"ciphertext":"NssjbtiTmnZrm5A5QMC-wS8oY8jVNRhs3b0cZWpEYdbFhtMMEOv0yI2JNLEkaA2utQs2O_GnIZbodCp6Dr1UoirPmX5GPiBa3wRQo4hflfCLY_tZ2JBaXB0ZFSokUEOZSOnbSNZ1Pa6EAy8QhAOwCgj5yrPbq6bvBv-JMfBS6YxhA3b7q1PV6VSkLWHn-FTvsMp3HMjzMRgj_l_Fz5n5Z-st0td8rq45PR0nlKgEnKI","iv":"l8XxXvQp-M8rIgA-_xkuCg","tag":"c2GrOJR84Xdjp-i4QtIYrjIbtDKtPvQ3Or4g9cGQP5Y","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJ4NHBOLWEwd2NkbVl5RW1kb09uUUJFR1o2OHVXNmVPUUlaZ29sMHhDaGU4V0pjcU1lMkQ0MC1UcEc5S2VhSzZqIiwieSI6ImVfQXNZM3pPSktYYUcwNG15RFFmUFdZSkJ3eUlXRVJyNGJZMTExTnJsc2x4VWRTT2laa0ZLTWtGdzUtQkF2VmYifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"jWzJiC_cdSHreMdQ2MChUWDGiE_QFY7KkTtLTEuHHzG7E-5PCFMfnkSeZ75vrqtawqm0XwsVBPir1lDkC-mKMUe7mHEr1dPQ"}'],
            ['input' => '{"ciphertext":"Mi_2P4e8uiptwMNQrUfTeQyY9-UpHdCsqTtCgHyX2k2wkKCEksmO5uGqgFS4vP9js76i-baltDNes-xH2tGYEFZpv9hpT5Mh784RpChxPC_LneCsN9_52SibnJO8u4umCyF3pJfkUUB9QXPIQQ4qTuuBgzfAXthK9cMxNZPP94hRRZgj3ZnbE3I36_NgANfQ2XVuGF3q6KQ-55KIFDL837SPRuNfzEM","iv":"O6u6sfSNvozzYC7k","tag":"e55FLRLwxKbKh5uudliVCA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJueU9UVURWUTBmV3RmcHFWc2lCZC1jLWdBRFdhVExoZEFiTmNiazBaMjVWc3Jhd29uQkZyQVVIYk51Tl95Z181IiwieSI6Im9nWkZlWVhVS25CUkhpbzJLYWJvTllNXzVCU3l0UzFDVHZ0SzZqMkxXb2JjWGhjSzJvU2cwdGJpQS1YRmxGNl8ifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"6hywjs7eY_AGzE0r4AcmM1pw_ET6hwFO"}'],
            ['input' => '{"ciphertext":"B---FvtsBS1ABH1Fz6PbtVU5t_WxpPGUhIRvrpEP3_YKVu36i4TImczF-L3cgeeFjypkmbM6hblJQmek2QFL5x9GJF6KzobCv_3g5KkFBNfEH8NwOcdUbmsSsPOEI_5ZTwcno-hHcc1PrEueUREwpLyJ0oP-1IgOHJn4j8NqeqWEAtcxzvQbWonBDF6o2c70SgPzCGZy01dJvSEosudOGpJtsCm4hvE","iv":"WUxQgfmtQWZtX3Bk","tag":"B08AHwCsv5zO1ZmX9wbQHw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJYbUlNX1NVY3J0Ymd0VjBYOERrY19zVFl3bHphdnJPRGJFRFhmb1NNaF9FU2pFN185UkIwNXhIaWw5R29zTFNwIiwieSI6InlEZmdzSEFWaVdxVUZHaWdSNy1XYml3UWRhWldOLTFyeFpyNVJCR2dTV1NBdXVuUnRoQzRxQ3JOQ2FiblV0bVYifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"04KAt72HccxdDIiSjuzRXm9hpNwJcRkRLG6dzuQvBcw"}'],
            ['input' => '{"ciphertext":"2l8m7S7WgvbAgg5JvvxpHTkpIeHTVcJDDjZdJX3a-pakoEqw9UDbsIHGJE_W6Gl4bMaRhRTMTsg8_xoqoIiif-NYGZKhKvJ2CBifeVaTZJjdcQJKovjvpJGUBMtev7F4pPnTnLPnRnLax4MXgpkOTv9ryh69Knn8zbcktnO93kO6ImzRCK5hwRE9hS82Bg-2Y4eNBsnsHAfkFCU8UX5z9nTOLDyQVns","iv":"aWjEAIckOJ5SxsrB","tag":"UNJ1ghRwzGG9wDzbnAdwrg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJ4UUNhckRYU0tRMG81TlZOTVE1RmptWFFoNWFFdWpzV2pJRUM2Q24zdGdybG92OHl1VlkxWEh1cUdpTXF4MUplIiwieSI6IjQxMG9vLUsxRDVoTGxPekxIV0NjREV0eGsybnJVYkVLTUdoMEpZYWxZaFNiR0pXWkd1Vy1OV09zeDY4dzR1dHgifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"M1FUr3rtiak6u_GUN0gm3Ahn7sjIMon5RmO3lVOrgXhnmHvLfgw6Uw"}'],
            ['input' => '{"ciphertext":"7kFxr0VKVbmJg_ro-7Fj8e6sQBKsQefPB1xQ-_FuUL1wS8w5CA7lnIpQTXoAwbFMClP3U62mrfz26d3EVHDi1b5sWoUui3V2OnLD6CxqpmJdAHQUgHeYaOglgfJWLJryqn6b1X2CJ8qcg5vy8rqPHHghAY0tgA3iA_OcPuYc9383yLWTcLmghRKwa5yw6zbYKXBXdT2WY8Leum9nqvZT4rTMeO0_QiOlgn-qFk2n5yM","iv":"FluGprT7jlECz74k2s6R_g","tag":"nNRf2uQSRZwNNubODrXSrQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBWlI2VEdpbFRVdmxoZFVnWktyYjNIbkZ6alp6LTRJMzdrSDBxR3BQaUlYenQ5bEwtSnh4QVRiV09sblNLSm5FbUJVVFZ0empYS0l6cFA5eklfUGR1TTFSIiwieSI6IkFid1VHaTVTaFRtR2dEaVlGSko5LThjUGh4b1U0elZ3clQwWmtmLXpkZWIxYy1nRk8yUWF4a0JVYTFqT3FQeGxnUDJYeEpXSlBqNHlGS21ISlR6bzN4NWEifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"ZJAvb1EpUU7CI7Kr8NkGswvdCsumf1JVUF2IaAKGrxOdIJEbTocVPw"}'],
            ['input' => '{"ciphertext":"eUpwHP_TPDMYTRJl7rPvo1UI0EqM8JJtdcJ-D1MWmwF-xQFxSvnWz5P761SgRCu82FlMrrByl25n_XUo1GQs07FqeKWa4eGhOGGxVH3aKW_z6lfAG9inr_-Qh7iwZ2wZsvUsNyCJJJstFqRWSZSxplEeju-e-WOIJ-ztMNVn91DHfeTIiOvXfC1ZOgrrs5S9PpNA_NYXlzrMbgNTrq_i40CUcWKDZbKKNMQ3Fziegrc","iv":"gbzsDnsImZqjm_orj5JmYQ","tag":"MVARiMCpmzlErYES9-DfIWHAJbh0pwvz","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBVXNDYWFtVzBsQW5XQWRlekZfZjU2Ml9yaTA5TllYcC1CRE1pU202OV9LakJqSkpwX2t1bWFrZVdTb1RGaEdVSnVONkVsYTl6WUZPVEUxdTVFSWJ4ZHQzIiwieSI6IkFBRnl1WEpuWlVOMnBrb3l2NHdLODhvaWJ3UENXckNYbGFUdkFVVXp2YlR3UUVmYnUtS0NxaUx5aFJZXzVCZkVvajJyZEVTU3ZJY1V0aE9tNFJNc3RjVncifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"8YEgqLWBvvBqyMymZ-Kpq9Bu_Z_NI01IqhJoSd8w2tTkTZTD4L95bSqa8JV-0z3sHjTiMYk6CwQ"}'],
            ['input' => '{"ciphertext":"w6l_-xk8sPZQALFwL_9P-PgatydHCrtTLk0adnp0f82x4uNGyViSq89VlOVYoztGr3nhklu7MjpoWXndPOYTEGWkZgfakAoWx_6ISGkz6D37__xDgJGdbbtzICJm-4Y3LeHJeuIQiO-CNiB3Rm2y6tvDjSEy9_xiy8D3c7ysZf9SeBNJDpQxSF3OKl4uc4OMa2om5DL_StA-AscWfDJOBLAJui3647g-SB-K4YWEkgk","iv":"bKfRWGKG6UPNSszCasPinQ","tag":"4VA0oS4q3qjwiqNjj4TI56qGlpIuG0D7UElG5DzisJo","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBYkgyUWxfd045Rkh5MzdzUmQwYlN4Y0N3aGRZRnFzY0ZfRXR5TmxXOWxtUy00ZHlSTTdibXFFVEcwSlZXMUp4SkpLZFF6eThMX2FIdUNLNUtzN01OdDR2IiwieSI6IkFIbXJmeDVrRS1kb0dfSGliM1FzV004QmROaVhZcDBQdUM5Rl9PRVI0cGhSM0hDMGRkSHRodnZrSmlWd1E4U0U0QW9IeVNKb2JDbUlxUzYyU1ZFT1BjMXIifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"kKII7fRYCmcPPEawSTbo3owo4zF2vDBSXNuDf3C-iqwqeF3GH8Fniz_nrWm5KW0Sed3lOtqI_1Hd24-coM-S7V6LAr4Cj2hU"}'],
            ['input' => '{"ciphertext":"JKi2Jhq-aOlzScwO3jc5rgcKGbtKwpnhsX1AxyfI9Wa2-AyKItYk3SBwRrHLjN0_xZ5eHXdIDHijcEy1dS03nAwY-skEejCcb8RAW2vmezBEzM0gBCciJ1s6kndKOHn8Jmz2-GmhD6JCK9by0J9BX9_Es0346tXe8d78lPjOxoGloJU2gnFJAU-bdSROAq9YSRo-_vUCzfoAT1f3PykDbZyiIaFlPow","iv":"wv9ZZWV6ifGu4vS3","tag":"tYQxcfD_FyTNNXI9a71Ffg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBTGJoYXNDektjbzBOeFhyUkhHNjFCOWFWQnJVSDRSYklGcnZ0VFJRMVliSDFHTjdhVVFLVktnc2pBM2tuY2tIMmRtOGJ2RDVFSVR6TnhkRUpyV0RyXzZHIiwieSI6IkFlY2xFZmtoRzlvSk9BQk44VjBqREh5Y0hZa3RjRjhsV3FIcVBXekxzNEJla0xURy11c1d2WmF6ZVFlbllsMndTbzBBVE81VFU0MGVzNmg5a1J5QVA5TDIifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"jANGIh49o4xDo0TQMPgf4duV4YGmtgon"}'],
            ['input' => '{"ciphertext":"OWkwZ0i9ldnjtjkBgZ93lsg3xm0l4OnP87tRuejocgTq6WYjs0QJ2U41A2akSVIG9T37T0SYnNKi41QGPWPeDpUcmp6u_xEg3-fsLn80eg6_xbjzU0lUNc42hSgRY2ADWM6osW4z0PKVGd22a2cH1be9wUn1BemDbop2RjKRTtocfVtJrqdjgIpVSelezRozQU22rM4GeF8bqLyc1VRaDkkKpkYkjXw","iv":"ihJleRGdOQ-v4d0M","tag":"yEqVOwAw4q1RodSCCWAVzA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBQkZlenV0NVFTWjdMM2hXZXliTmttbVZRQW5YNnduY01XUC1CU1JJYktkUmF2YlpIbDR3eTNDTkdGWTVpMG9YWHJaR0l3U3A0MVNXMWdOVTlVQm15UFVTIiwieSI6IkFUeW5yMmlMTV9wcXBSdUxkX3B5WlN4S2NYTEpBS2loZHZkRkszbkJJemhOWnhfMV8wZHlENGpVX2xqeHZUdm4xc1NUUHY4cmlOVzFpdmJCeFVvWmhsM1QifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"IKXDD3gFCARveeX9ziSCe0r31nCDv6Uwj4OILcAlvbU"}'],
            ['input' => '{"ciphertext":"mb1uW7cpr4CtkWbmp6r7sX9hNX12jZZTOwGg-5XQJsVQ3PQPkkn_N8Dr2EoKd9IyLqe9OYWrE_LBDd34mZKHYxhOYGXFR9xABwhop6fiBwDp7VGm5Oj_wv9cl2X3dCJ29WmAUTnGh4OEhBygBM39M9wUNib78Gmjz-iv5N5jceCEN-RMfnuIB0WL1OLq9n-bkRLDTXjSqFUxCkgrE9_nS_Sejoc4KsM","iv":"rnCX9ilzmkw1aose","tag":"K5bqlN1JpPHSQlMv7zFaWg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBU2FJT2FHZGNKWUZtaWtNREFRNkgwdVNZRkRuRGwwY01qYkxobnloN0ppUy1qZWQ3bDlENGc1R19vMUV1M0RCNEc5QVd5UEFmWEhJWWtWYmU3WV95YTBHIiwieSI6IkFWcDZUOG1taGxCSjZRdFBrSW81elFXOVlzd3FVQzRGTEUxVnE0VVhHTDRENjNxSWg4aWpWLVYwa0NZMndGWktKMkVzWTUyYnlMX1lENi1rcTJVaXNOUUUifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"n5DIQLcd4xliTvB-NioJe0A-STuCOVuU-JcHe70BCnWyoPvu4Xe9Dw"}'],
            ['input' => '{"ciphertext":"TTjx6GrYn8IphU_XqrzpnLscpDxvG0GTlb1UPulp9m6PwYwSE5IyqwyJef1UQ6-bHLSlWm7CSkp243d0QM3ysv-cdGwRkOG7aMmdUVoZkg6T_grmbm7nO-mvmmxawwwYOQI2Bxv0IPjR_-NdEldbMYf3HE_ZTNcBVvh-uWjYngHC7KqyVFeDc5Ye8FJp5tfr1ujrxAAjTXjRG5mkB6gF1QzMTUaP3PtrB6CIiUNfXJ8","iv":"ZJgv-pIn5y02EdJrLDykFg","tag":"WWOLFNkHRp042hZTLNzN5w","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6InRaZUVkYnZnWnUxQXhVU1NPZTZwcXJpUlF1d2IzdnZXNXQ1Z2ZtNWU2QjQifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"M7-Ghrpqtc3MWKvgfuzUrZY9ZOLsnX3u83WxPR--m2VoKsmmNueKpQ"}'],
            ['input' => '{"ciphertext":"YW-S0VU-C7aILn2lTDae6eDVB-1PBx3-xtjGNMIgkAhDmKw5h90HZa8Bf1xMPOYXDfJpD-_IZczeJE9v_nVjRXKux6ki8ldmPgchk48YA3rULAChVv5wwdzJWKQQ-MbrVeJLlBGfRKxrUKiUdLYOiYPaSHpE5eD3HAVhjh1HCw2emlSeyrFjB2ms8LaO9pFc4KHL0r0XBiGnui3We9buky4pYhsXazJq0JW5dO4yUUE","iv":"IlnmwXuwhzGvSxa330IzUQ","tag":"avy5dCCba8TduBUIdS59yQa39P3OhNyw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkxjRnpxaDRjcnJGai1mcmhjVVNCcmUwcnRrakZJbVgxZEh0TlJYVnpqM1EifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"h7UDx4lLIhRBxrLweTs6pn5xYfvC3dLmmgZbPzxyEE4lkx0ANdsKIluO3EDhAZylmgMtSDaB4X8"}'],
            ['input' => '{"ciphertext":"_jUi2qOplWRy_udDIRaMFbzGtdNzT4YuoXzR7CKy5FEJfVdO26zZuBjqqxC1Pd-WUyhVdEh13AdfPV7ZToeG8kCGFZU_OrgrFB1gAbeQKoNOdiflFSI2KcjpoY4MH_UAeUPsmuBHJtDDogCCVrte4gYm1On9-6tLamq4pu3RPDKWLQZD_s2oHdgPdqi7vEptgvM7Uah3YDOdz5GRJnBEJKoimrxFEmvzIVGvQkSzmnM","iv":"wPRiBUHyAVQl9LgSEG6_EQ","tag":"kTRaUSmoyWuRWz18rBWibRY5F5qBWgEVDU3MQtfo418","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ik1hOVRrMGJqeUJCVWtESnMwSjhibGw5dFluTHlrenptZzdiRFdJSWVIVkEifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"vTnxL_DFkfYJv_KxgbyqaWL0HQm2EnMLcFMf6ctT0T-BdhjZklCfo4kyJjCcrS1PP3ai1dKAlsENKHs4S2NPazriAoHrFpYQ"}'],
            ['input' => '{"ciphertext":"IK1g25wS9-ZrhP0F3UFvuX_mmy9V4Zc7QLpZ2rjIAyH3RQAcW2Lo3uC1VcG9MBHfvvehHYymtuHaS-jfHTkqlkAM8Umw9NfmUIjQvRyiW-1CECei2R-l1dlKAkoRwAgyj49CED3YkPb6PbybjHl0OCgLo4rUbimOxiRFayuLx51J4sODu-L8QmW2HKKqL0R9ULKKqhhIplGZWiLIdETXnkJPvX2y_uc","iv":"6LVsbG7JkJksn_eM","tag":"4GVV0TtMTLkKXriNKPspvg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IlVYWVdDNk9PdHlsZzZqTVpidVFqblhSX2FpdXdVdzg0dDRSS3ZyRy1TMkkifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"9yDT0CM9r87O8RgN7tMLlMRT0J-PCN0b"}'],
            ['input' => '{"ciphertext":"S_NBXzk1YBP8AQURXaNk0fhLaIJWygBT2y51fQQRS26y2QgHoeF1uuC-anNPOQBDvWzYaz1dqvsqYjQ2Mr3TZr-i5VtFSxgQsIKBpSqiTw8-lAH3I2VCJFtlAWgL1rksAlVZqm0EzJJMWhhRVIgBOFlFX4bm4-osO-um2jU0y6YGvUknmoE4rk2yckTgNFbxJGgXlCg8eqAdBw6L7JmJH2GKFKluRk8","iv":"CFPOv1KwEy_rQsxq","tag":"2QNLpLlRtHCH4qdvrflUcQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImYyWkl4R1hNS3VIOXoyOC1hUTVLdzJYSjBLUlZ3VWhuYVBRdE9NUkd2aGsifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"A0CdqfbHoJUsAy53D_Zawqm_GvgcMIRLEuROny57LAs"}'],
            ['input' => '{"ciphertext":"U0YAR0NAlroFurFBi4JW6RcAIaWTEIhhoc-onI9cql6y2Az7g-Da5z0ZZXP-dmDAnEqdxLMdz9sSFou1_uvimrLWftlcxyYr1yzkFFbIblPw-hKkNUJNwbq6maTbFLuDeinCQYo7Z18qjihH22BCIhzcNGDUIOPtH9gnhtWlTx_FTNF2d85fUqDKU48vzWE_KU7jEPwLUM7mbldC6u-my95UaPkCeTE","iv":"qYDygzVjWQq9MHdb","tag":"GqfBJ_ucdjWKSLYMZKe-yA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IlBXdE81ank0Yi1hQTU1b3V1eXoyT0FUek5WVFpyb1FpcXpqR1ZKSGlYWEkifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"nAXozH72PRPzt1qQNZbHdII6I7Pcbxxg7wqymlMNiWKh-_cILuFC0w"}'],
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
