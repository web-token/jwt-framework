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
 * @Groups({"JWE", "RSAEnc", "RSA-OAEP-256"})
 */
final class RSAOAEP256Bench extends EncryptionBench
{
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => ['alg' => 'RSA-OAEP-256', 'enc' => 'A128CBC-HS256'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA-OAEP-256', 'enc' => 'A192CBC-HS384'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA-OAEP-256', 'enc' => 'A256CBC-HS512'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA-OAEP-256', 'enc' => 'A128GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA-OAEP-256', 'enc' => 'A192GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA-OAEP-256', 'enc' => 'A256GCM'],
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
            ['input' => '{"ciphertext":"Kt1bXc5RMai6lvx9jzQnER5cjHhpkrhpMA-ouMcKpyfI8tRV3rR9YhX7nFwSqjlEMDHOpo2MSFE1VKFffv6PYgSo57Go_KH1nxCAfA2VvmfNw2m57s_k-CT6lQBPbL_wP4-p-G7sBTn5G2Y8JGv97KZfxaGMjJPbG-cItZGP6lXGHMz2dzOACuYMPnhnC4DMqU1841c3-bwDbdF7zRbSNR20fTRkQnsym7XUyzWlso4","iv":"50bhctq_S8c5HSWma1Z5jg","tag":"s0HVizdCpd0Yp3aCTq6VbQ","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"E0oIChIIRJdY6NwHHzIeoDso3yX0bqVDrhrD3AqEnaR6NBBAAXFVfc7PwOaQHEzc8u8Pu-RrgB-4TJ32vF_OzkqemMXzj2MmvYSSE8u-llrYUj3ojpBTdx4yytoU1ufLuMAua6GOKQai5FCFmDy_jdwlmLAFcCP5ve7_vWvBGEg"}'],
            ['input' => '{"ciphertext":"xHFEOVgYUCqgGcbTwJJzRfWG5Y109yYUYSrKYwRnqI8ILesl9VPq7N4XB96JHThBz1bDdWl1PFEvUUmQXh4che0jgYhnX-7DPcJknPxlgPGVTQ-I77L4QsuUSKebG_XckaQYZuCu7-gwvDZ-EkHhxYiMzg9umvuzp2CKJLcluogshvBOi7Mwq3C6R51Lcgi9OECtUhujDo3VwqUxHXU5EKkng0isgO52ITVnjReevAY","iv":"qUv69PrmNOrGNZaIB5wJMA","tag":"uN09z-ggZidiwxLhMcu6IOrlFiU-LiLf","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"Ev7I_-UEd772eVUYZTQYKWXDo9vXSp-kzyFePHftUzY-vooXwRIaN6fow-erdz8VwBnG3uXHZZ6ZJLaw6rD0b-GMNOxxcwYW9pEdAhcqVkdbUi_SdjeJSMTa9Sa7g284OyOpf2SjQoi0h0FhEyldCQUVHA_sAC_2rdzCGF9NoLI"}'],
            ['input' => '{"ciphertext":"JjI_AEMydlZllOGW2MfCVGiOMuacDwWc41pevYvmYol_7MohArgSKxEAyROJd3R9O7Zz63O5cyDwgDA231VE-idmVhV5snfxNXyXRlNvXDVAWFMPRWRWOtsQdUCWMrUI1WbQVLJ04OcXbfY9R6dYrTqqqTqQV69ylKLItXkB42EmJq8vnn50nr_WhDdhskFi8gtc0cK1x_E4LHlQc4NbisIQ3N1SI0DE5GiLzLMsaiU","iv":"q0qYbdan0pR07xAyYpVkbg","tag":"h8p6aLBIZqjimpr_w3iiUWaNS56NrigEcab6uPXRCdg","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"QVjgnUuKP6aNtncunJ-j7n_RTgte6uYoGJt1jBUIL8WvmHaZA5lfc5Ost_2KA6lcPCUtiYoMRKzXvOV6IWP59CETWTrvZg-Cn6Sho7eWdSr0HNg1948Tb6vR76FZSigPRn-cWjfUv9GeOBL5vJCx7aBHHXnBx8XeQch9nRNx-xMHPwEaU6qwUcyjvS4G6D0rS8rGnhlLArraew3tl4rs8s8cgU5jetXB_dAPetVUMvN2_caKVSU0g94cl_n_Qgo_G21J8mjxmZp428KSZR6_YtbonQIczenj47OV0mBIvgM4EgTFuvyFA_RMRIgun4DmeGiNgDtb7PB8myp6zc0v2g"}'],
            ['input' => '{"ciphertext":"qwZIydy2JYj0hf9_J4S7tAl5xjq7dFhEHqFoldMyEkjG67Z4E9o-eklYNwZ0wMgfUFbbUuvXcXO5xesBd2JNme04YVrYsb-tcj6L37pII01XA-R93Dto6yDUv9GFa9tgrvRthRiwnwv7X9HfT9HAF32IN3CA_j1nX65XqZiH-FeywSYwbmhKzhVsvdLJxYx6RD1Ebb8Tg5Ht1gVZMs0MHYjEiCeUk6s","iv":"0ZXHoOtEL8l7Ln7X","tag":"TeVmyPlt71EcdWI5mqnP0w","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"YhyxlZ1qorCPatENA6emkBg0Wg0DQQj7jfLyf6iKZ5NrVGRXdsV5LEbsodmDGKFb_yYDlWfaI_yz4fjBA8z_-qWUyqxSbD7yaX4Kyd8HmH-D2JNHqZzdfqxnssociCSkVKya418ullYVK0juJ7ag5t24vGixAbUoF3vFZEo8H6k"}'],
            ['input' => '{"ciphertext":"Ri-yczaqxmZol-a6jiYUAA2lCBDQqWXJz3uFhVreb6iGjAuCaIsTRUPc6G4r-FXXaGi1vmN4YZJQLYqVJ58poyNe8eqiqorQRreZtVF_Ugt79rPKe3Nsq7nxSH0i0Iw_5Xwzwg9tKEgrfyu4HSfx3CYhr7GXZ4Ngt9b6C7AT14RwUPMJn9s_6maxVt_mGAFYZZNowvwAX20zrTGB-9mISn2my7Kzxgk","iv":"Z3E8pNe9CQbKoVk8","tag":"KNnMD0_g0gkudMaMu0ZdMA","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"mtX6HjMdgJzXFVE2ct2NysjfK-AfUzFWK_WUDg1-jTsGPexOQhvoin4pGSVVPweIL5k1ZROrHSbxocGyTjHmnox7QnVbkVnJ2Dtd6aYtiDmibEhY1v9cgIw2-NFPHJQ4b44fy_ovSHFUH3Jcs7q0l3VBrhXOZPU0HBdbjPgMBkY"}'],
            ['input' => '{"ciphertext":"J7OYhHw1S5EYipkRAFFjpCYkzV_VsmmQRZXNRJHhxc0sMj_axqE023yL63ltZhil8N3rlwFHShKkCT_HbEA53RuXcHrKrkpBCCq6vmxfZO2knKHjUv_k7wzXNCi6z8TvhE6yX5NMjIetBv30CbE3aOfk9gTa2nT-A8Xu2uP78oqvoFFULfhv3vQBx2-g__eRKhaEdzZ9GrbZZLhrIPtsOo8Sgf41QyY","iv":"BjA2cnG8Vj_2FqDt","tag":"0ifI7hCpz3HtsaykvqTx-A","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"UC1F43FkAeURaolsPXKRayZDk8z05T8jOmZ8TveoQiKkHqtH_Ph0EXx6srwtvGiocMB7VOreeiHuhqePx9U7lSq15MzTtoHOPLKI9FWJ1dEYi6FndpBPkxfXxOQAfc03XslSY8TA-S0dYdWxXEgVrJ43erROJX0pS-jzzj9DcV0"}'],
            ['input' => '{"ciphertext":"XnyZ7w7GFsJ_faDlBtE1p36gMcYpo3HGwFY8qkopuFRbrAqSPaNqPsUXTrI9627jEGpLBv4VuAXIUE6CZPcSYK_n8amYcL_Ji07FdMDRuR5-BQHWUKMeSVtYUAVYDe7LwZ0GK_xCfyPbcMTb6fKYsvL7TE16SZzfHFdSOhT9m77NiXiLJE-NExn-uqWf8t7xQnoi9YU0bx_a4xwNK8I1AC2VgY8T7_tp1oaAZe51lrc","iv":"0geETbnN9S9VYsn6-jMLLA","tag":"OZYNmc4UfJvSR37SUk8rmg","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"WjDBeYp_H1lRkJP_0a-jP0kAVhAoIyJuQ44qJAQsJX5ElxWk6YdxX4KUaTiHHsfgmSbocZNF4YrrlLjLbevCQMIuvMCAHjg_OrbnmbcWZe8DhuqWbYegDO6l9ijj8p7FkQQ_aS3DMLxRO4dF439EKisiJMBtT_Wo3278sCCfqoKMEny2IkItzqXm_maWRTEGIQc2hmp0xTLeQJt4Dn1JQ2MQlw_0ZtraU-xblyqxEF1up8f_SHA4B4aFIbGMXbSormP4qvStwyNL94eyA8Dw9kLe1-Ii8BO8ZASlNcssWw1hpigtyill9klFPjRKxBrJbn_G1d8dgUs81BpPH_d3PA"}'],
            ['input' => '{"ciphertext":"X7VkvjUSIPZEa7hk64LJ_pnONh-4E8x2HQE_9eNr8XsSUGUVz9PCuKBpIq3LrJoD2eTJA2OpKvVkm5InOH6Lvqin5hhKr43no01d1QCF81nZnU7mhaw4C_ag5YJvNqgRkX34T89_m2W0SBWk1qXDn3TXR4fz4NLKJwnZ_j3Upy_NMz5JsMtCjG0GZhIqLXHz77JA_jcSZBgdpFqD683M_b-96szPZ2QxbcxVcw5YtR8","iv":"blNjabJ8qu3kkSg3I_52kw","tag":"a4w_zKis-7yLUE5Dtr1D5rb7C68R1g6_","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"ogW4_Z0jzd2POyMx9oy4CGW7GOjL6gEHmFqdoeRtj8fQoB3ofYM0voLo-YqIlxDdTgyIqNwwTM729WMZw_uV4Pa7J9cMRAgLczsgIRvHTbYieBfqvLRU4jxrE65XM4PUGiwzwj_r-ICrXkoH-UzXUkzQdPBPgOznSzcQ2Fn5xqr_bNptKxX5b2Ppbscm37MjmEIliJavrnUmh1TGGbYSVXODUf4ER1evdT1zPWUeqcc5NJ-I2DyNPQWKVS4HI200HJ0HEGWMVTU7I6Ggjypm0azkNJskC75Os2rMoGaNy5UOtfLq97yCTPzcZ1LcBQHAJP7bh1rxSj0BHZW0mTN2GA"}'],
            ['input' => '{"ciphertext":"uha6DjGNNpMcOFDgn87PMyTJrRSoTdVgCyXNO5zk8bzJ9tkYEy_81lXlBX7oQ96YgOCugrEv-4OND7y4c69GFO0m8_v_R5yIuX7Qpl2OAj30WQd6v1VC8-JBXDW357_6L-XY7vSuCvQHB1wnVABw6onKGz92raOW_xrIi_J9wx5lmzMLSth3BalXe8VhcgiRh4EciIjMynIurcVMuZ3rstSjQe2k_7BQXiXpWInwy9E","iv":"wpwbjyGnBiMvv9-bhcorpQ","tag":"z_WkrSiMw0X3EhU0JXSOu8Hm5ty9aYvAJmunXZ_eIKU","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"QRIg4N6HwngfX473i6Rp869h69EVTbjMAQ_5EV_TrWOgq4gi-ooxooOrJ2Sxm6HvX52UbQ04F-shaAwvEA3kj2Sy8zqv058uX_BUutNF-hE4pV1DyRqXAGamEQuvq8X4t8BXWS02ITQizBOy0znGsJKopKL8dR3BttcONYBfuCP58nPOLEg7Vsw4xAKC0Di11ppumBJD3eFM94ii1XecikVdMqLlHEP2oUZRWFCUUltev1Yhj_JZzElvSABvbuNVHFwJYrQzmhjq70WDVEJJIrpVVfmuwNn4MADw5B9XrT4xdTMDligt8lqIxNd5rxItxLv3n8HwLaDFoOMrgR54GA"}'],
            ['input' => '{"ciphertext":"W1_OC0LkFGUPJSQetkjTGT4WAVe_5OeVVIq3YKixV8_heCA72OXJppapE58tiQktfbsxgG2PR6my2HuHK5IMdzf5ugF8ALQaGBNnHvsOCQZA1JZLc03QPRQGYgbRGhDkxOLNxwMzYPytQLYpcxHVsVId39-3IRreXaZbd3C_SvTFlPRx-6wD43ExWEpdBnxnn1xHlw3xU-HdOjZQfSRPeUGJoF_x4t8","iv":"BXm6XOtRiw0dJd94","tag":"r41IaktoReqoeamFZ9yl_w","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"IzFHtCyOENKi22ePBOtQcYRBIjGIdqP2ZE8M7nulP3Z_iaS-IB_bQjoIRQ7hPzKlr_jNHzb7hAYaHBZ7TfV1f_q0CkYtZhVP9jQGx3Bp0VVLaHhY_2wB8ojU58Y45Q7NYtTgsQLspv9PTdxtFaZhoQcJTqGfWR_X8Vh1q2vhVWKp5rNBxvQ3Cq5uDqSnzDRy4Yn6Rt800Mm1nmgToVnj0laAM-tBdvjD76ICD35GP-cxL8xZ4-xFrZ5SOuQwTARsR_ruoECUZsc3Q-ddaflSN9qBIKObId4czTBlt47aIS6Q3NuMc4TtiYWu_QAdFBviE7uPrhMSHIA-XqFOtlQGWw"}'],
            ['input' => '{"ciphertext":"sq9GLKF4P-KXuxBy_LNmntSm1sZz0tYT_f-i2HGO0xl6af53QD2WaFAm5PdwSBJXZKkf1d0nNLP2XqA02zkuMSh40KBz41oHPzqTRHrLd2CbZuL8FUR0avrNMXw_7-1I2cMYS5USW1VNuUDVjwqy-ohT8-_j-VeA-3q4Jt5mPSL4GSgE5EkflJ3TpeKfTsW04G3vrsSFH6mfJPz5WOCl6vfQHzy95NQ","iv":"8YTVo5q5Fro7BTto","tag":"aAiOhoDVrprwYY2nsmO6MA","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"W2KgXKz3Cym1VXSd2JNUiAFWFEDmq_kGBHVC9g-eJZC-ZztcOnh3IgYCepbhLpVvDuj42E4KorCF12Lk79OAwmmcfZ-DvsLwgp60L2Ho2qaUl32TVmHkuKzN2RwORvb6QTMyOBklt-2BEfLC4mqYYI_755MM9noUrpA3lHkx-b-lr0l8f-fhGCWKrgsOidsfJN20nDEIvJL2PqH7SXLDKDHgY9JFdF0NfZJnZIUOUJB2kCYmaJ_CqTF6fPypBNRGwh0Wr4P2Zko9RMOp3Syuo7W3NPb05jo6xR5g2wxSOnK_WDd0YhnAX1SvBtgTq_E7vfhy6A2YO9QJC5kxAoTqgA"}'],
            ['input' => '{"ciphertext":"M_MGtxHwXLi350tKZBQPr1gSw_4c2NhXtxKkZtFwELSqRvmTuUJxKiU_tkr9DWfHfoxFT586LpmGjOeu7u-4asToZ3BWu8namlORdkMdOO4k1x2ydeygWdWUfzNkwoMU3Yn7_zlw2PVoDkZlEcB5cDidBbrUHbKugAN5ZBOBOYCDoonsnRVRtbs2HKhi3J-YYnS3hgQJIlYDXpasb7YxlV5NerdZQu8","iv":"YowIbccIgldZtWhM","tag":"hLaDeUhCkt24cDuIaRZPkQ","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"KDmm43wYSHFxTbeQ3UwfB_Grwpf7xHJbX_ytkEQ7aIr8BPXwUPRPk50Xbk7STQQjdTN4IdB47plCVcmtFVVvVr1Kb-9Z2ouQEz4XIymvNfME-48afqA77KALuxIdJyXnlaHfzagSxM_r-CwzR8qMoiZ31VCP3uWcHVaoG7A2tzHJMvvDy4BosJ7Q0j_UQN9FiS8ZsC-CCjBtSwtG9SBsAk7ni5891o8OEkVvi11Mqybz18zQ5VdL28pq0yBSicCZlPyYXVbkpv0svHU8VhZtqjwKFmEblwuou3TduM9GATSqP66PXNjEZ0IbnwBxFStNMy4r1bbGvY3cB1NLHOO0bw"}'],
            ['input' => '{"ciphertext":"nYEFVB7x9GwrdWCfPopHrnZz63pUMJPiluUvP4uKjMZLmMfSXjirkPFJHLNenvAnY9N_St2MsNVRjJGVA8BKpD5Lou9as1LhQKtZvbbhSFeh3Pgtl-dWkk-pPNlUks21xhulz9-WkcUI6UDMECubhTCyks9mQYs4CGYn2-N8YqvGJW-MQY-fKmI_ANLqYmbrxDBg2nLVZwedI1a1mZTvlBmWg6y1J9iliSZmNx3E0D8","iv":"MXJVPlmpK2RmNGH8G12KzA","tag":"XP7oILWIwDQETo5svidYtw","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"Gn6OkvU9Vrj4yW8bEOYQXrZ5nHNTw5NTXj4E8RtYia0XSr77p916dsgJ7ydM-Cqp3bc-FW-Dw2mJzNG9aetUBImFV-C136Zd8qZfurVR6wdmknRRVV_EYDIGEUJmUeN20if7tUP-rxUEVN6R0ROJ-8N_XwDmlxx_kxqjoNBU1GlsGSyPhVXrBPOcHyeLrTQ1Dw4K2zzlOETcIg9HNq2wOgeMl5T7cAwAPup9IYhAYQPijwbZlY2Fh1DuldZ_lrGD6jQSRGKho1aSRd7i-tVyOfLU88nmCN9lInMIXlOWoiTjbip7e0dfbh2_Q4EDg-bwsvolgsiVt9Xqrz-2E1q0xM7E086KcFFG4__xyt0Y5J-TPlrX9oL1XYikSYaJG9LkSdUbuYNqqTdx8tRvpX_-r_zP7qlvTPZEsaR-Pa_ICKohZfqxMuU4c7ZEP2ayOLDDpewAm3oKX5Ln5hjBMNrWh-chsNin2t90Morq72xsCkKhRCEczXljQpp574e5j-8eIOv4o-LNCaf1liuq-4kHl48B7IkQrhNQtSJ6sEf5NyIItesD513o1XRcLadH4VYmn_zbUXOpTWcy32EoqawV8SVamku1MBup2hme01i5UPstvJVU2TT6lPAp0Y1IQrUwY6z0CDzT9FbUvJBi07Wu0GNj1hFrrryZaI8DcEMnhpM"}'],
            ['input' => '{"ciphertext":"IunHcQrdO2xEJO_DTbjfC9RodsUSE8YBHSSdtJW3DNDHfiOeioejCgXCKLWJRXhzOsC1LLcgt8n1oFncw7QnoMNGq6bhUqJ9o53CoetZTwP_aM6lKK7Fq73dRmj_ejcgphIAvlhEjMGQbi60jgBgrerilT4N_S7x3f39CSX2VnDScdHlLnLLj_822sjQoxAOFGhMQ2FSXLIISWdCxUQG13xtK-RxLRJhcL_F6rdQpNo","iv":"IOYdkjO4y9mVjiX8RNlh0w","tag":"xy6A83DIJUkEzKM8FjyoyZfxpCvGfqYK","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"ulk_x1VauBMMaN_FKe2Db6fk4RBwiZRKCvBgYz_ddJY916pYBPwZ4v9YmL9EtxU1isbzgXHTPjHHWlRI7PdqMZm5_kdzgo98uxd8cklLTDJz8dcA3-DQmcFmszOG2Wh2_vdMdUnrQxdmM8cI4k62zZ4WsCM0rGiANE7KRSieuxwkUHYXu62i9U7WT1m9re0UnNGBP_7kGSYgigSJfTsoWRH6eKGye5bXAcdOlfbo0hGu1i_9p9duClP_u9AR7LSxdUxzmTSW9yjHVMSg_PhJBIw9IBqAtfTR9K6ltzxbVPHRXzeIaxU8u14u9UE5ubIP325yot1XAdS-2r9tW_UsaPxFPn-wAuguU0vYcJoi_Lng7ZUf_KwpUXIcKplY2nThnZH8Q4GDlvrmDMUwRET9Uv5_rspX3VLL1isrJmghV4CyO18RX8bpgEYGqMhssXFPUTipcAlbWPIDRt-sjH8LpuQ777bygBFNwtBoAtK5CTL8PgdWPE7RORVKGRJGkcnsqiqyWKnaztY5XIOG57fFgQ055zjfThBKcV40Iit-FwSeq6NVyS3FSiJlQ4pJVWkcebhNIewOO2yvbQFyj_HMe5NMTPyJEZIL8P6L0b6VUsupMVkaJEM8ZbvvjOQ9iU7Cs7l9S1NWLZ7reIxNT-JSFHT2IrAYxl_BdgbBrwsJ5Hs"}'],
            ['input' => '{"ciphertext":"1-42J-20SxLWe2xcuvITQFe4uOI83WEl8DH33pCZAMAaWfiPPKFT1GEHqFApj90pEigPZ1vieh150m05DDE5iE_I1Oanp3RD0JtF7kFDQGl-WthHEpid4BffTD70m8Jdy2DBaHLAnVoshQJKWTP269Xvx-avbU_SQfGUCa9uOoWaWGEZ99S4i8IMyMIx6H6H-buTBizeeMy1C14WPmi_IBu6HF_V_5hk4xIXkeN1QNs","iv":"rD3ssiyJAzK2w_NBCu3dhg","tag":"pOegUBPvh0mwRfYuiy_Xpn-QoY1iacjtNkRqY6k63dU","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"A0pMdy8sJfzd3KHguIGU9BiYL13lFsjkud3qY-1Roofxgq95jCJSg4Gt5t0ob52JC-xK7mtoLDhnkRbX7lPVaDdUOBQ1fK3eueFZigXW63XUE7xJF9cRJrWQ6aPuxgdwz-DhIbZP-bfozvSg6SqvaMNZjGgtiV2-Xd0awzF7ZtZbJEVOpgZGFV4PabGvVsZ7OA7ezQ0MUauwz4JuWDvggebiFESLwJhsP__xR2NhFWpcIBdOoKqYy1-s1cHa_TBoqq96q5OjYE8hz6NVa1A50WeudTflaObgyY2_cze_oXVbd77ve5_i1k2SyR_C8D24tCwCFq-zZnxoSqXzu1TI8ddl9yqs3DXQRGv7ow1R7QIF0V9D-2L-LcP9xsQ11j45FEoXI-TM67ob4AxkrLzGY8G8tT8ihTF9LFUyQV0qBA41Tsu-72-c_rdysigmQTjI7zj5BBi1rOPKJpewZ6QSpDP_D0Ko4Iv1WfCis8D49WqMguLI6cF2Ph5HXIbuzXSLqJlzJXXQvvxP1Pa3OVqrUUVJ2zIwoA1A3_og6LNH8qpeeSUQn9b8Vuoo6-xlGhg-iUHPHtWRQNIdDAu39kSHWLxGRdA1CKPyRk6nZoFFESSc-9nhWB4zb080Lm3YKEm-4EPVdCwdDavXTwGRS3vPx6AfFvaCn58dvU3NNQXMbOE"}'],
            ['input' => '{"ciphertext":"mrk14MJdDRKyqlvjahhsHdet8oXYuqTmoJ5BeORbij3ZyyAZVEz4J42gjtG5wwlkR0rB4BazlrBcaBZdZoNK1OKBj7h3s0QUd1nMhF5qA7h8jeiwxirXOqhlwHUxpEPWwJ04XcS-eG4VI-DOSk5Tem7bRn_PlL4VC1qS_Y_ZQk6P7x-tMQLcYQWwme4-E14n8_syWyfzNqHQHRdmNmPSLZ3daOFCqsk","iv":"ppT2nVwjH0oM19hQ","tag":"edjw-7Ta4gf8w42nsucCuA","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"HUGJZ2q9oPK6BTH0NBZJVKSDEq7OU1Z-8T4GLv70HbEZJ43iAjUe1-K5WDQzz2ikAtQSyTAmVySir3ziLdMUJt0vBj5iQakFtxmYD4GA_lNudh5b_12D1I4xCwjCEYKX5FByT7QYm3rU79XGNYs0gzbTKha78X9mQ5SsDgQqXvbESz-7apeAlaKa1PqyO8ow0s-Pp0wUDbP3NLjK6qozTPSf34MpDt44FAcc6TR92dXDMkvi4_SdKGKUKwvYx7KHe0hKoHub0rl_m68UAdlxJ2Hy39n-HefN2pL-M46k9SlfZiQdA_wVDg7jNMJG0pD19XWLpM3n8a_meGMt8UYcqsUagMydjJU-10I_lO--HXA4kfjulEmvXOdZrAgea28f5w_BRpoMGJnkTks-UqDfFa2KPOv2S-qYO0aNwPcuhLOIwiPRKtgcuujG6GtuBgMUleS2pNoZg6q6Gw3mQC7sBSikOqCyEx_A-CTzzXFqfN8k986QDCTx-2OT97jaaQPQ8BWVQgLzDDREj7wuv60CQL031bv27P99oZ80BK-vGiPfzjG0MNwT7BS7NC6NnhgXFS4Czo4SECk0TCmhz06IckID8xUIn_TJtQtn9gAPnyZaHV4R9YIoHx_Y7cmnc-xAd4gVk65QpviaKJ-cgyNcNuoIiklmm3CHDxaydat6xHI"}'],
            ['input' => '{"ciphertext":"b4wrAX6XyHJy01y0MdUtMqLyMiNs_Q7kHUdPYaB0s83zQ5gdJfc3L0CJBdTPV5tC4QY6N8-r6QrLSj5O-QFDgCpIj7c3IYFtjKPtpsiWJ80HyZ4ZoIBCrOshhUtCMzs_L4MYVRi2kKr-wvsAKmODw62kzFVzoEEWaEK5zdbgWbS9AGa0g2LMe80Y4blTE0SAwc215KBlY-_ONYULBecP8DjLCnu4Ybs","iv":"A6eFQhv2gXcyQAwS","tag":"Y4lDzYlIGqcqNoSpSYJOdg","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"pyvUtlJZBjW7SY2qIesf4wJuiHsXM6Qmd0hJxGu3GaPpSrNhj19TlcNkAAH9JFoBo1i8GS3Qw6BsWBO6FXVtXqm-ZAi03Hw5BqOlaVz5Ls_Ruj6z6GUxa9MYJAd-iIWqCD1yCyT578ZwHZaarAA2tCuZMADxaQ74pBaXUggt7UmU3D5TZiEHuh4ShjB2CJR2fxJnO-U1GyAkr7j4XbFU5xVoxgTQDYd4FlDA0KDScnGd9r2gBT6TnM2ljA1nIyEz7a5qjDODZvVWTLqEmoRNgXzXrWT0WTh1wCrh0Q15JY_qLoTW8bWTBbs1bZLtpLaU0RL84F3iaEskcHo4O4VtSzKOQyDCVchN52gFN-yJ_IUTXBgb3HWJpM9QIP_0t-sAcg37CPO-JeuvrdT5e7_s8IMdMw2QzwpFdUT86FQAdYDYLKwG8TzMwqISLKkMeRZpt2N7XgKrDSTX-HsYLzWedc7DPugHfbEl2nknTFcmfjDj20Vpr01z_jWMhr6gs9612ucx71i0qYFk0PXDUN2dWY_w_ff790KNA5EEYlQLdnJ6BH1N30I654v23KUR9gs6kDy1KyHUuw-ylfByYXYT8du22vH5DzXiyW_ldHov_WULhGupABcE800ou2TPf94LOkfam47M8CISDJCqJ-rtkCVza-wCCw4lQf7ZvtAoJUE"}'],
            ['input' => '{"ciphertext":"05bmbpoOhrkgxaKrD15PJjOapFOMm5XdHCiQIpbDrbh7_yarzAOqtsnbhocrJ-3bNVgU4i7DevuNMWDdrM1BQDXUOmEKaNqx10I5k65aOE3B16--IG-RjOxdlUGj5YwQewyi98twt2SEmAwJJy7XkAaULrWYGluklqyg5XMBWmpkRG6i5lDMX7um19o4mtOkcWhp0uUnbuu-ZIe38eOivalJRQLXcRg","iv":"TibsjD24NcHTumc1","tag":"9N2CVWptZDd5IqlxuAgmJw","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"aM2uxhn1345sBBAohoHchu13E10LDU79BXdO97HbAqtqQf8CBw8vt3C39CCNz46J5_IIpSYDjvhIgj4ivMCR0hPIHfYdWcAmtDnzKz1kbD4olHE0aQoOe-Vckg08J6-MEXeHL9yPNFhLPSo8-SrMAnEbSeTYB88MEpABXOW-y9cM_R9D6zO5trinfu60TjCY_28SZl54i22g_U3xx9Rzqe1nnlZmmoDTFraMv8_WF9Mnnk2S9gXwW8jHe2QSXRSiyouyNIniH2ff6BM-YmI0UEe8yBtq9BgvaQpFWq-XXUcsi6a9jhr0TvizCrX9bvqvRd8FnehZB9MwkI3nyk7CWn9cvIx4oEzNwuP0iQlPu8mZETSV5Mbaya8qsT9mpOSRqEEYcsZHnlpXHofs8HE5_sCqLQy74kc6VCJ3h82lHLoplane9xlfuPulTCnuhd9OyoyQ3hY2-ZDQdfWa7bhmOdSJtUU6e-pC11pL6VpZ-NXjNciuBtT8AZ58lMToZ0fm9RT3zhzBcWuDHbqKfWtt8NzC1y6zaVYiTuTXNzjNBf4NTQe-2HW1sfsyKbe2cxDGqxtH71CIPoVK40gqoWBNiexkZa7ZzwLVD8-97jNx0O2ndFZ3_xhY8359fbxPpUqQTnoRABYmo6CDUgH_uU7nKVfqHldUB5m2RFHfQgWMLDk"}'],
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
