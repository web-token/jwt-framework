Feature: Compression services are available

    Scenario: The compression methods manager is available and can issue compression methods managers
        Given the compression methods manager factory is available
        When I create an compression methods manager with method DEF
        Then I should get a compression manager with method DEF
