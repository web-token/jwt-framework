Feature: Shared JWKSet are available through a route

  Scenario: A client wants to get the shared public key set (JWKSet format)
    Given I am on "https://www.example.test/keys/jwkset.json"
    Then the response status code should be 200
    And the response content-type should be "application/jwk-set+json; charset=UTF-8"
    And the response should contain a key set in JWKSet format
