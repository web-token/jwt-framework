Selective Disclosure For JWT-Framework
======================================

This repository is a sub repository of [the JWT Framework](https://github.com/web-token/jwt-framework) project and is
READ ONLY.

**Please do not submit any Pull Request here.**
You should go to [the main repository](https://github.com/web-token/jwt-framework) instead.

# What Is In This Package?

Selective Disclosure for JWTs, as defined by [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html): the SD-JWT and
SD-JWT+KB formats, compact or in the JWS JSON serialization, and the three roles of the specification on top of the
JWS services of the library.

- The Issuer signs a JWT whose selectively disclosable claims are replaced by salted digests, with decoy digests.
- The Holder selects the Disclosures of the claims it presents and binds the presentation to its key with a Key
  Binding JWT.
- The Verifier checks the Issuer-signed JWT, the Disclosures and the Key Binding JWT, and returns the claims that were
  disclosed.

SD-JWT is the credential format of SD-JWT VC, of the EU Digital Identity Wallet and of OpenID for Verifiable
Credentials. Those profiles are left to the application.

# Documentation

The official documentation is available as https://web-token.spomky-labs.com/

# Licence

This software is release under [MIT licence](LICENSE).
