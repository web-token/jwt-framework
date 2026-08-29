RSA1_5 Key Encryption For JWT-Framework
=======================================

This repository is a sub repository of [the JWT Framework](https://github.com/web-token/jwt-framework) project and is
READ ONLY.

**Please do not submit any Pull Request here.**
You should go to [the main repository](https://github.com/web-token/jwt-framework) instead.

# What Is In This Package?

The `RSA1_5` key encryption algorithm (RSAES-PKCS1-v1_5) of RFC 7518, section 4.2.

It is not an experimental algorithm: it is perfectly standard, but its padding is vulnerable to the Bleichenbacher
adaptive chosen-ciphertext attack, and RFC 8017 discourages it for new applications. It is shipped apart from the main
library so that using it is an explicit and auditable decision. Use `RSA-OAEP-256` instead whenever the other party
supports it.

The RSASSA-PKCS1-v1_5 **signature** algorithms (`RS256`, `RS384`, `RS512`) are a different family: they are not
affected by this attack and remain in the main library.

# Documentation

The official documentation is available as https://web-token.spomky-labs.com/

# Licence

This software is release under [MIT licence](LICENSE).
