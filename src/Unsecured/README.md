Unsecured JWS For JWT-Framework
===============================

This repository is a sub repository of [the JWT Framework](https://github.com/web-token/jwt-framework) project and is
READ ONLY.

**Please do not submit any Pull Request here.**
You should go to [the main repository](https://github.com/web-token/jwt-framework) instead.

# What Is In This Package?

The `none` signature algorithm, used by the unsecured JWT of RFC 7519, section 6.

It is not an experimental algorithm: it is perfectly standard, but a JWS that uses it has no integrity protection at
all, and it is the root cause of the JWT "alg confusion" family of vulnerabilities. It is shipped apart from the main
library so that using it is an explicit and auditable decision: an application that does not require this package
simply cannot be tricked into accepting an unsecured token.

# Documentation

The official documentation is available as https://web-token.spomky-labs.com/

# Licence

This software is release under [MIT licence](LICENSE).
