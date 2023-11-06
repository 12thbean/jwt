<?php

namespace Zendrop\LaravelJwt;

use Firebase\JWT\JWT as FirebaseLibraryJwt;
use Illuminate\Contracts\Auth\Authenticatable;

class JwtIssuer implements JwtIssuerInterface
{
    public function __construct(
        protected readonly string $rawEncodeKey,
        protected readonly string $encodingAlgorithm,
        protected readonly string $tokenIssuerName,
        protected readonly int $tokenTTL
    ) {
    }

    public function makeJwt(Authenticatable $authenticatable): Jwt
    {
        $payload = new Payload(
            iss: $this->tokenIssuerName,
            iat: time(),
            sub: $authenticatable->getAuthIdentifier(),
            exp: time() + $this->tokenTTL,
            pwh: $authenticatable->getAuthPassword(),
        );

        $encodedToken = FirebaseLibraryJwt::encode(
            payload: $payload->toArray(),
            key: $this->rawEncodeKey,
            alg: $this->encodingAlgorithm,
        );

        return new Jwt(
            payload: $payload,
            encodedToken: $encodedToken
        );
    }
}
