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
        protected readonly int $shortTermTokenTTL,
        protected readonly int $longTermTokenTTL
    ) {
    }

    public function makeJwt(Authenticatable $authenticatable, bool $shortTerm = false): Jwt
    {
        $ttl = $shortTerm ? $this->shortTermTokenTTL : $this->longTermTokenTTL;

        $payload = new Payload(
            iss: $this->tokenIssuerName,
            iat: time(),
            sub: $authenticatable->getAuthIdentifier(),
            exp: time() + $ttl,
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
