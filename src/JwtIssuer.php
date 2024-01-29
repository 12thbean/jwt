<?php

namespace Zendrop\LaravelJwt;

use Firebase\JWT\JWT as FirebaseLibraryJwt;
use Illuminate\Contracts\Auth\Authenticatable;

class JwtIssuer implements JwtIssuerInterface
{
    /** @var array<string, Jwt> */
    private array $lastIssued = [];

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

        $jwt = new Jwt(
            payload: $payload,
            encodedToken: $encodedToken
        );

        $this->lastIssued[(string)$authenticatable->getAuthIdentifier()] = $jwt;

        return $jwt;
    }

    public function getLastIssued(Authenticatable $authenticatable): ?Jwt
    {
        return $this->lastIssued[(string)$authenticatable->getAuthIdentifier()] ?? null;
    }
}
