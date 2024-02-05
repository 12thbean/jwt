<?php

namespace Zendrop\LaravelJwt;

use Firebase\JWT\JWT as FirebaseLibraryJwt;
use Illuminate\Contracts\Auth\Authenticatable;

class JwtIssuer implements JwtIssuerInterface
{
    /**
     * @var array<string, Jwt>
     */
    private array $lastIssued = [];

    public function __construct(
        protected readonly string $rawEncodeKey,
        protected readonly string $encodingAlgorithm,
        protected readonly string $tokenIssuerName,
        protected readonly int $shortTermTokenTTL,
        protected readonly int $longTermTokenTTL
    ) {
    }

    public function makeJwt(Authenticatable $authenticatable, bool $shortTerm = false, bool $forceNew = false): Jwt
    {
        if ($forceNew) {
            return $this->issueNew($authenticatable, $shortTerm);
        }

        $cached = $this->getFromCache($authenticatable, $shortTerm);

        if (!$cached) {
            $jwt = $this->issueNew($authenticatable, $shortTerm);
            $this->putInCache($authenticatable, $shortTerm, $jwt);
            return $jwt;
        }

        return $cached;
    }

    private function issueNew(Authenticatable $authenticatable, bool $shortTerm = false): Jwt
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

    private function getCacheKey(Authenticatable $authenticatable, bool $isShortTermed): string
    {
        return 'laravel-jwt_' . $authenticatable->getAuthIdentifier() . '_' . (int)$isShortTermed;
    }

    private function putInCache(Authenticatable $authenticatable, bool $isShortTermed, Jwt $jwt): void
    {
        $cacheKey = $this->getCacheKey($authenticatable, $isShortTermed);
        $this->lastIssued[$cacheKey] = $jwt;
    }

    private function getFromCache(Authenticatable $authenticatable, bool $isShortTermed): ?Jwt
    {
        $cacheKey = $this->getCacheKey($authenticatable, $isShortTermed);
        return $this->lastIssued[$cacheKey] ?? null;
    }
}
