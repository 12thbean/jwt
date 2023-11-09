<?php

namespace Zendrop\LaravelJwt;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Zendrop\LaravelJwt\Traits\ExtractTokenFromRequestTrait;

class Guard
{
    use ExtractTokenFromRequestTrait;

    public function __construct(
        protected readonly JwtDecoderInterface $jwtDecoder,
        protected readonly BlacklistDriverInterface $blacklist,
        protected readonly UserProvider $userProvider,
    ) {
    }

    public function __invoke(Request $request): ?Authenticatable
    {
        $rawToken = $this->extractTokenFromRequest($request);

        if (null === $rawToken) {
            return null;
        }

        $jwt = $this->jwtDecoder->decode($rawToken);

        if (null === $jwt) {
            return null;
        }

        $authenticatable = $this->userProvider->retrieveById($jwt->payload->sub);

        if (null === $authenticatable) {
            return null;
        }

        if (!$this->isValid($jwt, $authenticatable)) {
            return null;
        }

        return $authenticatable;
    }

    protected function isValid(Jwt $jwt, Authenticatable $authenticatable): bool
    {
        $isExpired = Carbon::createFromTimestamp($jwt->payload->exp) < now();
        $inBlacklist = $this->blacklist->has($jwt);
        $passwordChanged = $authenticatable->getAuthPassword() !== $jwt->payload->pwh;

        return !$isExpired && !$inBlacklist && !$passwordChanged;
    }
}
