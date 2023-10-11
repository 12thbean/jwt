<?php

namespace Zendrop\LaravelJwt\Guards;

use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Zendrop\LaravelJwt\BlacklistInterface;
use Zendrop\LaravelJwt\Jwt;
use Zendrop\LaravelJwt\JwtDecoderInterface;

abstract class BaseJwtGuard
{
    use GuardHelpers;

    public readonly string $name;

    protected JwtDecoderInterface $jwtDecoder;

    protected Request $request;

    protected ?Authenticatable $lastAttempted = null;

    protected Dispatcher $dispatcher;

    protected BlacklistInterface $blacklist;

    public function __construct(
        string $name,
        JwtDecoderInterface $jwtDecoder,
        UserProvider $provider,
        Request $request,
        Dispatcher $dispatcher,
        BlacklistInterface $blacklist,
    ) {
        $this->name = $name;
        $this->jwtDecoder = $jwtDecoder;
        $this->provider = $provider;
        $this->request = $request;
        $this->dispatcher = $dispatcher;
        $this->blacklist = $blacklist;
    }

    public function validate(array $credentials = []): bool
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if (!$user) {
            return false;
        }

        return $this->hasValidCredentials($user, $credentials);
    }

    public function user(): ?Authenticatable
    {
        if ($this->user) {
            return $this->user;
        }

        $token = $this->extractTokenFromRequest();

        if (empty($token)) {
            return null;
        }

        return $this->retrieveUserByToken($token);
    }

    protected function hasValidCredentials(Authenticatable $user, array $credentials): bool
    {
        $validationResult = $this->provider->validateCredentials($user, $credentials);

        if ($validationResult) {
            $this->fireValidatedEvent($user);
        }

        return $validationResult;
    }

    protected function fireValidatedEvent(Authenticatable $user): void
    {
        $this->dispatcher->dispatch(
            new Validated(
                $this->name,
                $user
            )
        );
    }

    protected function retrieveUserByToken(string $token): ?Authenticatable
    {
        $jwt = $this->jwtDecoder->decode($token);

        if (!$jwt) {
            return null;
        }

        if (!is_null($jwt->payload->exp) and $jwt->payload->exp < time()) {
            return null;
        }

        if ($this->blacklist->has($token)) {
            return null;
        }

        $authenticatable = $this->provider->retrieveById($jwt->payload->uid);
        if (!$authenticatable) {
            return null;
        }

        if ($authenticatable->getAuthPassword() != $jwt->payload->pwh) {
            return null;
        }

        return $authenticatable;
    }

    protected function invalidate(Jwt $jwt): void
    {
        $this->blacklist->add($jwt);
    }

    abstract protected function extractTokenFromRequest(): ?string;
}
