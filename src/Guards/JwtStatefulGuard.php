<?php

namespace Zendrop\LaravelJwt\Guards;

use DateTimeInterface;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Cookie\QueueingFactory as CookieJarContract;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use Symfony\Component\HttpFoundation\Cookie;
use Zendrop\LaravelJwt\BlacklistInterface;
use Zendrop\LaravelJwt\JwtDecoderInterface;
use Zendrop\LaravelJwt\JwtIssuerInterface;

class JwtStatefulGuard extends BaseJwtGuard implements StatefulGuard
{
    private const LONG_TERM_COOKIE_NAME = 'token';
    private const SHORT_TERM_COOKIE_NAME = 'fresh_auth_token';

    protected Timebox $timebox;

    protected JwtIssuerInterface $jwtIssuer;

    protected CookieJarContract $cookieJar;

    protected bool $loggedOut = false;

    public function __construct(
        string $name,
        JwtDecoderInterface $jwtDecoder,
        UserProvider $provider,
        Request $request,
        Dispatcher $dispatcher,
        BlacklistInterface $blacklist,
        JwtIssuerInterface $jwtIssuer,
        CookieJarContract $cookieJar,
        Timebox $timebox
    ) {
        $this->jwtIssuer = $jwtIssuer;
        $this->cookieJar = $cookieJar;
        $this->timebox = $timebox;

        parent::__construct($name, $jwtDecoder, $provider, $request, $dispatcher, $blacklist);
    }

    public function attempt(array $credentials = [], $remember = false): bool
    {
        $this->fireAttemptEvent($credentials, $remember);

        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if (!$user) {
            return false;
        }

        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user, $remember);

            return true;
        }

        $this->fireFailedEvent($user, $credentials);

        return false;
    }

    public function login(Authenticatable $user, $remember = false): void
    {
        $expire = $remember ? now()->addYear() : null;

        $this->queueLongTermTokenCookie($user, $expire);
        $this->queueShortTermTokenCookie($user);

        $this->setUser($user);
        $this->fireLoginEvent($user, $remember);
    }

    protected function queueLongTermTokenCookie(Authenticatable $user, ?DateTimeInterface $expire): void
    {
        $this->cookieJar->queue(
            new Cookie(
                name: self::LONG_TERM_COOKIE_NAME,
                value: $this->jwtIssuer->makeJwt($user),
                expire: $expire ?? 0
            )
        );
    }

    protected function forgetLongTermTokenCookie(): void
    {
        $this->cookieJar->forget(self::LONG_TERM_COOKIE_NAME);
    }

    protected function queueShortTermTokenCookie(Authenticatable $user): void
    {
        $this->cookieJar->queue(
            new Cookie(
                name: self::SHORT_TERM_COOKIE_NAME,
                value: $this->jwtIssuer->makeJwt($user),
                expire: now()->addHour()
            )
        );
    }

    public function once(array $credentials = []): bool
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    public function loginUsingId($id, $remember = false): Authenticatable|false
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {
            $this->login($user, $remember);

            return $user;
        }

        return false;
    }

    public function onceUsingId($id): Authenticatable|false
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);

            return $user;
        }

        return false;
    }

    public function viaRemember(): bool
    {
        $shortTermToken = $this->request->cookie(self::SHORT_TERM_COOKIE_NAME);

        if (empty($shortTermToken)) {
            return true;
        }

        /** @var Authenticatable|null $user */
        $user = $this->retrieveUserByToken($shortTermToken);

        if (!$user) {
            return true;
        }

        return !($user->getAuthIdentifier() === $this->user->getAuthIdentifier());
    }

    public function logout(): void
    {
        $jwt = $this->jwtDecoder->decode($this->extractTokenFromRequest());

        if (!$jwt) {
            return;
        }

        if ($this->loggedOut) {
            return;
        }

        $user = $this->user();

        if (!$user) {
            return;
        }

        $this->forgetLongTermTokenCookie();

        $this->invalidate($jwt);

        $this->fireLogoutEvent($user);

        $this->forgetUser();

        $this->loggedOut = true;
    }

    protected function fireLoginEvent($user, $remember = false): void
    {
        $this->dispatcher->dispatch(new Login($this->name, $user, $remember));
    }

    protected function fireFailedEvent(Authenticatable $user, array $credentials): void
    {
        $this->dispatcher->dispatch(new Failed($this->name, $user, $credentials));
    }

    protected function fireAttemptEvent(array $credentials, bool $remember = false): void
    {
        $this->dispatcher->dispatch(new Attempting($this->name, $credentials, $remember));
    }

    protected function fireLogoutEvent(Authenticatable $user): void
    {
        $this->dispatcher->dispatch(new Logout($this->name, $user));
    }

    protected function extractTokenFromRequest(): ?string
    {
        return $this->request->cookie(self::LONG_TERM_COOKIE_NAME) ?? $this->request->bearerToken();
    }
}
