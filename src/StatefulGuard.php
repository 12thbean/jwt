<?php

namespace Zendrop\LaravelJwt;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard as StatefulGuardContract;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Cookie\QueueingFactory as CookieQueueingFactory;
use Illuminate\Contracts\Events\Dispatcher as EventDispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Timebox;
use Zendrop\LaravelJwt\Traits\ExtractTokenFromRequestTrait;

class StatefulGuard implements StatefulGuardContract
{
    use ExtractTokenFromRequestTrait;
    use GuardHelpers;

    /**
     * The name of the guard.
     *
     * Corresponds to guard name in authentication configuration.
     */
    public readonly string $name;

    /**
     * The request instance.
     */
    protected Request $request;

    /**
     * The timebox instance.
     */
    protected Timebox $timebox;

    /**
     * JwtGuard.
     */
    protected Guard $guard;

    /**
     * Invalidated tokens management.
     */
    protected BlacklistDriverInterface $blacklist;

    /**
     * The Illuminate cookie creator service.
     */
    protected CookieQueueingFactory $cookieQueuingFactory;

    /**
     * The event dispatcher instance.
     */
    protected EventDispatcher $events;

    /**
     * The jwt issuer.
     */
    protected JwtIssuerInterface $jwtIssuer;

    /**
     * Indicates if the logout method has been called.
     */
    protected bool $loggedOut = false;

    /**
     * The user we last attempted to retrieve.
     */
    protected ?Authenticatable $lastAttempted = null;

    public function __construct(
        string $name,
        Request $request,
        Guard $guard,
        JwtIssuerInterface $jwtIssuer,
        CookieQueueingFactory $cookieQueuingFactory,
        BlacklistDriverInterface $blacklist,
        UserProvider $provider,
        EventDispatcher $eventDispatcher,
        Timebox $timebox = null,
    ) {
        $this->name = $name;
        $this->request = $request;
        $this->guard = $guard;
        $this->jwtIssuer = $jwtIssuer;
        $this->cookieQueuingFactory = $cookieQueuingFactory;
        $this->blacklist = $blacklist;
        $this->provider = $provider;
        $this->events = $eventDispatcher;
        $this->timebox = $timebox ?? new Timebox();
    }

    public function user(): ?Authenticatable
    {
        if ($this->loggedOut) {
            return null;
        }

        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        return $this->user ?? ($this->user = call_user_func($this->guard, $this->request));
    }

    /**
     * @param array<string, string> $credentials
     */
    public function validate(array $credentials = []): bool
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if (null === $user) {
            return false;
        }

        return $this->hasValidCredentials($user, $credentials);
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param array<string, string> $credentials
     * @param bool                  $remember
     */
    public function attempt(array $credentials = [], $remember = false): bool
    {
        $this->fireAttemptEvent($credentials, $remember);

        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if (null === $user) {
            return false;
        }

        // If an implementation of UserInterface was returned, we'll ask the provider
        // to validate the user against the given credentials, and if they are in
        // fact valid we'll log the users into the application and return true.
        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user, $remember);

            return true;
        }

        // If the authentication attempt fails we will fire an event so that the user
        // may be notified of any suspicious attempts to access their account from
        // an unrecognized user. A developer may listen to this event as needed.
        $this->fireFailedEvent($user, $credentials);

        return false;
    }

    /**
     * Log a user into the application without sessions or cookies.
     *
     * @param array<string, string> $credentials
     */
    public function once(array $credentials = []): bool
    {
        $this->fireAttemptEvent($credentials);

        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    public function login(Authenticatable $user, $remember = false): void
    {
        $this->queueJwtCookie($user, $remember);

        // If we have an event dispatcher instance set we will fire an event so that
        // any listeners will hook into the authentication events and run actions
        // based on the login and logout events fired from the guard instances.
        $this->fireLoginEvent($user, $remember);

        $this->setUser($user);
    }

    /**
     * Log the given user ID into the application.
     *
     * @param bool $remember
     */
    public function loginUsingId($id, $remember = false): Authenticatable|false
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {
            $this->login($user, $remember);

            return $user;
        }

        return false;
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     */
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
        return true;
    }

    /**
     * Log the user out of the application.
     */
    public function logout(): void
    {
        $user = $this->user();

        // This allows the developer to be listening for anytime a user signs out of
        // this application manually.
        $this->events->dispatch(new Logout($this->name, $user));

        if ($token = $this->extractTokenFromRequest($this->request)) {
            $this->blacklist->add($token);
        }

        // Once we have fired the logout event we will clear the users out of memory
        // so they are no longer available as the user is no longer considered as
        // being signed into this application and should not be available here.
        $this->user = null;

        $this->loggedOut = true;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param array<string, string> $credentials
     */
    protected function hasValidCredentials(Authenticatable $user, array $credentials): bool
    {
        return $this->timebox->call(function ($timebox) use ($user, $credentials) {
            $validated = $this->provider->validateCredentials($user, $credentials);

            if ($validated) {
                $timebox->returnEarly();

                $this->fireValidatedEvent($user);
            }

            return $validated;
        }, 200 * 1000);
    }

    protected function queueJwtCookie(Authenticatable $user, bool $remember): void
    {
        $shouldBeSessionCookie = !$remember;

        $jwt = $this->jwtIssuer->makeJwt($user, $shouldBeSessionCookie);

        $cookie = $this->cookieQueuingFactory->make(
            name: config('laravel-jwt.token-key'),
            value: $jwt->encodedToken,
            minutes: ($shouldBeSessionCookie)
                ? 0
                : now()->diffInMinutes(Carbon::createFromTimestamp($jwt->payload->exp)),
            httpOnly: false
        );

        $this->cookieQueuingFactory->queue($cookie);
    }

    /**
     * Fire the attempt event with the arguments.
     *
     * @param array<string, string> $credentials
     */
    protected function fireAttemptEvent(array $credentials, bool $remember = false): void
    {
        $this->events->dispatch(new Attempting($this->name, $credentials, $remember));
    }

    /**
     * Fires the validated event if the dispatcher is set.
     */
    protected function fireValidatedEvent(Authenticatable $user): void
    {
        $this->events->dispatch(new Validated($this->name, $user));
    }

    /**
     * Fire the login event if the dispatcher is set.
     */
    protected function fireLoginEvent(Authenticatable $user, bool $remember = false): void
    {
        $this->events->dispatch(new Login($this->name, $user, $remember));
    }

    /**
     * Fire the authenticated event if the dispatcher is set.
     */
    protected function fireAuthenticatedEvent(Authenticatable $user): void
    {
        $this->events->dispatch(new Authenticated($this->name, $user));
    }

    /**
     * Fire the failed authentication attempt event with the given arguments.
     *
     * @param array<string, string> $credentials
     */
    protected function fireFailedEvent(?Authenticatable $user, array $credentials): void
    {
        $this->events->dispatch(new Failed($this->name, $user, $credentials));
    }

    /**
     * Set the current user.
     *
     * @return $this
     */
    public function setUser(Authenticatable $user): self
    {
        $this->user = $user;

        $this->loggedOut = false;

        $this->fireAuthenticatedEvent($user);

        return $this;
    }

    public function setRequest(Request $request): void
    {
        $this->request = $request;
    }
}
