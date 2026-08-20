<?php

namespace Zendrop\LaravelJwt;

use Firebase\JWT\Key;
use Illuminate\Auth\AuthManager;
use Illuminate\Auth\RequestGuard;
use Illuminate\Contracts\Auth\Guard as IlluminateStatelessGuardContract;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Cookie\QueueingFactory as CookieQueueingFactoryContract;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Zendrop\LaravelJwt\Console\RemoveExpiredBlacklistedTokensCommand;
use Zendrop\LaravelJwt\Exceptions\InvalidConfigException;
use Zendrop\LaravelJwt\StatefulGuard as IlluminateStatefulGuardContract;

class LaravelJwtServiceProvider extends ServiceProvider
{
    public const GUARD_DRIVER_STATELESS = 'laravel-jwt';

    public const GUARD_DRIVER_STATEFUL = 'laravel-jwt-stateful';

    /**
     * Register any application services.
     */
    public function register(): void
    {
        config([
            'auth.guards.laravel-jwt' => array_merge([
                'driver' => 'laravel-jwt',
                'provider' => 'users',
            ], config('auth.guards.laravel-jwt', [])),
        ]);

        if (!app()->configurationIsCached()) {
            $this->mergeConfigFrom(__DIR__ . '/../config/laravel-jwt.php', 'laravel-jwt');
        }
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            // todo publish config & migrations

            $this->commands([
                RemoveExpiredBlacklistedTokensCommand::class,
            ]);
        }

        $this->bindDependencies();
        $this->configureGuardDrivers();
    }

    /**
     * Sets up bindings for JWT issuer, decoder, and blacklist interfaces.
     */
    protected function bindDependencies(): void
    {
        $this->app->bind(JwtIssuerInterface::class, function (): JwtIssuer {
            return new JwtIssuer(
                rawEncodeKey: config('laravel-jwt.keys.encode'),
                encodingAlgorithm: config('laravel-jwt.algorithm'),
                tokenIssuerName: config('laravel-jwt.payload.iss'),
                shortTermTokenTTL: config('laravel-jwt.token-ttl.short-term'),
                longTermTokenTTL: config('laravel-jwt.token-ttl.long-term'),
            );
        });

        $this->app->bind(JwtDecoderInterface::class, function (): JwtDecoder {
            $algorithm = config('laravel-jwt.algorithm');

            $rawKeys = array_values(array_filter(array_map(
                'trim',
                explode(',', (string) config('laravel-jwt.keys.decode'))
            )));

            if ([] === $rawKeys) {
                throw new InvalidConfigException('laravel-jwt.keys.decode must contain at least one key.');
            }

            return new JwtDecoder(
                array_map(
                    static fn (string $keyMaterial): Key => new Key($keyMaterial, $algorithm),
                    $rawKeys
                )
            );
        });

        $this->app->bind(BlacklistDriverInterface::class, config('laravel-jwt.blacklist-driver'));
    }

    /**
     * Configures laravel-jwt guard drivers.
     */
    protected function configureGuardDrivers(): void
    {
        // Laravel 13 rebinds the extend() callback to the AuthManager instance
        // (Illuminate\Support\RebindsCallbacksToSelf), which changes both $this and the
        // closure scope. First-class callables keep their own $this and scope, so guard
        // creation keeps working on Laravel 11, 12 and 13.
        $createStatelessGuard = $this->createStatelessGuard(...);
        $createStatefulGuard = $this->createStatefulGuard(...);

        // laravel-jwt
        Auth::resolved(function (AuthManager $auth) use ($createStatelessGuard) {
            $auth->extend(
                driver: static::GUARD_DRIVER_STATELESS,
                callback: function ($app, $name, array $config) use ($auth, $createStatelessGuard) {
                    $guard = $createStatelessGuard($auth, $config);
                    $app->refresh('request', $guard, 'setRequest');

                    return $guard;
                }
            );
        });

        // laravel-jwt-stateful
        Auth::resolved(function (AuthManager $auth) use ($createStatefulGuard) {
            $auth->extend(
                driver: static::GUARD_DRIVER_STATEFUL,
                callback: function ($app, $name, array $config) use ($auth, $createStatefulGuard) {
                    $guard = $createStatefulGuard($auth, $name, $config);
                    $app->refresh('request', $guard, 'setRequest');

                    return $guard;
                }
            );
        });
    }

    /**
     * @param array<string, mixed> $config
     *
     * @throws InvalidConfigException
     */
    protected function createStatelessGuard(AuthManager $authManager, array $config): IlluminateStatelessGuardContract
    {
        $userProvider = $this->getUserProvider($authManager, $config['provider']);

        return new RequestGuard(
            callback: $this->createGuard($userProvider),
            request: request(),
            provider: $userProvider
        );
    }

    /**
     * @param array<string, mixed> $config
     *
     * @throws InvalidConfigException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function createStatefulGuard(
        AuthManager $authManager,
        string $name,
        array $config
    ): IlluminateStatefulGuardContract {
        $userProvider = $this->getUserProvider($authManager, $config['provider']);

        return new StatefulGuard(
            name: $name,
            request: request(),
            guard: $this->createGuard($userProvider),
            jwtIssuer: $this->app->make(JwtIssuerInterface::class),
            cookieQueuingFactory: $this->app->make(CookieQueueingFactoryContract::class),
            blacklist: $this->app->make(BlacklistDriverInterface::class),
            provider: $userProvider,
            eventDispatcher: $this->app['events']
        );
    }

    protected function createGuard(UserProvider $userProvider): Guard
    {
        return new Guard(
            jwtDecoder: $this->app->make(JwtDecoderInterface::class),
            blacklist: $this->app->make(BlacklistDriverInterface::class),
            userProvider: $userProvider,
        );
    }

    /**
     * @throws InvalidConfigException
     */
    protected function getUserProvider(AuthManager $authManager, string $providerName): UserProvider
    {
        $userProvider = $authManager->createUserProvider($providerName);

        if (!$userProvider) {
            throw new InvalidConfigException('Provider for guard is missed. Check the auth config.');
        }

        return $userProvider;
    }
}
