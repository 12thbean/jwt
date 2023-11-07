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
     *
     * @return void
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
            $this->mergeConfigFrom(__DIR__.'/../config/laravel-jwt.php', 'laravel-jwt');
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
     *
     * @return void
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
            return new JwtDecoder(
                new Key(
                    keyMaterial: config('laravel-jwt.keys.decode'),
                    algorithm: config('laravel-jwt.algorithm')
                )
            );
        });

        $this->app->bind(BlacklistDriverInterface::class, (config('laravel-jwt.blacklist-driver')));
    }

    /**
     * Configures laravel-jwt guard drivers
     *
     * @return void
     */
    protected function configureGuardDrivers(): void
    {
        // laravel-jwt
        Auth::resolved(function (AuthManager $auth) {
            $auth->extend(
                driver: static::GUARD_DRIVER_STATELESS,
                callback: function ($app, $name, array $config) use ($auth) {
                    $guard = $this->createStatelessGuard($auth, $config);
                    $app->refresh('request', $guard, 'setRequest');
                    return $guard;
                });
        });

        // laravel-jwt-stateful
        Auth::resolved(function (AuthManager $auth) {
            $auth->extend(
                driver: static::GUARD_DRIVER_STATEFUL,
                callback: function ($app, $name, array $config) use ($auth) {
                    $guard = $this->createStatefulGuard($auth, $name, $config);
                    $app->refresh('request', $guard, 'setRequest');
                    return $guard;
                });
        });
    }

    protected function createStatelessGuard(AuthManager $authManager, array $config): IlluminateStatelessGuardContract
    {
        $userProvider = $this->getUserProvider($authManager, $config['provider']);

        return new RequestGuard(
            callback: $this->createGuard($userProvider),
            request: request(),
            provider: $userProvider
        );
    }

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

    protected function getUserProvider(AuthManager $authManager, $providerName): UserProvider
    {
        $userProvider = $authManager->createUserProvider($providerName);

        if (!$userProvider) {
            throw new InvalidConfigException("Provider for guard is missed. Check the auth config.");
        }
        return $userProvider;
    }
}
