<?php

namespace Zendrop\LaravelJwt;

use Firebase\JWT\Key;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Cookie\QueueingFactory as CookieJarContract;
use Illuminate\Contracts\Events\Dispatcher as EventDispatcherContract;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as IlluminateBaseAuthServiceProvider;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Timebox;
use Zendrop\LaravelJwt\Console\RemoveExpiredBlacklistedTokensCommand;
use Zendrop\LaravelJwt\Guards\JwtGuard;
use Zendrop\LaravelJwt\Guards\JwtStatefulGuard;

class LaravelJwtAuthServiceProvider extends IlluminateBaseAuthServiceProvider
{
    public const JWT_GUARD_NAME = 'laravel-jwt';
    public const STATEFUL_JWT_GUARD_NAME = 'laravel-jwt-cookie';

    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/laravel-jwt.php',
            'laravel-jwt'
        );
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../../config/laravel-jwt.php' => config_path('laravel-jwt.php'),
        ]);

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->commands([
                RemoveExpiredBlacklistedTokensCommand::class,
            ]);
        }

        $this->bindBlacklist();
        $this->bindJwtIssuer();
        $this->bindJwtDecoder();

        $this->extendAuthWithJwtGuard();
        $this->extendAuthWithJwtStatefulGuard();
    }

    protected function bindBlacklist(): void
    {
        $this->app->bind(BlacklistInterface::class, (config('laravel-jwt.blacklist-driver')));
    }

    protected function bindJwtIssuer(): void
    {
        $this->app->bind(JwtIssuerInterface::class, function (): JwtIssuer {
            return new JwtIssuer(
                key: config('laravel-jwt.keys.encode'),
                algorythm: config('laravel-jwt.algorithm'),
                config: new JwtIssuerConfig(
                    iss: config('laravel-jwt.payload.iss'),
                    ttl: config('laravel-jwt.payload.ttl')
                )
            );
        });
    }

    protected function bindJwtDecoder(): void
    {
        $this->app->bind(JwtDecoderInterface::class, function (): JwtDecoder {
            return new JwtDecoder(
                new Key(
                    keyMaterial: config('laravel-jwt.keys.decode'),
                    algorithm: config('laravel-jwt.algorithm')
                )
            );
        });
    }

    protected function extendAuthWithJwtGuard(): void
    {
        Auth::extend(self::JWT_GUARD_NAME, function (Application $app, string $name, array $config): Guard {
            return new JwtGuard(
                name: self::JWT_GUARD_NAME,
                jwtDecoder: app(JwtDecoderInterface::class),
                provider: Auth::createUserProvider($config['provider']),
                request: request(),
                dispatcher: app(EventDispatcherContract::class),
                blacklist: app(BlacklistInterface::class)
            );
        });
    }

    protected function extendAuthWithJwtStatefulGuard(): void
    {
        Auth::extend(
            self::STATEFUL_JWT_GUARD_NAME,
            function (Application $app, string $name, array $config): JwtStatefulGuard {
                return new JwtStatefulGuard(
                    name: self::STATEFUL_JWT_GUARD_NAME,
                    jwtDecoder: app(JwtDecoderInterface::class),
                    provider: Auth::createUserProvider($config['provider']),
                    request: request(),
                    dispatcher: app(EventDispatcherContract::class),
                    blacklist: app(BlacklistInterface::class),
                    jwtIssuer: app(JwtIssuerInterface::class),
                    cookieJar: app(CookieJarContract::class),
                    timebox: new Timebox()
                );
            }
        );
    }
}
