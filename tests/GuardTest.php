<?php

namespace Zendrop\LaravelJwt\Tests;

use Illuminate\Auth\RequestGuard;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase;
use Zendrop\LaravelJwt\JwtDecoderInterface;
use Zendrop\LaravelJwt\LaravelJwtServiceProvider;
use Zendrop\LaravelJwt\Models\BlacklistTokenModel;
use Zendrop\LaravelJwt\StatefulGuard;
use Zendrop\LaravelJwt\Tests\Fixtures\GuardTestUser;

/**
 * Covers guard registration and the full request lifecycle of both guard drivers.
 *
 * Laravel 13 rebinds the AuthManager::extend() callback to the AuthManager instance, which
 * silently breaks guard creation unless the service provider keeps its own $this and scope.
 * These tests fail loudly when that happens.
 */
class GuardTest extends TestCase
{
    private const KEY = 'base64:vN0hCJ4qLsvJH5CQ2xTvXPQ0wF1cB7dGkYmZaR3eS8U=';

    private const PASSWORD = 'correct-horse-battery-staple';

    /**
     * @param \Illuminate\Foundation\Application $app
     *
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [LaravelJwtServiceProvider::class];
    }

    /**
     * @param \Illuminate\Foundation\Application $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('laravel-jwt.payload.iss', 'https://jwt.test');
        $app['config']->set('laravel-jwt.keys.encode', self::KEY);
        $app['config']->set('laravel-jwt.keys.decode', self::KEY);
        $app['config']->set('auth.providers.users.model', GuardTestUser::class);
        $app['config']->set('auth.guards.' . LaravelJwtServiceProvider::GUARD_DRIVER_STATEFUL, [
            'driver' => LaravelJwtServiceProvider::GUARD_DRIVER_STATEFUL,
            'provider' => 'users',
        ]);
    }

    protected function defineDatabaseMigrations(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('email')->unique();
            $table->string('password');
        });

        Schema::create(config('laravel-jwt.blacklist-database-table'), function (Blueprint $table): void {
            $table->id();
            $table->string('hash')->unique();
            $table->dateTime('expired_at')->nullable();
            $table->timestamps();
        });
    }

    protected function defineRoutes($router): void
    {
        /** @var Router $router */
        $router->middleware('auth:' . LaravelJwtServiceProvider::GUARD_DRIVER_STATELESS)
            ->get('/_test/stateless', fn () => ['id' => Auth::guard(LaravelJwtServiceProvider::GUARD_DRIVER_STATELESS)->id()]);

        $router->middleware('auth:' . LaravelJwtServiceProvider::GUARD_DRIVER_STATEFUL)
            ->get('/_test/stateful', fn () => ['id' => Auth::guard(LaravelJwtServiceProvider::GUARD_DRIVER_STATEFUL)->id()]);

        $router->post('/_test/login', fn () => [
            'ok' => Auth::guard(LaravelJwtServiceProvider::GUARD_DRIVER_STATEFUL)->attempt([
                'email' => 'jwt@example.com',
                'password' => self::PASSWORD,
            ]),
        ]);

        $router->post('/_test/logout', function () {
            Auth::guard(LaravelJwtServiceProvider::GUARD_DRIVER_STATEFUL)->logout();

            return ['blacklisted' => BlacklistTokenModel::query()->count()];
        });
    }

    public function testBothGuardDriversAreResolvable(): void
    {
        $this->assertInstanceOf(
            RequestGuard::class,
            Auth::guard(LaravelJwtServiceProvider::GUARD_DRIVER_STATELESS)
        );
        $this->assertInstanceOf(
            StatefulGuard::class,
            Auth::guard(LaravelJwtServiceProvider::GUARD_DRIVER_STATEFUL)
        );
    }

    public function testStatelessGuardAuthenticatesUserFromBearerToken(): void
    {
        $user = $this->createUser();

        $this->withToken((string) $user->makeJwt())
            ->getJson('/_test/stateless')
            ->assertOk()
            ->assertJson(['id' => $user->id]);
    }

    public function testStatelessGuardRejectsMalformedToken(): void
    {
        $this->createUser();

        $this->withToken('not.a.jwt')
            ->getJson('/_test/stateless')
            ->assertUnauthorized();
    }

    public function testStatelessGuardRejectsRequestWithoutToken(): void
    {
        $this->createUser();

        $this->getJson('/_test/stateless')->assertUnauthorized();
    }

    public function testStatelessGuardRejectsTokenAfterPasswordChange(): void
    {
        $user = $this->createUser();
        $token = (string) $user->makeJwt();

        $user->password = Hash::make('a-brand-new-password');
        $user->save();

        $this->withToken($token)->getJson('/_test/stateless')->assertUnauthorized();
    }

    public function testStatefulGuardAuthenticatesUserFromBearerToken(): void
    {
        $user = $this->createUser();

        $this->withToken((string) $user->makeJwt())
            ->getJson('/_test/stateful')
            ->assertOk()
            ->assertJson(['id' => $user->id]);
    }

    public function testStatefulGuardAttemptQueuesJwtCookie(): void
    {
        $user = $this->createUser();

        $this->postJson('/_test/login')
            ->assertOk()
            ->assertJson(['ok' => true]);

        $cookieName = config('laravel-jwt.token-cookie-name');
        $this->assertTrue(Cookie::hasQueued($cookieName));

        $jwt = $this->app->make(JwtDecoderInterface::class)->decode(Cookie::queued($cookieName)->getValue());

        $this->assertNotNull($jwt);
        $this->assertSame($user->id, $jwt->payload->sub);
    }

    public function testStatefulGuardRejectsInvalidCredentials(): void
    {
        $user = $this->createUser();
        $user->password = Hash::make('some-other-password');
        $user->save();

        $this->postJson('/_test/login')->assertOk()->assertJson(['ok' => false]);
    }

    public function testStatefulGuardBlacklistsTokenOnLogout(): void
    {
        $user = $this->createUser();
        $token = (string) $user->makeJwt();

        $this->withToken($token)
            ->postJson('/_test/logout')
            ->assertOk()
            ->assertJson(['blacklisted' => 1]);

        $this->withToken($token)->getJson('/_test/stateful')->assertUnauthorized();
        $this->withToken($token)->getJson('/_test/stateless')->assertUnauthorized();
    }

    public function testRemoveExpiredBlacklistedTokensCommandSucceeds(): void
    {
        $this->artisan('laravel-jwt:remove-expired-blacklisted-tokens')->assertSuccessful();
    }

    private function createUser(): GuardTestUser
    {
        $user = new GuardTestUser();
        $user->email = 'jwt@example.com';
        $user->password = Hash::make(self::PASSWORD);
        $user->save();

        return $user;
    }
}
