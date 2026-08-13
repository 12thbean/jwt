<?php

namespace Zendrop\LaravelJwt\Tests;

use Firebase\JWT\JWT as FirebaseLibraryJwt;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\TestCase;
use Zendrop\LaravelJwt\Events\JwtDecodedUsingFallbackKey;
use Zendrop\LaravelJwt\Exceptions\InvalidConfigException;
use Zendrop\LaravelJwt\JwtDecoderInterface;
use Zendrop\LaravelJwt\LaravelJwtServiceProvider;

class JwtDecoderTest extends TestCase
{
    private const NEW_KEY = 'base64:NEWKEYNEWKEYNEWKEYNEWKEYNEWKEY=';

    private const OLD_KEY = 'base64:OLDKEYOLDKEYOLDKEYOLDKEYOLDKEY=';

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
        $app['config']->set('laravel-jwt.keys.encode', self::NEW_KEY);
        $app['config']->set('laravel-jwt.keys.decode', self::NEW_KEY . ',' . self::OLD_KEY);
    }

    public function testDecodesTokenSignedWithPrimaryKey(): void
    {
        Event::fake();

        $jwt = $this->makeDecoder()->decode($this->issueToken(self::NEW_KEY));

        $this->assertNotNull($jwt);
        $this->assertSame(42, $jwt->payload->sub);
        Event::assertNotDispatched(JwtDecodedUsingFallbackKey::class);
    }

    public function testDecodesLegacyTokenWithFallbackKeyAndDispatchesEvent(): void
    {
        Event::fake();

        $jwt = $this->makeDecoder()->decode($this->issueToken(self::OLD_KEY));

        $this->assertNotNull($jwt);
        $this->assertSame(42, $jwt->payload->sub);
        Event::assertDispatched(
            JwtDecodedUsingFallbackKey::class,
            fn (JwtDecodedUsingFallbackKey $event) => $event->keyIndex === 1 && $event->jwt->payload->sub === 42
        );
    }

    public function testTrimsSpacesAndSkipsEmptySegmentsInKeyList(): void
    {
        config(['laravel-jwt.keys.decode' => ' ' . self::NEW_KEY . ' , ' . self::OLD_KEY . ' ,']);

        $decoder = $this->makeDecoder();

        $this->assertNotNull($decoder->decode($this->issueToken(self::NEW_KEY)));
        $this->assertNotNull($decoder->decode($this->issueToken(self::OLD_KEY)));
    }

    public function testSingleKeyConfigKeepsWorking(): void
    {
        config(['laravel-jwt.keys.decode' => self::OLD_KEY]);

        $decoder = $this->makeDecoder();

        $this->assertNotNull($decoder->decode($this->issueToken(self::OLD_KEY)));
        $this->assertNull($decoder->decode($this->issueToken(self::NEW_KEY)));
    }

    public function testReturnsNullForTokenSignedWithUnknownKey(): void
    {
        $token = $this->issueToken('base64:UNKNOWNUNKNOWNUNKNOWNUNKNOWN');

        $this->assertNull($this->makeDecoder()->decode($token));
    }

    public function testReturnsNullForMalformedToken(): void
    {
        $this->assertNull($this->makeDecoder()->decode('not.a.jwt'));
    }

    public function testReturnsNullForExpiredToken(): void
    {
        $token = $this->issueToken(self::OLD_KEY, ['iat' => time() - 7200, 'exp' => time() - 3600]);

        $this->assertNull($this->makeDecoder()->decode($token));
    }

    public function testThrowsWhenDecodeKeyListIsEmpty(): void
    {
        config(['laravel-jwt.keys.decode' => ' , ']);

        $this->expectException(InvalidConfigException::class);

        $this->makeDecoder();
    }

    private function makeDecoder(): JwtDecoderInterface
    {
        return $this->app->make(JwtDecoderInterface::class);
    }

    /**
     * @param array<string, mixed> $claimOverrides
     */
    private function issueToken(string $key, array $claimOverrides = []): string
    {
        $claims = array_merge([
            'iss' => 'test-issuer',
            'iat' => time(),
            'sub' => 42,
            'exp' => time() + 3600,
            'pwh' => 'password-hash',
        ], $claimOverrides);

        return FirebaseLibraryJwt::encode($claims, $key, 'HS256');
    }
}
