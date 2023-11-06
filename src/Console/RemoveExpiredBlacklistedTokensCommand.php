<?php

namespace Zendrop\LaravelJwt\Console;

use Illuminate\Console\Command;
use Zendrop\LaravelJwt\BlacklistDrivers\DatabaseBlacklistDriver;

class RemoveExpiredBlacklistedTokensCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'laravel-jwt:remove-expired-blacklisted-tokens';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Remove expired tokens from the JWT blacklist';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(DatabaseBlacklistDriver $databaseBlacklist): int
    {
        $this->info("Initiating removal of expired tokens from the JWT blacklist...");

        $databaseBlacklist->removeExpired();

        $this->info("Successfully removed expired tokens from the blacklist.");

        return self::SUCCESS;
    }
}
