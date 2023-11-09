<?php

namespace Zendrop\LaravelJwt\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int    $id
 * @property string $hash
 * @property Carbon $expired_at
 */
class BlacklistTokenModel extends Model
{
    /**
     * @var array<string, string>
     */
    protected $casts = [
        'expired_at' => 'datetime',
    ];

    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(array $attributes = [])
    {
        $this->table = config('laravel-jwt.blacklist-database-table');

        parent::__construct($attributes);
    }

    public static function findByHash(string $value): ?self
    {
        /** @var self $result */
        $result = self::query()
            ->where('hash', $value)
            ->first();

        return $result;
    }
}
