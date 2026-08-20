<?php

namespace Zendrop\LaravelJwt;

use Illuminate\Contracts\Support\Arrayable;

/**
 * @implements Arrayable<string, mixed>
 */
class Payload implements Arrayable
{
    public function __construct(
        public readonly string $iss,
        public readonly int $iat,
        public readonly string|int $sub,
        public readonly ?int $exp,
        public readonly ?string $pwh
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $reflectionClass = new \ReflectionClass($this);
        $properties = $reflectionClass->getProperties(\ReflectionProperty::IS_PUBLIC);

        $array = [];
        foreach ($properties as $property) {
            if ($property->isInitialized($this)) {
                $propertyName = $property->getName();
                $array[$propertyName] = $this->{$propertyName};
            }
        }

        return $array;
    }
}
