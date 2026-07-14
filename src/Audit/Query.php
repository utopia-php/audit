<?php

namespace Utopia\Audit;

use Utopia\Query\Query as BaseQuery;

/**
 * Audit Query
 *
 * Thin extension of `Utopia\Query\Query` so audit consumers share the
 * canonical query types — including `cursorAfter` / `cursorBefore` and
 * `parse()` validation — while keeping audit's lenient single-value factory
 * signatures (the base requires arrays / scalars only; audit accepts mixed
 * including `DateTime` for the `time` column).
 */
class Query extends BaseQuery
{
    /**
     * Filter by equal condition.
     *
     * Accepts a single scalar/object/array value and stores it as the values
     * array. Matches the legacy audit signature.
     *
     * @param mixed $value Single value or array of values
     */
    #[\Override]
    public static function equal(string $attribute, mixed $value): static
    {
        /** @var array<mixed> $values */
        $values = \is_array($value) ? $value : [$value];
        return new static(self::TYPE_EQUAL, $attribute, $values);
    }

    /**
     * Filter by less than condition.
     *
     * Accepts mixed (including `DateTime` for the `time` column); the
     * adapter handles type-specific formatting.
     */
    #[\Override]
    public static function lessThan(string $attribute, mixed $value): static
    {
        return new static(self::TYPE_LESSER, $attribute, [$value]);
    }

    /**
     * Filter by greater than condition.
     */
    #[\Override]
    public static function greaterThan(string $attribute, mixed $value): static
    {
        return new static(self::TYPE_GREATER, $attribute, [$value]);
    }

    /**
     * Filter by BETWEEN condition.
     */
    #[\Override]
    public static function between(string $attribute, mixed $start, mixed $end): static
    {
        return new static(self::TYPE_BETWEEN, $attribute, [$start, $end]);
    }
}
