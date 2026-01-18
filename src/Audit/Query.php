<?php

namespace Utopia\Audit;

/**
 * Query class for ClickHouse Audit adapter
 *
 * Provides a fluent interface for building ClickHouse queries.
 * Contains only methods needed for audit log operations.
 */
class Query
{
    // Filter methods
    public const TYPE_EQUAL = 'equal';
    public const TYPE_GREATER = 'greaterThan';
    public const TYPE_LESSER = 'lessThan';
    public const TYPE_BETWEEN = 'between';
    public const TYPE_IN = 'contains';

    // Order methods
    public const TYPE_ORDER_DESC = 'orderDesc';
    public const TYPE_ORDER_ASC = 'orderAsc';

    // Pagination methods
    public const TYPE_LIMIT = 'limit';
    public const TYPE_OFFSET = 'offset';

    protected string $method = '';
    protected string $attribute = '';

    /**
     * @var array<mixed>
     */
    protected array $values = [];

    /**
     * Construct a new query object
     *
     * @param string $method
     * @param string $attribute
     * @param array<mixed> $values
     */
    public function __construct(string $method, string $attribute = '', array $values = [])
    {
        $this->method = $method;
        $this->attribute = $attribute;
        $this->values = $values;
    }

    /**
     * @return string
     */
    public function getMethod(): string
    {
        return $this->method;
    }

    /**
     * @return string
     */
    public function getAttribute(): string
    {
        return $this->attribute;
    }

    /**
     * @return array<mixed>
     */
    public function getValues(): array
    {
        return $this->values;
    }

    /**
     * @param mixed $default
     * @return mixed
     */
    public function getValue(mixed $default = null): mixed
    {
        return $this->values[0] ?? $default;
    }

    /**
     * Filter by equal condition
     *
     * @param string $attribute
     * @param mixed $value
     * @return self
     */
    public static function equal(string $attribute, mixed $value): self
    {
        return new self(self::TYPE_EQUAL, $attribute, [$value]);
    }

    /**
     * Filter by less than condition
     *
     * @param string $attribute
     * @param mixed $value
     * @return self
     */
    public static function lessThan(string $attribute, mixed $value): self
    {
        return new self(self::TYPE_LESSER, $attribute, [$value]);
    }

    /**
     * Filter by greater than condition
     *
     * @param string $attribute
     * @param mixed $value
     * @return self
     */
    public static function greaterThan(string $attribute, mixed $value): self
    {
        return new self(self::TYPE_GREATER, $attribute, [$value]);
    }

    /**
     * Filter by BETWEEN condition
     *
     * @param string $attribute
     * @param mixed $start
     * @param mixed $end
     * @return self
     */
    public static function between(string $attribute, mixed $start, mixed $end): self
    {
        return new self(self::TYPE_BETWEEN, $attribute, [$start, $end]);
    }

    /**
     * Filter by IN condition
     *
     * @param string $attribute
     * @param array<mixed> $values
     * @return self
     */
    public static function in(string $attribute, array $values): self
    {
        return new self(self::TYPE_IN, $attribute, $values);
    }

    /**
     * Order by descending
     *
     * @param string $attribute
     * @return self
     */
    public static function orderDesc(string $attribute = 'time'): self
    {
        return new self(self::TYPE_ORDER_DESC, $attribute);
    }

    /**
     * Order by ascending
     *
     * @param string $attribute
     * @return self
     */
    public static function orderAsc(string $attribute = 'time'): self
    {
        return new self(self::TYPE_ORDER_ASC, $attribute);
    }

    /**
     * Limit number of results
     *
     * @param int $limit
     * @return self
     */
    public static function limit(int $limit): self
    {
        return new self(self::TYPE_LIMIT, '', [$limit]);
    }

    /**
     * Offset results
     *
     * @param int $offset
     * @return self
     */
    public static function offset(int $offset): self
    {
        return new self(self::TYPE_OFFSET, '', [$offset]);
    }

    /**
     * Parse query from JSON string
     *
     * @param string $query
     * @return self
     * @throws \Exception
     */
    public static function parse(string $query): self
    {
        try {
            $query = \json_decode($query, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \Exception('Invalid query: ' . $e->getMessage());
        }

        if (!\is_array($query)) {
            throw new \Exception('Invalid query. Must be an array, got ' . \gettype($query));
        }

        return self::parseQuery($query);
    }

    /**
     * Parse an array of queries
     *
     * @param array<string> $queries
     * @return array<self>
     * @throws \Exception
     */
    public static function parseQueries(array $queries): array
    {
        $parsed = [];

        foreach ($queries as $query) {
            $parsed[] = self::parse($query);
        }

        return $parsed;
    }

    /**
     * Parse query from array
     *
     * @param array<string, mixed> $query
     * @return self
     * @throws \Exception
     */
    protected static function parseQuery(array $query): self
    {
        $method = $query['method'] ?? '';
        $attribute = $query['attribute'] ?? '';
        $values = $query['values'] ?? [];

        if (!\is_string($method)) {
            throw new \Exception('Invalid query method. Must be a string, got ' . \gettype($method));
        }

        if (!\is_string($attribute)) {
            throw new \Exception('Invalid query attribute. Must be a string, got ' . \gettype($attribute));
        }

        if (!\is_array($values)) {
            throw new \Exception('Invalid query values. Must be an array, got ' . \gettype($values));
        }

        return new self($method, $attribute, $values);
    }

    /**
     * Convert query to array
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $array = ['method' => $this->method];

        if (!empty($this->attribute)) {
            $array['attribute'] = $this->attribute;
        }

        $array['values'] = $this->values;

        return $array;
    }

    /**
     * Convert query to JSON string
     *
     * @return string
     * @throws \Exception
     */
    public function toString(): string
    {
        try {
            return \json_encode($this->toArray(), flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \Exception('Invalid Json: ' . $e->getMessage());
        }
    }
}
