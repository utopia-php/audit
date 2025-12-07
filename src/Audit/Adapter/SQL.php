<?php

namespace Utopia\Audit\Adapter;

use Utopia\Audit\Adapter;
use Utopia\Database\Database;
use Utopia\Database\Document;

/**
 * Base SQL Adapter for Audit
 *
 * This is an abstract base class for SQL-based adapters (Database, ClickHouse, etc.)
 * It provides common functionality and schema definitions for all SQL adapters.
 */
abstract class SQL extends Adapter
{
    public const COLLECTION = 'audit';

    /**
     * Get the collection/table name for audit logs.
     *
     * @return string
     */
    protected function getCollectionName(): string
    {
        return self::COLLECTION;
    }

    /**
     * Get attribute definitions for audit logs.
     *
     * Each attribute is an array with the following string keys:
     * - $id: string (attribute identifier)
     * - type: string
     * - size: int
     * - required: bool
     * - signed: bool
     * - array: bool
     * - filters: array<string>
     *
     * @return array<int, array<string, mixed>>
     */
    protected function getAttributes(): array
    {
        return [
            [
                '$id' => 'userId',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => false,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'event',
                'type' => Database::VAR_STRING,
                'size' => 255,
                'required' => true,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'resource',
                'type' => Database::VAR_STRING,
                'size' => 255,
                'required' => false,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'userAgent',
                'type' => Database::VAR_STRING,
                'size' => 65534,
                'required' => true,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'ip',
                'type' => Database::VAR_STRING,
                'size' => 45,
                'required' => true,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'location',
                'type' => Database::VAR_STRING,
                'size' => 45,
                'required' => false,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'time',
                'type' => Database::VAR_DATETIME,
                'format' => '',
                'size' => 0,
                'signed' => true,
                'required' => false,
                'array' => false,
                'filters' => ['datetime'],
            ],
            [
                '$id' => 'data',
                'type' => Database::VAR_STRING,
                'size' => 16777216,
                'required' => false,
                'signed' => true,
                'array' => false,
                'filters' => ['json'],
            ],
        ];
    }

    /**
     * Get attribute documents for audit logs.
     *
     * @return array<Document>
     */
    protected function getAttributeDocuments(): array
    {
        return array_map(static fn (array $attribute) => new Document($attribute), $this->getAttributes());
    }

    /**
     * Get index definitions for audit logs.
     *
     * Each index is an array with the following string keys:
     * - $id: string (index identifier)
     * - type: string
     * - attributes: array<string>
     *
     * @return array<int, array<string, mixed>>
     */
    protected function getIndexes(): array
    {
        return [
            [
                '$id' => 'idx_event',
                'type' => 'key',
                'attributes' => ['event'],
            ],
            [
                '$id' => 'idx_userId_event',
                'type' => 'key',
                'attributes' => ['userId', 'event'],
            ],
            [
                '$id' => 'idx_resource_event',
                'type' => 'key',
                'attributes' => ['resource', 'event'],
            ],
            [
                '$id' => 'idx_time_desc',
                'type' => 'key',
                'attributes' => ['time'],
            ],
        ];
    }

    /**
     * Get index documents for audit logs.
     *
     * @return array<Document>
     */
    protected function getIndexDocuments(): array
    {
        return array_map(static fn (array $index) => new Document($index), $this->getIndexes());
    }

    /**
     * Get a single attribute by ID.
     *
     * @param string $id
     * @return array<string, mixed>|null
     */
    protected function getAttribute(string $id)
    {
        foreach ($this->getAttributes() as $attribute) {
            if ($attribute['$id'] === $id) {
                return $attribute;
            }
        }

        return null;
    }

    /**
     * Get SQL column definition for a given attribute ID.
     *
     * @param string $id
     * @return string
     */
    protected function getColumnDefinition(string $id): string
    {
        $attribute = $this->getAttribute($id);

        if (! $attribute) {
            throw new \Exception("Attribute {$id} not found");
        }

        $type = match ($id) {
            'userId', 'event', 'resource', 'userAgent', 'ip', 'location', 'data' => 'String',
            'time' => 'DateTime64(3)',
            default => 'String',
        };

        $nullable = ! $attribute['required'] ? 'Nullable(' . $type . ')' : $type;

        return "{$id} {$nullable}";
    }

    /**
     * Get all SQL column definitions.
     *
     * @return array<string>
     */
    protected function getAllColumnDefinitions(): array
    {
        $definitions = [];
        foreach ($this->getAttributes() as $attribute) {
            /** @var string $id */
            $id = $attribute['$id'];
            $definitions[] = $this->getColumnDefinition($id);
        }

        return $definitions;
    }
}
