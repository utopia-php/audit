<?php

namespace Utopia\Audit;

/**
 * Abstract Adapter class for Audit implementations
 *
 * This class provides a base interface for different audit storage adapters.
 * Different implementations can store audit logs to various backends like
 * databases, files, external services, etc.
 */
abstract class Adapter
{
    /**
     * Get the name of the adapter.
     */
    abstract public function getName(): string;

    /**
     * Setup the adapter (create required tables/collections, indexes, etc.)
     *
     * @return void
     * @throws \Exception
     */
    abstract public function setup(): void;

    /**
     * Get a single log by its ID.
     *
     * @param string $id
     * @return Log|null The log entry or null if not found
     *
     * @throws \Exception
     */
    abstract public function getById(string $id): ?Log;

    /**
     * Create an audit log entry.
     *
     * @param array{
     *     userId?: string|null,
     *     event: string,
     *     resource: string,
     *     userAgent: string,
     *     ip: string,
     *     location?: string,
     *     data?: array<string, mixed>
     * } $log
     * @return Log The created log entry
     *
     * @throws \Exception
     */
    abstract public function create(array $log): Log;

    /**
     * Create multiple audit log entries in batch.
     *
     * @param array<array{
     *     userId?: string|null,
     *     event: string,
     *     resource: string,
     *     userAgent: string,
     *     ip: string,
     *     location?: string,
     *     time: \DateTime|string|null,
     *     data?: array<string, mixed>
     * }> $logs
     * @return bool
     *
     * @throws \Exception
     */
    abstract public function createBatch(array $logs): bool;

    /**
     * Get logs by user ID.
     *
     * @param string $userId
     * @return array<Log>
     *
     * @throws \Exception
     */
    abstract public function getByUser(
        string $userId,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
        int $limit = 25,
        int $offset = 0,
        bool $ascending = false,
    ): array;

    /**
     * Count logs by user ID.
     *
     * @param string $userId
     * @return int
     *
     * @throws \Exception
     */
    abstract public function countByUser(
        string $userId,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
    ): int;

    /**
     * Get logs by resource.
     *
     * @param string $resource
     * @return array<Log>
     *
     * @throws \Exception
     */
    abstract public function getByResource(
        string $resource,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
        int $limit = 25,
        int $offset = 0,
        bool $ascending = false,
    ): array;

    /**
     * Count logs by resource.
     *
     * @param string $resource
     * @return int
     *
     * @throws \Exception
     */
    abstract public function countByResource(
        string $resource,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
    ): int;

    /**
     * Get logs by user and events.
     *
     * @param string $userId
     * @param array<int, string> $events
     * @return array<Log>
     *
     * @throws \Exception
     */
    abstract public function getByUserAndEvents(
        string $userId,
        array $events,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
        int $limit = 25,
        int $offset = 0,
        bool $ascending = false,
    ): array;

    /**
     * Count logs by user and events.
     *
     * @param string $userId
     * @param array<int, string> $events
     * @return int
     *
     * @throws \Exception
     */
    abstract public function countByUserAndEvents(
        string $userId,
        array $events,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
    ): int;

    /**
     * Get logs by resource and events.
     *
     * @param string $resource
     * @param array<int, string> $events
     * @return array<Log>
     *
     * @throws \Exception
     */
    abstract public function getByResourceAndEvents(
        string $resource,
        array $events,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
        int $limit = 25,
        int $offset = 0,
        bool $ascending = false,
    ): array;

    /**
     * Count logs by resource and events.
     *
     * @param string $resource
     * @param array<int, string> $events
     * @return int
     *
     * @throws \Exception
     */
    abstract public function countByResourceAndEvents(
        string $resource,
        array $events,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
    ): int;

    /**
     * Delete logs older than the specified datetime.
     *
     * @param \DateTime $datetime
     * @return bool
     *
     * @throws \Exception
     */
    abstract public function cleanup(\DateTime $datetime): bool;

    /**
     * Find logs using custom queries.
     *
     * @param array<\Utopia\Audit\Query> $queries
     * @return array<Log>
     *
     * @throws \Exception
     */
    abstract public function find(array $queries = []): array;

    /**
     * Count logs using custom queries.
     *
     * @param array<\Utopia\Audit\Query> $queries
     * @return int
     *
     * @throws \Exception
     */
    abstract public function count(array $queries = []): int;
}
