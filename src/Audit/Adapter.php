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
     *     timestamp: string,
     *     data?: array<string, mixed>
     * }> $logs
     * @return array<Log>
     *
     * @throws \Exception
     */
    abstract public function createBatch(array $logs): array;

    /**
     * Get logs by user ID.
     *
     * @param string $userId
     * @param array<mixed> $queries Additional query parameters
     * @return array<Log>
     *
     * @throws \Exception
     */
    abstract public function getByUser(string $userId, array $queries = []): array;

    /**
     * Count logs by user ID.
     *
     * @param string $userId
     * @param array<mixed> $queries Additional query parameters
     * @return int
     *
     * @throws \Exception
     */
    abstract public function countByUser(string $userId, array $queries = []): int;

    /**
     * Get logs by resource.
     *
     * @param string $resource
     * @param array<mixed> $queries Additional query parameters
     * @return array<Log>
     *
     * @throws \Exception
     */
    abstract public function getByResource(string $resource, array $queries = []): array;

    /**
     * Count logs by resource.
     *
     * @param string $resource
     * @param array<mixed> $queries Additional query parameters
     * @return int
     *
     * @throws \Exception
     */
    abstract public function countByResource(string $resource, array $queries = []): int;

    /**
     * Get logs by user and events.
     *
     * @param string $userId
     * @param array<int, string> $events
     * @param array<mixed> $queries Additional query parameters
     * @return array<Log>
     *
     * @throws \Exception
     */
    abstract public function getByUserAndEvents(string $userId, array $events, array $queries = []): array;

    /**
     * Count logs by user and events.
     *
     * @param string $userId
     * @param array<int, string> $events
     * @param array<mixed> $queries Additional query parameters
     * @return int
     *
     * @throws \Exception
     */
    abstract public function countByUserAndEvents(string $userId, array $events, array $queries = []): int;

    /**
     * Get logs by resource and events.
     *
     * @param string $resource
     * @param array<int, string> $events
     * @param array<mixed> $queries Additional query parameters
     * @return array<Log>
     *
     * @throws \Exception
     */
    abstract public function getByResourceAndEvents(string $resource, array $events, array $queries = []): array;

    /**
     * Count logs by resource and events.
     *
     * @param string $resource
     * @param array<int, string> $events
     * @param array<mixed> $queries Additional query parameters
     * @return int
     *
     * @throws \Exception
     */
    abstract public function countByResourceAndEvents(string $resource, array $events, array $queries = []): int;

    /**
     * Delete logs older than the specified datetime.
     *
     * @param string $datetime ISO 8601 datetime string
     * @return bool
     *
     * @throws \Exception
     */
    abstract public function cleanup(string $datetime): bool;
}
