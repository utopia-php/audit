<?php

namespace Utopia\Audit;

use Utopia\Database\Database;
use Utopia\Database\Document;

/**
 * Audit Log Manager
 *
 * This class manages audit logs using pluggable adapters.
 * The default adapter is the Database adapter which stores logs in utopia-php/database.
 * Custom adapters can be created by extending the Adapter abstract class.
 */
class Audit
{
    private Adapter $adapter;

    /**
     * Constructor.
     *
     * @param Adapter $adapter The adapter to use for storing audit logs
     */
    public function __construct(Adapter $adapter)
    {
        $this->adapter = $adapter;
    }

    /**
     * Get the current adapter.
     *
     * @return Adapter
     */
    public function getAdapter(): Adapter
    {
        return $this->adapter;
    }

    /**
     * Setup the audit log storage.
     *
     * @return void
     * @throws \Exception
     */
    public function setup(): void
    {
        $this->adapter->setup();
    }

    /**
     * Add event log.
     *
     * @param string|null $userId
     * @param string $event
     * @param string $resource
     * @param string $userAgent
     * @param string $ip
     * @param string $location
     * @param array<string, mixed> $data
     * @return Document
     *
     * @throws \Exception
     */
    public function log(?string $userId, string $event, string $resource, string $userAgent, string $ip, string $location, array $data = []): Document
    {
        return $this->adapter->create([
            'userId' => $userId,
            'event' => $event,
            'resource' => $resource,
            'userAgent' => $userAgent,
            'ip' => $ip,
            'location' => $location,
            'data' => $data,
        ]);
    }

    /**
     * Add multiple event logs in batch.
     *
     * @param array<array{userId: string|null, event: string, resource: string, userAgent: string, ip: string, location: string, timestamp: string, data?: array<string, mixed>}> $events
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function logBatch(array $events): array
    {
        return $this->adapter->createBatch($events);
    }

    /**
     * Get all logs by user ID.
     *
     * @param string $userId
     * @param array<mixed> $queries
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function getLogsByUser(
        string $userId,
        array $queries = []
    ): array {
        return $this->adapter->getByUser($userId, $queries);
    }

    /**
     * Count logs by user ID.
     *
     * @param string $userId
     * @param array<mixed> $queries
     * @return int
     * @throws \Exception
     */
    public function countLogsByUser(
        string $userId,
        array $queries = []
    ): int {
        return $this->adapter->countByUser($userId, $queries);
    }

    /**
     * Get all logs by resource.
     *
     * @param string $resource
     * @param array<mixed> $queries
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function getLogsByResource(
        string $resource,
        array $queries = [],
    ): array {
        return $this->adapter->getByResource($resource, $queries);
    }

    /**
     * Count logs by resource.
     *
     * @param string $resource
     * @param array<mixed> $queries
     * @return int
     *
     * @throws \Exception
     */
    public function countLogsByResource(
        string $resource,
        array $queries = []
    ): int {
        return $this->adapter->countByResource($resource, $queries);
    }

    /**
     * Get logs by user and events.
     *
     * @param string $userId
     * @param array<int, string> $events
     * @param array<mixed> $queries
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function getLogsByUserAndEvents(
        string $userId,
        array $events,
        array $queries = [],
    ): array {
        return $this->adapter->getByUserAndEvents($userId, $events, $queries);
    }

    /**
     * Count logs by user and events.
     *
     * @param string $userId
     * @param array<int, string> $events
     * @param array<mixed> $queries
     * @return int
     *
     * @throws \Exception
     */
    public function countLogsByUserAndEvents(
        string $userId,
        array $events,
        array $queries = [],
    ): int {
        return $this->adapter->countByUserAndEvents($userId, $events, $queries);
    }

    /**
     * Get logs by resource and events.
     *
     * @param string $resource
     * @param array<int, string> $events
     * @param array<mixed> $queries
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function getLogsByResourceAndEvents(
        string $resource,
        array $events,
        array $queries = [],
    ): array {
        return $this->adapter->getByResourceAndEvents($resource, $events, $queries);
    }

    /**
     * Count logs by resource and events.
     *
     * @param string $resource
     * @param array<int, string> $events
     * @param array<mixed> $queries
     * @return int
     *
     * @throws \Exception
     */
    public function countLogsByResourceAndEvents(
        string $resource,
        array $events,
        array $queries = [],
    ): int {
        return $this->adapter->countByResourceAndEvents($resource, $events, $queries);
    }

    /**
     * Delete all logs older than `$datetime` seconds
     *
     * @param string $datetime
     * @return bool
     *
     * @throws \Exception
     */
    public function cleanup(string $datetime): bool
    {
        return $this->adapter->cleanup($datetime);
    }
}
