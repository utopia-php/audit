<?php

namespace Utopia\Audit;

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
     * @return Log
     *
     * @throws \Exception
     */
    public function log(?string $userId, string $event, string $resource, string $userAgent, string $ip, string $location, array $data = []): Log
    {
        /** @var array{userId?: string|null, event: string, resource: string, userAgent: string, ip: string, location?: string, data?: array<string, mixed>} $log */
        $log = [
            'userId' => $userId,
            'event' => $event,
            'resource' => $resource,
            'userAgent' => $userAgent,
            'ip' => $ip,
            'location' => $location,
            'data' => $data,
        ];

        return $this->adapter->create($log);
    }

    /**
     * Add multiple event logs in batch.
     *
     * @param array<array{userId: string|null, event: string, resource: string, userAgent: string, ip: string, location: string, time: string, data?: array<string, mixed>}> $events
     * @param array<string, mixed> $defaultAttributes
     * @return bool
     *
     * @throws \Exception
     */
    public function logBatch(array $events, array $defaultAttributes = []): bool
    {
        /** @var array<array{userId?: string|null, event: string, resource: string, userAgent: string, ip: string, location?: string, time: \DateTime|string|null, data?: array<string, mixed>}> $eventsWithDefaults */
        $eventsWithDefaults = array_map(static fn (array $event) => array_merge($defaultAttributes, $event), $events);

        return $this->adapter->createBatch($eventsWithDefaults);
    }

    /**
     * Get a single log by its ID.
     *
     * @param string $id
     * @return Log|null The log entry or null if not found
     *
     * @throws \Exception
     */
    public function getLogById(string $id): ?Log
    {
        return $this->adapter->getById($id);
    }

    /**
     * Get all logs by user ID.
     *
     * @param string $userId
     * @return array<Log>
     *
     * @throws \Exception
     */
    public function getLogsByUser(
        string $userId,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
        int $limit = 25,
        int $offset = 0,
        bool $ascending = false,
    ): array {
        return $this->adapter->getByUser($userId, $after, $before, $limit, $offset, $ascending);
    }

    /**
     * Count logs by user ID.
     *
     * @param string $userId
     * @return int
     * @throws \Exception
     */
    public function countLogsByUser(
        string $userId,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
    ): int {
        return $this->adapter->countByUser($userId, $after, $before);
    }

    /**
     * Get all logs by resource.
     *
     * @param string $resource
     * @return array<Log>
     *
     * @throws \Exception
     */
    public function getLogsByResource(
        string $resource,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
        int $limit = 25,
        int $offset = 0,
        bool $ascending = false,
    ): array {
        return $this->adapter->getByResource($resource, $after, $before, $limit, $offset, $ascending);
    }

    /**
     * Count logs by resource.
     *
     * @param string $resource
     * @return int
     *
     * @throws \Exception
     */
    public function countLogsByResource(
        string $resource,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
    ): int {
        return $this->adapter->countByResource($resource, $after, $before);
    }

    /**
     * Get logs by user and events.
     *
     * @param string $userId
     * @param array<int, string> $events
     * @return array<Log>
     *
     * @throws \Exception
     */
    public function getLogsByUserAndEvents(
        string $userId,
        array $events,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
        int $limit = 25,
        int $offset = 0,
        bool $ascending = false,
    ): array {
        return $this->adapter->getByUserAndEvents($userId, $events, $after, $before, $limit, $offset, $ascending);
    }

    /**
     * Count logs by user and events.
     *
     * @param string $userId
     * @param array<int, string> $events
     * @return int
     *
     * @throws \Exception
     */
    public function countLogsByUserAndEvents(
        string $userId,
        array $events,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
    ): int {
        return $this->adapter->countByUserAndEvents($userId, $events, $after, $before);
    }

    /**
     * Get logs by resource and events.
     *
     * @param string $resource
     * @param array<int, string> $events
     * @return array<Log>
     *
     * @throws \Exception
     */
    public function getLogsByResourceAndEvents(
        string $resource,
        array $events,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
        int $limit = 25,
        int $offset = 0,
        bool $ascending = false,
    ): array {
        return $this->adapter->getByResourceAndEvents($resource, $events, $after, $before, $limit, $offset, $ascending);
    }

    /**
     * Count logs by resource and events.
     *
     * @param string $resource
     * @param array<int, string> $events
     * @return int
     *
     * @throws \Exception
     */
    public function countLogsByResourceAndEvents(
        string $resource,
        array $events,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
    ): int {
        return $this->adapter->countByResourceAndEvents($resource, $events, $after, $before);
    }

    /**
     * Delete all logs older than the specified datetime
     *
     * @param \DateTime $datetime
     * @return bool
     *
     * @throws \Exception
     */
    public function cleanup(\DateTime $datetime): bool
    {
        return $this->adapter->cleanup($datetime);
    }

    /**
     * Find logs using custom queries.
     *
     * @param array<Query> $queries Array of Audit Query objects
     * @return array<Log>
     *
     * @throws \Exception
     */
    public function find(array $queries = []): array
    {
        return $this->adapter->find($queries);
    }

    /**
     * Count logs using custom queries.
     *
     * @param array<Query> $queries Array of Audit Query objects
     * @return int
     *
     * @throws \Exception
     */
    public function count(array $queries = []): int
    {
        return $this->adapter->count($queries);
    }
}
