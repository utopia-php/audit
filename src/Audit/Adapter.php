<?php

namespace Utopia\Audit;

use Utopia\Database\Database;
use Utopia\Database\Document;
use Utopia\Database\Exception as DatabaseException;
use Utopia\Database\Exception\Authorization as AuthorizationException;
use Utopia\Database\Exception\Duplicate as DuplicateException;
use Utopia\Database\Exception\Restricted as RestrictedException;
use Utopia\Database\Exception\Structure as StructureException;
use Utopia\Database\Exception\Timeout as TimeoutException;
use Utopia\Database\Exception\Query as QueryException;
use Utopia\Database\Query;
use Utopia\Database\Validator\Authorization;
use Utopia\Exception;

abstract class Adapter
{
    protected Database $db;

    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    /**
     * Setup database structure.
     *
     * @return void
     *
     * @throws DuplicateException
     * @throws \Exception
     */
    public function setup(): void
    {
        if (!$this->db->exists($this->db->getDatabase())) {
            throw new Exception('You need to create the database before running Audit setup');
        }

        $attributes = \array_map(fn ($attribute) => new Document($attribute), $this->getAttributes());
        $indexes = \array_map(fn ($index) => new Document($index), $this->getIndexes());

        try {
            $this->db->createCollection(
                $this->getCollection(),
                $attributes,
                $indexes
            );
        } catch (DuplicateException) {
            // Collection already exists
        }
    }

    /**
     * Get collection attributes.
     *
     * @return array<array<string, mixed>>
     */
    abstract public static function getAttributes(): array;

    /**
     * Get collection indexes.
     *
     * @return array<array<string, mixed>>
     */
    abstract public static function getIndexes(): array;

    /**
     * Get collection name.
     *
     * @return string
     */
    abstract public static function getCollection(): string;

    /**
     * Add event log.
     *
     * @param Log $log
     * @return bool
     *
     * @throws AuthorizationException
     * @throws StructureException
     * @throws \Exception
     * @throws \Throwable
     */
    public function log(Log $log): bool
    {
        Authorization::skip(function () use ($log) {
            $this->db->createDocument(
                $this->getCollection(),
                new Document($this->filter($log)->getArrayCopy())
            );
        });

        return true;
    }

    /**
     * Override to filter log before saving.
     *
     * @param Log $log
     * @return Log
     */
    public function filter(Log $log): Log
    {
        return $log;
    }

    /**
     * Add multiple event logs in batch.
     *
     * @param array<Log> $logs
     * @return bool
     *
     * @throws AuthorizationException
     * @throws StructureException
     * @throws \Exception
     * @throws \Throwable
     */
    public function logBatch(array $logs): bool
    {
        Authorization::skip(function () use ($logs) {
            $documents = \array_map(
                fn ($log) => new Document($this->filter($log)->getArrayCopy()),
                $logs
            );

            $this->db->createDocuments(
                $this->getCollection(),
                $documents
            );
        });

        return true;
    }

    /**
     * Get all logs by user ID.
     *
     * @param string $userId
     * @param array<Query> $queries
     * @return array<Document>
     *
     * @throws TimeoutException
     * @throws DatabaseException
     * @throws QueryException
     */
    public function getLogsByUser(
        string $userId,
        array $queries = []
    ): array {
        /** @var array<Document> $result */
        $result = Authorization::skip(function () use ($queries, $userId) {
            $queries[] = Query::equal('userId', [$userId]);
            $queries[] = Query::orderDesc();

            return $this->db->find(
                collection: static::getCollection(),
                queries: $queries,
            );
        });

        return $result;
    }

    /**
     * Count logs by user ID.
     *
     * @param string $userId
     * @param array<Query> $queries
     * @return int
     * @throws DatabaseException
     */
    public function countLogsByUser(
        string $userId,
        array $queries = []
    ): int {
        /** @var int $count */
        $count = Authorization::skip(function () use ($queries, $userId) {
            return $this->db->count(
                collection: static::getCollection(),
                queries: [
                    Query::equal('userId', [$userId]),
                    ...$queries,
                ]
            );
        });

        return $count;
    }

    /**
     * Get all logs by resource.
     *
     * @param string $resource
     * @param array<Query> $queries
     * @return array<Document>
     *
     * @throws TimeoutException
     * @throws DatabaseException
     * @throws QueryException
     */
    public function getLogsByResource(
        string $resource,
        array $queries = [],
    ): array {
        /** @var array<Document> $result */
        $result = Authorization::skip(function () use ($queries, $resource) {
            $queries[] = Query::equal('resource', [$resource]);
            $queries[] = Query::orderDesc();

            return $this->db->find(
                collection: static::getCollection(),
                queries: $queries,
            );
        });

        return $result;
    }

    /**
     * Count logs by resource.
     *
     * @param string $resource
     * @param array<Query> $queries
     * @return int
     *
     * @throws DatabaseException
     */
    public function countLogsByResource(
        string $resource,
        array $queries = []
    ): int {
        /** @var int $count */
        $count = Authorization::skip(function () use ($resource, $queries) {
            return $this->db->count(
                collection: static::getCollection(),
                queries: [
                    Query::equal('resource', [$resource]),
                    ...$queries,
                ]
            );
        });

        return $count;
    }

    /**
     * Get logs by user and events.
     *
     * @param string $userId
     * @param array<int,string> $events
     * @param array<Query> $queries
     * @return array<Document>
     *
     * @throws TimeoutException
     * @throws DatabaseException
     * @throws QueryException
     */
    public function getLogsByUserAndEvents(
        string $userId,
        array $events,
        array $queries = [],
    ): array {
        /** @var array<Document> $result */
        $result = Authorization::skip(function () use ($userId, $events, $queries) {
            $queries[] = Query::equal('userId', [$userId]);
            $queries[] = Query::equal('event', $events);
            $queries[] = Query::orderDesc();

            return $this->db->find(
                collection: static::getCollection(),
                queries: $queries,
            );
        });

        return $result;
    }

    /**
     * Count logs by user and events.
     *
     * @param string $userId
     * @param array<int,string> $events
     * @param array<Query> $queries
     * @return int
     *
     * @throws DatabaseException
     */
    public function countLogsByUserAndEvents(
        string $userId,
        array $events,
        array $queries = [],
    ): int {
        /** @var int $count */
        $count = Authorization::skip(function () use ($userId, $events, $queries) {
            return $this->db->count(
                collection: static::getCollection(),
                queries: [
                    Query::equal('userId', [$userId]),
                    Query::equal('event', $events),
                    ...$queries,
                ]
            );
        });

        return $count;
    }

    /**
     * Get logs by resource and events.
     *
     * @param string $resource
     * @param array<int,string> $events
     * @param array<Query> $queries
     * @return array<Document>
     *
     * @throws TimeoutException
     * @throws DatabaseException
     * @throws QueryException
     */
    public function getLogsByResourceAndEvents(
        string $resource,
        array $events,
        array $queries = [],
    ): array {
        /** @var array<Document> $result */
        $result = Authorization::skip(function () use ($resource, $events, $queries) {
            $queries[] = Query::equal('resource', [$resource]);
            $queries[] = Query::equal('event', $events);
            $queries[] = Query::orderDesc();

            return $this->db->find(
                collection: static::getCollection(),
                queries: $queries,
            );
        });

        return $result;
    }

    /**
     * Count logs by resource and events.
     *
     * @param string $resource
     * @param array<int,string> $events
     * @param array<Query> $queries
     * @return int
     *
     * @throws DatabaseException
     */
    public function countLogsByResourceAndEvents(
        string $resource,
        array $events,
        array $queries = [],
    ): int {
        /** @var int $count */
        $count = Authorization::skip(function () use ($resource, $events, $queries) {
            return $this->db->count(
                collection: static::getCollection(),
                queries: [
                    Query::equal('resource', [$resource]),
                    Query::equal('event', $events),
                    ...$queries,
                ]
            );
        });

        return $count;
    }

    /**
     * Delete all logs older than `$timestamp` seconds
     *
     * @param string $datetime
     * @return bool
     * @throws AuthorizationException
     * @throws RestrictedException
     * @throws DatabaseException
     * @throws \Throwable
     */
    public function cleanup(string $datetime): bool
    {
        Authorization::skip(function () use ($datetime) {
            $this->db->deleteDocuments(
                collection: $this->getCollection(),
                queries: [
                    Query::lessThan('time', $datetime),
                    Query::orderDesc('time'),
                    Query::orderDesc(),
                ]
            );
        });

        return true;
    }
}
