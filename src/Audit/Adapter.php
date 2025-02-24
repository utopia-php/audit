<?php

namespace Utopia\Audit;

use Utopia\Database\Database;
use Utopia\Database\Document;
use Utopia\Database\Exception\Authorization as AuthorizationException;
use Utopia\Database\Exception\Duplicate as DuplicateException;
use Utopia\Database\Exception\Structure as StructureException;
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
    abstract public function getAttributes(): array;

    /**
     * Get collection indexes.
     *
     * @return array<array<string, mixed>>
     */
    abstract public function getIndexes(): array;

    /**
     * Get collection name.
     *
     * @return string
     */
    abstract public function getCollection(): string;

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
     * @param int|null $limit
     * @param int|null $offset
     * @param Document|null $orderAfter
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function getLogsByUser(
        string $userId,
        ?int $limit = null,
        ?int $offset = null,
        ?Document $orderAfter = null
    ): array {
        /** @var array<Document> $result */
        $result = Authorization::skip(function () use ($userId, $limit, $offset, $orderAfter) {
            /** @var array<Query> $queries */
            $queries = [];

            $queries[] = Query::equal('userId', [$userId]);
            $queries[] = Query::orderDesc('');

            if (!\is_null($limit)) {
                $queries[] = Query::limit($limit);
            }
            if (!\is_null($offset)) {
                $queries[] = Query::offset($offset);
            }
            if (!\is_null($orderAfter)) {
                $queries[] = Query::cursorAfter($orderAfter);
            }

            return $this->db->find(
                collection: $this->getCollection(),
                queries: $queries,
            );
        });

        return $result;
    }

    /**
     * Count logs by user ID.
     *
     * @param string $userId
     * @return int
     * @throws \Utopia\Database\Exception
     */
    public function countLogsByUser(string $userId): int
    {
        /** @var int $count */
        $count = Authorization::skip(function () use ($userId) {
            return $this->db->count(
                collection: $this->getCollection(),
                queries: [Query::equal('userId', [$userId])]
            );
        });

        return $count;
    }

    /**
     * Get all logs by resource.
     *
     * @param string $resource
     * @param int|null $limit
     * @param int|null $offset
     * @param Document|null $orderAfter
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function getLogsByResource(string $resource, ?int $limit = 25, ?int $offset = null, ?Document $orderAfter = null): array
    {
        /** @var array<Document> $result */
        $result = Authorization::skip(function () use ($resource, $limit, $offset, $orderAfter) {
            /** @var array<Query> $queries */
            $queries = [];

            $queries[] = Query::equal('resource', [$resource]);
            $queries[] = Query::orderDesc('');

            if (!\is_null($limit)) {
                $queries[] = Query::limit($limit);
            }
            if (!\is_null($offset)) {
                $queries[] = Query::offset($offset);
            }
            if (!\is_null($orderAfter)) {
                $queries[] = Query::cursorAfter($orderAfter);
            }

            return $this->db->find(
                collection: $this->getCollection(),
                queries: $queries,
            );
        });

        return $result;
    }

    /**
     * Count logs by resource.
     *
     * @param string $resource
     * @return int
     *
     * @throws \Exception
     */
    public function countLogsByResource(string $resource): int
    {
        /** @var int $count */
        $count = Authorization::skip(function () use ($resource) {
            return $this->db->count(
                collection: $this->getCollection(),
                queries: [Query::equal('resource', [$resource])]
            );
        });

        return $count;
    }

    /**
     * Get logs by user and events.
     *
     * @param string $userId
     * @param array<int,string> $events
     * @param int|null $limit
     * @param int|null $offset
     * @param Document|null $orderAfter
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function getLogsByUserAndEvents(string $userId, array $events, ?int $limit = null, ?int $offset = null, ?Document $orderAfter = null): array
    {
        /** @var array<Document> $result */
        $result = Authorization::skip(function () use ($userId, $events, $limit, $offset, $orderAfter) {
            /** @var array<Query> $queries */
            $queries = [];

            $queries[] = Query::equal('userId', [$userId]);
            $queries[] = Query::equal('event', $events);
            $queries[] = Query::orderDesc('');

            if (!\is_null($limit)) {
                $queries[] = Query::limit($limit);
            }
            if (!\is_null($offset)) {
                $queries[] = Query::offset($offset);
            }
            if (!\is_null($orderAfter)) {
                $queries[] = Query::cursorAfter($orderAfter);
            }

            return $this->db->find(
                collection: $this->getCollection(),
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
     * @return int
     *
     * @throws \Exception
     */
    public function countLogsByUserAndEvents(string $userId, array $events): int
    {
        /** @var int $count */
        $count = Authorization::skip(function () use ($userId, $events) {
            return $this->db->count(
                collection: $this->getCollection(),
                queries: [
                    Query::equal('userId', [$userId]),
                    Query::equal('event', $events),
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
     * @param int|null $limit
     * @param int|null $offset
     * @param Document|null $orderAfter
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function getLogsByResourceAndEvents(string $resource, array $events, ?int $limit = null, ?int $offset = null, ?Document $orderAfter = null): array
    {
        /** @var array<Document> $result */
        $result = Authorization::skip(function () use ($resource, $events, $limit, $offset, $orderAfter) {
            /** @var array<Query> $queries */
            $queries = [];

            $queries[] = Query::equal('resource', [$resource]);
            $queries[] = Query::equal('event', $events);
            $queries[] = Query::orderDesc('');

            if (!\is_null($limit)) {
                $queries[] = Query::limit($limit);
            }
            if (!\is_null($offset)) {
                $queries[] = Query::offset($offset);
            }
            if (!\is_null($orderAfter)) {
                $queries[] = Query::cursorAfter($orderAfter);
            }

            return $this->db->find(
                collection: $this->getCollection(),
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
     * @return int
     *
     * @throws \Exception
     */
    public function countLogsByResourceAndEvents(string $resource, array $events): int
    {
        /** @var int $count */
        $count = Authorization::skip(function () use ($resource, $events) {
            return $this->db->count(
                collection: $this->getCollection(),
                queries: [
                    Query::equal('resource', [$resource]),
                    Query::equal('event', $events),
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
     *
     * @throws AuthorizationException
     * @throws \Exception
     */
    public function cleanup(string $datetime): bool
    {
        Authorization::skip(function () use ($datetime) {
            $this->db->deleteDocuments(
                collection: $this->getCollection(),
                queries: [
                    Query::lessThan('time', $datetime),
                ]
            );
        });

        return true;
    }
}
