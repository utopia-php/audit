<?php

namespace Utopia\Audit\Adapter;

use Utopia\Database\Database as DatabaseClient;
use Utopia\Database\DateTime;
use Utopia\Database\Document;
use Utopia\Database\Exception\Authorization as AuthorizationException;
use Utopia\Database\Exception\Duplicate as DuplicateException;
use Utopia\Database\Exception\Timeout;
use Utopia\Database\Query;
use Utopia\Exception;

/**
 * Database Adapter for Audit
 *
 * This adapter stores audit logs in a Utopia Database collection.
 */
class Database extends SQL
{
    private \Utopia\Database\Database $db;

    public function __construct(DatabaseClient $db)
    {
        $this->db = $db;
    }

    /**
     * Get adapter name.
     */
    public function getName(): string
    {
        return 'Database';
    }

    /**
     * Setup database structure.
     *
     * @return void
     * @throws Exception|\Exception
     */
    public function setup(): void
    {
        if (! $this->db->exists($this->db->getDatabase())) {
            throw new Exception('You need to create the database before running Audit setup');
        }

        $attributes = $this->getAttributeDocuments();
        $indexes = $this->getIndexDocuments();

        try {
            $this->db->createCollection(
                $this->getCollectionName(),
                $attributes,
                $indexes
            );
        } catch (DuplicateException) {
            // Collection already exists
        }
    }

    /**
     * Create an audit log entry.
     *
     * @param array<string, mixed> $log
     * @return Document
     * @throws AuthorizationException|\Exception
     */
    public function create(array $log): Document
    {
        return $this->db->getAuthorization()->skip(function () use ($log) {
            return $this->db->createDocument($this->getCollectionName(), new Document([
                '$permissions' => [],
                'userId' => $log['userId'] ?? null,
                'event' => $log['event'],
                'resource' => $log['resource'],
                'userAgent' => $log['userAgent'],
                'ip' => $log['ip'],
                'location' => $log['location'] ?? null,
                'data' => $log['data'] ?? [],
                'time' => DateTime::now(),
            ]));
        });
    }

    /**
     * Create multiple audit log entries in batch.
     *
     * @param array<int, array<string, mixed>> $logs
     * @return array<Document>
     * @throws AuthorizationException|\Exception
     */
    public function createBatch(array $logs): array
    {
        $created = [];
        $this->db->getAuthorization()->skip(function () use ($logs, &$created) {
            foreach ($logs as $log) {
                $created[] = $this->db->createDocument($this->getCollectionName(), new Document([
                    '$permissions' => [],
                    'userId' => $log['userId'] ?? null,
                    'event' => $log['event'],
                    'resource' => $log['resource'],
                    'userAgent' => $log['userAgent'],
                    'ip' => $log['ip'],
                    'location' => $log['location'] ?? null,
                    'data' => $log['data'] ?? [],
                    'time' => $log['timestamp'],
                ]));
            }
        });

        return $created;
    }

    /**
     * Get audit logs by user ID.
     *
     * @param array<int, Query> $queries
     * @return array<Document>
     * @throws AuthorizationException|\Exception
     */
    public function getByUser(string $userId, array $queries = []): array
    {
        return $this->db->getAuthorization()->skip(function () use ($userId, $queries) {
            $queries[] = Query::equal('userId', [$userId]);
            $queries[] = Query::orderDesc();

            return $this->db->find(
                collection: $this->getCollectionName(),
                queries: $queries,
            );
        });
    }

    /**
     * Count audit logs by user ID.
     *
     * @param array<int, Query> $queries
     * @throws AuthorizationException|\Exception
     */
    public function countByUser(string $userId, array $queries = []): int
    {
        return $this->db->getAuthorization()->skip(function () use ($userId, $queries) {
            return $this->db->count(
                collection: $this->getCollectionName(),
                queries: [
                    Query::equal('userId', [$userId]),
                    ...$queries,
                ]
            );
        });
    }

    /**
     * Get logs by resource.
     *
     * @param string $resource
     * @param array<int, Query> $queries
     * @return array<Document>
     * @throws Timeout|\Utopia\Database\Exception|\Utopia\Database\Exception\Query
     */
    public function getByResource(string $resource, array $queries = []): array
    {
        return $this->db->getAuthorization()->skip(function () use ($resource, $queries) {
            $queries[] = Query::equal('resource', [$resource]);
            $queries[] = Query::orderDesc();

            return $this->db->find(
                collection: $this->getCollectionName(),
                queries: $queries,
            );
        });
    }

    /**
     * Count logs by resource.
     *
     * @param string $resource
     * @param array<int, Query> $queries
     * @return int
     * @throws \Utopia\Database\Exception
     */
    public function countByResource(string $resource, array $queries = []): int
    {
        return $this->db->getAuthorization()->skip(function () use ($resource, $queries) {
            return $this->db->count(
                collection: $this->getCollectionName(),
                queries: [
                    Query::equal('resource', [$resource]),
                    ...$queries,
                ]
            );
        });
    }

    /**
     * Get logs by user and events.
     *
     * @param string $userId
     * @param array<int, string> $events
     * @param array<int, Query> $queries
     * @return array<Document>
     * @throws Timeout|\Utopia\Database\Exception|\Utopia\Database\Exception\Query
     */
    public function getByUserAndEvents(string $userId, array $events, array $queries = []): array
    {
        return $this->db->getAuthorization()->skip(function () use ($userId, $events, $queries) {
            $queries[] = Query::equal('userId', [$userId]);
            $queries[] = Query::equal('event', $events);
            $queries[] = Query::orderDesc();

            return $this->db->find(
                collection: $this->getCollectionName(),
                queries: $queries,
            );
        });
    }

    /**
     * Count logs by user and events.
     *
     * @param string $userId
     * @param array<int, string> $events
     * @param array<int, Query> $queries
     * @return int
     * @throws \Utopia\Database\Exception
     */
    public function countByUserAndEvents(string $userId, array $events, array $queries = []): int
    {
        return $this->db->getAuthorization()->skip(function () use ($userId, $events, $queries) {
            return $this->db->count(
                collection: $this->getCollectionName(),
                queries: [
                    Query::equal('userId', [$userId]),
                    Query::equal('event', $events),
                    ...$queries,
                ]
            );
        });
    }

    /**
     * Get logs by resource and events.
     *
     * @param string $resource
     * @param array<int, string> $events
     * @param array<int, Query> $queries
     * @return array<Document>
     * @throws Timeout|\Utopia\Database\Exception|\Utopia\Database\Exception\Query
     */
    public function getByResourceAndEvents(string $resource, array $events, array $queries = []): array
    {
        return $this->db->getAuthorization()->skip(function () use ($resource, $events, $queries) {
            $queries[] = Query::equal('resource', [$resource]);
            $queries[] = Query::equal('event', $events);
            $queries[] = Query::orderDesc();

            return $this->db->find(
                collection: $this->getCollectionName(),
                queries: $queries,
            );
        });
    }

    /**
     * Count logs by resource and events.
     *
     * @param string $resource
     * @param array<int, string> $events
     * @param array<int, Query> $queries
     * @return int
     * @throws \Utopia\Database\Exception
     */
    public function countByResourceAndEvents(string $resource, array $events, array $queries = []): int
    {
        return $this->db->getAuthorization()->skip(function () use ($resource, $events, $queries) {
            return $this->db->count(
                collection: $this->getCollectionName(),
                queries: [
                    Query::equal('resource', [$resource]),
                    Query::equal('event', $events),
                    ...$queries,
                ]
            );
        });
    }

    /**
     * Delete logs older than the specified datetime.
     *
     * @param string $datetime
     * @return bool
     * @throws AuthorizationException|\Exception
     */
    public function cleanup(string $datetime): bool
    {
        $this->db->getAuthorization()->skip(function () use ($datetime) {
            do {
                $documents = $this->db->find(
                    collection: $this->getCollectionName(),
                    queries: [
                        Query::lessThan('time', $datetime),
                    ]
                );

                foreach ($documents as $document) {
                    $this->db->deleteDocument($this->getCollectionName(), $document->getId());
                }
            } while (! empty($documents));
        });

        return true;
    }

    /**
     * Get database-agnostic column definition for a given attribute ID.
     *
     * For the Database adapter, this method is not actively used since the adapter
     * delegates to utopia-php/database's native Document/Collection API which handles
     * type mapping internally. However, this implementation is required to satisfy
     * the abstract method declaration in the base SQL adapter.
     *
     * @param string $id Attribute identifier
     * @return string Database-agnostic column description
     * @throws Exception
     */
    protected function getColumnDefinition(string $id): string
    {
        $attribute = $this->getAttribute($id);

        if (!$attribute) {
            throw new Exception("Attribute {$id} not found");
        }

        // For the Database adapter, we use Utopia's VAR_* type constants internally
        // This method provides a description for reference purposes
        /** @var string $type */
        $type = $attribute['type'];
        /** @var int $size */
        $size = $attribute['size'] ?? 0;

        if ($size > 0) {
            return "{$id}: {$type}({$size})";
        }

        return "{$id}: {$type}";
    }
}
