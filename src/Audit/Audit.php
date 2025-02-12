<?php

namespace Utopia\Audit;

use Utopia\Database\Database;
use Utopia\Database\DateTime;
use Utopia\Database\Document;
use Utopia\Database\Exception\Authorization as AuthorizationException;
use Utopia\Database\Exception\Duplicate as DuplicateException;
use Utopia\Database\Exception\Structure as StructureException;
use Utopia\Database\Query;
use Utopia\Database\Validator\Authorization;
use Utopia\Exception;

class Audit
{
    public const COLLECTION = 'audit';

    public const ATTRIBUTES = [
        [
            '$id' => 'userId',
            'type' => Database::VAR_STRING,
            'size' => Database::LENGTH_KEY,
            'required' => true,
            'signed' => true,
            'array' => false,
            'filters' => [],
        ], [
            '$id' => 'event',
            'type' => Database::VAR_STRING,
            'size' => 255,
            'required' => true,
            'signed' => true,
            'array' => false,
            'filters' => [],
        ], [
            '$id' => 'resource',
            'type' => Database::VAR_STRING,
            'size' => 255,
            'required' => false,
            'signed' => true,
            'array' => false,
            'filters' => [],
        ], [
            '$id' => 'userAgent',
            'type' => Database::VAR_STRING,
            'size' => 65534,
            'required' => true,
            'signed' => true,
            'array' => false,
            'filters' => [],
        ], [
            '$id' => 'ip',
            'type' => Database::VAR_STRING,
            'size' => 45,
            'required' => true,
            'signed' => true,
            'array' => false,
            'filters' => [],
        ], [
            '$id' => 'location',
            'type' => Database::VAR_STRING,
            'size' => 45,
            'required' => false,
            'signed' => true,
            'array' => false,
            'filters' => [],
        ], [
            '$id' => 'time',
            'type' => Database::VAR_DATETIME,
            'format' => '',
            'size' => 0,
            'signed' => true,
            'required' => false,
            'array' => false,
            'filters' => ['datetime'],
        ], [
            '$id' => 'data',
            'type' => Database::VAR_STRING,
            'size' => 16777216,
            'required' => false,
            'signed' => true,
            'array' => false,
            'filters' => ['json'],
        ],
    ];

    public const INDEXES = [
        [
            '$id' => 'index2',
            'type' => Database::INDEX_KEY,
            'attributes' => ['event'],
            'lengths' => [],
            'orders' => [],
        ], [
            '$id' => 'index4',
            'type' => Database::INDEX_KEY,
            'attributes' => ['userId', 'event'],
            'lengths' => [],
            'orders' => [],
        ], [
            '$id' => 'index5',
            'type' => Database::INDEX_KEY,
            'attributes' => ['resource', 'event'],
            'lengths' => [],
            'orders' => [],
        ], [
            '$id' => 'index-time',
            'type' => Database::INDEX_KEY,
            'attributes' => ['time'],
            'lengths' => [],
            'orders' => [Database::ORDER_DESC],
        ],
    ];

    private Database $db;

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
        if (! $this->db->exists($this->db->getDatabase())) {
            throw new Exception('You need to create the database before running Audit setup');
        }

        $attributes = \array_map(function ($attribute) {
            return new Document($attribute);
        }, self::ATTRIBUTES);

        $indexes = \array_map(function ($index) {
            return new Document($index);
        }, self::INDEXES);

        try {
            $this->db->createCollection(
                Audit::COLLECTION,
                $attributes,
                $indexes
            );
        } catch (DuplicateException) {
            // Collection already exists
        }
    }

    /**
     * Add event log.
     *
     * @param  string  $userId
     * @param  string  $event
     * @param  string  $resource
     * @param  string  $userAgent
     * @param  string  $ip
     * @param  string  $location
     * @param  array<string,mixed>  $data
     * @return bool
     *
     * @throws AuthorizationException
     * @throws StructureException
     * @throws \Exception
     * @throws \Throwable
     */
    public function log(string $userId, string $event, string $resource, string $userAgent, string $ip, string $location, array $data = []): bool
    {
        Authorization::skip(function () use ($userId, $event, $resource, $userAgent, $ip, $location, $data) {
            $this->db->createDocument(Audit::COLLECTION, new Document([
                '$permissions' => [],
                'userId' => $userId,
                'event' => $event,
                'resource' => $resource,
                'userAgent' => $userAgent,
                'ip' => $ip,
                'location' => $location,
                'data' => $data,
                'time' => DateTime::now(),
            ]));
        });

        return true;
    }

    /**
     * Get all logs by user ID.
     *
     * @param  string  $userId
     * @param  int|null  $limit
     * @param  int|null  $offset
     * @param  Document|null  $orderAfter
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function getLogsByUser(string $userId, ?int $limit = null, ?int $offset = null, ?Document $orderAfter = null): array
    {
        /** @var array<Document> $result */
        $result = Authorization::skip(function () use ($userId, $limit, $offset, $orderAfter) {
            $queries[] = Query::equal('userId', [$userId]);
            $queries[] = Query::orderDesc('');

            if (! \is_null($limit)) {
                $queries[] = Query::limit($limit);
            }
            if (! \is_null($offset)) {
                $queries[] = Query::offset($offset);
            }
            if (! \is_null($orderAfter)) {
                $queries[] = Query::cursorAfter($orderAfter);
            }

            return $this->db->find(
                collection: Audit::COLLECTION,
                queries: $queries,
            );
        });

        return $result;
    }

    /**
     * Count logs by user ID.
     *
     * @param  string  $userId
     * @return int
     */
    public function countLogsByUser(string $userId): int
    {
        /** @var int $count */
        $count = Authorization::skip(function () use ($userId) {
            return $this->db->count(
                collection: Audit::COLLECTION,
                queries: [Query::equal('userId', [$userId])]
            );
        });

        return $count;
    }

    /**
     * Get all logs by resource.
     *
     * @param  string  $resource
     * @param  int|null  $limit
     * @param  int|null  $offset
     * @param  Document|null  $orderAfter
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function getLogsByResource(string $resource, ?int $limit = 25, ?int $offset = null, ?Document $orderAfter = null): array
    {
        /** @var array<Document> $result */
        $result = Authorization::skip(function () use ($resource, $limit, $offset, $orderAfter) {
            $queries[] = Query::equal('resource', [$resource]);
            $queries[] = Query::orderDesc('');

            if (! \is_null($limit)) {
                $queries[] = Query::limit($limit);
            }
            if (! \is_null($offset)) {
                $queries[] = Query::offset($offset);
            }
            if (! \is_null($orderAfter)) {
                $queries[] = Query::cursorAfter($orderAfter);
            }

            return $this->db->find(
                collection: Audit::COLLECTION,
                queries: $queries,
            );
        });

        return $result;
    }

    /**
     * Count logs by resource.
     *
     * @param  string  $resource
     * @return int
     *
     * @throws \Exception
     */
    public function countLogsByResource(string $resource): int
    {
        /** @var int $count */
        $count = Authorization::skip(function () use ($resource) {
            return $this->db->count(
                collection: Audit::COLLECTION,
                queries: [Query::equal('resource', [$resource])]
            );
        });

        return $count;
    }

    /**
     * Get logs by user and events.
     *
     * @param  string  $userId
     * @param  array<int,string>  $events
     * @param  int|null  $limit
     * @param  int|null  $offset
     * @param  Document|null  $orderAfter
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function getLogsByUserAndEvents(string $userId, array $events, ?int $limit = null, ?int $offset = null, ?Document $orderAfter = null): array
    {
        /** @var array<Document> $result */
        $result = Authorization::skip(function () use ($userId, $events, $limit, $offset, $orderAfter) {
            $queries[] = Query::equal('userId', [$userId]);
            $queries[] = Query::equal('event', $events);
            $queries[] = Query::orderDesc('');

            if (! \is_null($limit)) {
                $queries[] = Query::limit($limit);
            }
            if (! \is_null($offset)) {
                $queries[] = Query::offset($offset);
            }
            if (! \is_null($orderAfter)) {
                $queries[] = Query::cursorAfter($orderAfter);
            }

            return $this->db->find(
                collection: Audit::COLLECTION,
                queries: $queries,
            );
        });

        return $result;
    }

    /**
     * Count logs by user and events.
     *
     * @param  string  $userId
     * @param  array<int,string>  $events
     * @return int
     *
     * @throws \Exception
     */
    public function countLogsByUserAndEvents(string $userId, array $events): int
    {
        /** @var int $count */
        $count = Authorization::skip(function () use ($userId, $events) {
            return $this->db->count(
                collection: Audit::COLLECTION,
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
     * @param  string  $resource
     * @param  array<int,string>  $events
     * @param  int|null  $limit
     * @param  int|null  $offset
     * @param  Document|null  $orderAfter
     * @return array<Document>
     *
     * @throws \Exception
     */
    public function getLogsByResourceAndEvents(string $resource, array $events, ?int $limit = null, ?int $offset = null, ?Document $orderAfter = null): array
    {
        /** @var array<Document> $result */
        $result = Authorization::skip(function () use ($resource, $events, $limit, $offset, $orderAfter) {
            $queries[] = Query::equal('resource', [$resource]);
            $queries[] = Query::equal('event', $events);
            $queries[] = Query::orderDesc('');

            if (! \is_null($limit)) {
                $queries[] = Query::limit($limit);
            }
            if (! \is_null($offset)) {
                $queries[] = Query::offset($offset);
            }
            if (! \is_null($orderAfter)) {
                $queries[] = Query::cursorAfter($orderAfter);
            }

            return $this->db->find(
                collection: Audit::COLLECTION,
                queries: $queries,
            );
        });

        return $result;
    }

    /**
     * Count logs by resource and events.
     *
     * @param  string  $resource
     * @param  array<int,string>  $events
     * @return int
     *
     * @throws \Exception
     */
    public function countLogsByResourceAndEvents(string $resource, array $events): int
    {
        /** @var int $count */
        $count = Authorization::skip(function () use ($resource, $events) {
            return $this->db->count(
                collection: Audit::COLLECTION,
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
     * @param  string  $datetime
     * @return bool
     *
     * @throws AuthorizationException
     * @throws \Exception
     */
    public function cleanup(string $datetime): bool
    {
        Authorization::skip(function () use ($datetime) {
            do {
                $documents = $this->db->find(
                    collection: Audit::COLLECTION,
                    queries: [
                        Query::lessThan('time', $datetime),
                    ]
                );

                foreach ($documents as $document) {
                    $this->db->deleteDocument(Audit::COLLECTION, $document->getId());
                }
            } while (! empty($documents));
        });

        return true;
    }

    /**
     * Add multiple event logs in batch.
     *
     * @param array<array{userId: string, event: string, resource: string, userAgent: string, ip: string, location: string, timestamp: string, data?: array<string,mixed>}> $events
     * @return bool
     *
     * @throws AuthorizationException
     * @throws StructureException
     * @throws \Exception
     * @throws \Throwable
     */
    public function logByBatch(array $events): bool
    {
        Authorization::skip(function () use ($events) {
            $documents = array_map(function ($event) {
                return new Document([
                    '$permissions' => [],
                    'userId' => $event['userId'],
                    'event' => $event['event'],
                    'resource' => $event['resource'],
                    'userAgent' => $event['userAgent'],
                    'ip' => $event['ip'],
                    'location' => $event['location'],
                    'data' => $event['data'] ?? [],
                    'time' => $event['timestamp'],
                ]);
            }, $events);
            
            $this->db->createDocuments(Audit::COLLECTION, $documents);
        });

        return true;
    }
}
