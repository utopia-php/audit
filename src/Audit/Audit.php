<?php

namespace Utopia\Audit;

use Exception as GlobalException;
use Utopia\Database\Database;
use Utopia\Database\DateTime;
use Utopia\Database\Document;
use Utopia\Database\Exception\Duplicate;
use Utopia\Database\Query;
use Utopia\Database\Validator\Authorization;
use Utopia\Exception;

class Audit
{
    const COLLECTION = 'audit';

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
     * @throws GlobalException
     * @throws Exception
     * @throws Duplicate
     */
    public function setup(): void
    {
        if (! $this->db->exists($this->db->getDefaultDatabase())) {
            throw new Exception('You need to create the database before running Audit setup');
        }

        $attributes = [
            new Document([
                '$id' => 'userInternalId',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ]),
            new Document([
                '$id' => 'userId',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ]),
            new Document([
                '$id' => 'event',
                'type' => Database::VAR_STRING,
                'size' => 255,
                'required' => true,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ]),
            new Document([
                '$id' => 'resource',
                'type' => Database::VAR_STRING,
                'size' => 255,
                'required' => false,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ]),
            new Document([
                '$id' => 'userAgent',
                'type' => Database::VAR_STRING,
                'size' => 65534,
                'required' => true,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ]),
            new Document([
                '$id' => 'ip',
                'type' => Database::VAR_STRING,
                'size' => 45,
                'required' => true,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ]),
            new Document([
                '$id' => 'location',
                'type' => Database::VAR_STRING,
                'size' => 45,
                'required' => false,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ]),
            new Document([
                '$id' => 'time',
                'type' => Database::VAR_DATETIME,
                'format' => '',
                'size' => 0,
                'signed' => true,
                'required' => false,
                'array' => false,
                'filters' => ['datetime'],
            ]),
            new Document([
                '$id' => 'data',
                'type' => Database::VAR_STRING,
                'size' => 16777216,
                'required' => false,
                'signed' => true,
                'array' => false,
                'filters' => ['json'],
            ]),
        ];

        $indexes = [
            new Document([
                '$id' => 'index2',
                'type' => Database::INDEX_KEY,
                'attributes' => ['event'],
                'lengths' => [],
                'orders' => [],
            ]),
            new Document([
                '$id' => 'index4',
                'type' => Database::INDEX_KEY,
                'attributes' => ['userId', 'event'],
                'lengths' => [],
                'orders' => [],
            ]),
            new Document([
                '$id' => 'index5',
                'type' => Database::INDEX_KEY,
                'attributes' => ['resource', 'event'],
                'lengths' => [],
                'orders' => [],
            ]),
            new Document([
                '$id' => 'index-time',
                'type' => Database::INDEX_KEY,
                'attributes' => ['time'],
                'lengths' => [],
                'orders' => [Database::ORDER_DESC],
            ]),
        ];

        $this->db->createCollection(Audit::COLLECTION, $attributes, $indexes);
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
     */
    public function log(string $userInternalId, string $userId, string $event, string $resource, string $userAgent, string $ip, string $location, array $data = []): bool
    {
        Authorization::skip(function () use ($userId, $userInternalId, $event, $resource, $userAgent, $ip, $location, $data) {
            $this->db->createDocument(Audit::COLLECTION, new Document([
                '$permissions' => [],
                'userInternalId' => $userInternalId,
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
     * @param  int  $limit
     * @param  int  $offset
     * @param  Document|null  $orderAfter
     * @return Document[]
     */
    public function getLogsByUser(string $userId, int $limit = 25, int $offset = 0, Document $orderAfter = null): array
    {
        /** @var Document[] $result */
        $result = Authorization::skip(function () use ($userId, $limit, $offset, $orderAfter) {
            $queries = $this->buildQuery(['userId' => $userId], Query::TYPE_EQUAL);

            $queries[] = Query::limit($limit);
            $queries[] = Query::offset($offset);
            $queries[] = Query::orderDesc('');
            if ($orderAfter) {
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
                queries: $this->buildQuery(['userId' => $userId], Query::TYPE_EQUAL)
            );
        });

        return $count;
    }

    /**
     * Get all logs by resource.
     *
     * @param  string  $resource
     * @param  int  $limit
     * @param  int  $offset
     * @param  Document|null  $orderAfter
     * @return Document[]
     */
    public function getLogsByResource(string $resource, int $limit = 25, int $offset = 0, Document $orderAfter = null): array
    {
        /** @var Document[] $results */
        $results = Authorization::skip(function () use ($resource, $limit, $offset, $orderAfter) {
            $queries = $this->buildQuery(['resource' => $resource], Query::TYPE_EQUAL);

            $queries[] = Query::limit($limit);
            $queries[] = Query::offset($offset);
            $queries[] = Query::orderDesc('');
            if ($orderAfter) {
                $queries[] = Query::cursorAfter($orderAfter);
            }

            return $this->db->find(
                collection: Audit::COLLECTION,
                queries: $queries,
            );
        });

        return $results;
    }

    /**
     * Count logs by resource.
     *
     * @param  string  $resource
     * @return int
     */
    public function countLogsByResource(string $resource): int
    {
        /** @var int $count */
        $count = Authorization::skip(fn () => $this->db->count(
            collection: Audit::COLLECTION,
            queries: $this->buildQuery(['resource' => $resource], Query::TYPE_EQUAL)
        ));

        return $count;
    }

    /**
     * Get logs by user and events.
     *
     * @param  string  $userId
     * @param  array<int,string>  $events
     * @param  int  $limit
     * @param  int  $offset
     * @param  Document|null  $orderAfter
     * @return Document[]
     */
    public function getLogsByUserAndEvents(string $userId, array $events, int $limit = 25, int $offset = 0, Document $orderAfter = null): array
    {
        /** @var Document[] $results */
        $results = Authorization::skip(function () use ($userId, $events, $limit, $offset, $orderAfter) {
            $queries = $this->buildQuery([
                'userId' => $userId,
                'event' => $events,
            ], Query::TYPE_EQUAL);

            $queries[] = Query::limit($limit);
            $queries[] = Query::offset($offset);
            $queries[] = Query::orderDesc('');
            if ($orderAfter) {
                $queries[] = Query::cursorAfter($orderAfter);
            }

            return $this->db->find(
                collection: Audit::COLLECTION,
                queries: $queries,
            );
        });

        return $results;
    }

    /**
     * Count logs by user and events.
     *
     * @param  string  $userId
     * @param  array<int,string>  $events
     * @return int
     */
    public function countLogsByUserAndEvents(string $userId, array $events): int
    {
        /** @var int $count */
        $count = Authorization::skip(fn () => $this->db->count(
            collection: Audit::COLLECTION,
            queries: $this->buildQuery([
                'userId' => $userId,
                'event' => $events,
            ], Query::TYPE_EQUAL)
        ));

        return $count;
    }

    /**
     * Get logs by resource and events.
     *
     * @param  string  $resource
     * @param  array<int,string>  $events
     * @param  int  $limit
     * @param  int  $offset
     * @param  Document|null  $orderAfter
     * @return Document[]
     */
    public function getLogsByResourceAndEvents(string $resource, array $events, int $limit = 25, int $offset = 0, Document $orderAfter = null): array
    {
        /** @var Document[] $results */
        $results = Authorization::skip(function () use ($resource, $events, $limit, $offset, $orderAfter) {
            $queries = $this->buildQuery([
                'resource' => $resource,
                'event' => $events,
            ], Query::TYPE_EQUAL);

            $queries[] = Query::limit($limit);
            $queries[] = Query::offset($offset);
            $queries[] = Query::orderDesc('');
            if ($orderAfter) {
                $queries[] = Query::cursorAfter($orderAfter);
            }

            return $this->db->find(
                collection: Audit::COLLECTION,
                queries: $queries,
            );
        });

        return $results;
    }

    /**
     * Count logs by resource and events.
     *
     * @param  string  $resource
     * @param  array<int,string>  $events
     * @return int
     */
    public function countLogsByResourceAndEvents(string $resource, array $events): int
    {
        /** @var int $count */
        $count = Authorization::skip(function () use ($resource, $events) {
            return $this->db->count(
                collection: Audit::COLLECTION,
                queries: $this->buildQuery([
                    'resource' => $resource,
                    'event' => $events,
                ], Query::TYPE_EQUAL)
            );
        });

        return $count;
    }

    /**
     * Delete all logs older than `$timestamp` seconds
     *
     * @param  string  $datetime
     * @return bool
     */
    public function cleanup(string $datetime): bool
    {
        Authorization::skip(function () use ($datetime) {
            do {
                $documents = $this->db->find(
                    collection: Audit::COLLECTION,
                    queries: $this->buildQuery([
                        'time' => $datetime,
                    ], Query::TYPE_LESSER)
                );

                foreach ($documents as $document) {
                    $this->db->deleteDocument(Audit::COLLECTION, $document->getId());
                }
            } while (! empty($documents));
        });

        return true;
    }

    /**
     * Builds an array of Query objects from
     * an assoc array of $key => $value pairs
     *
     * The `$method` is applied to each k/v pair
     *
     * @param  array<string,mixed>  $values
     * @param  string  $method
     * @return Query[]
     *
     * @throws Exception
     */
    private function buildQuery(array $values, string $method): array
    {
        if (! Query::isMethod($method)) {
            throw new Exception('Method not supported');
        }

        $query = [];
        foreach ($values as $key => $value) {
            if (! \is_array($value)) {
                $value = [$value];
            }
            $query[] = new Query($method, $key, $value);
        }

        return $query;
    }
}
