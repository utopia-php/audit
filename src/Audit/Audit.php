<?php

namespace Utopia\Audit;

use Utopia\Database\Database;
use Utopia\Database\DateTime;
use Utopia\Database\Document;
use Utopia\Database\Query;
use Utopia\Database\Validator\Authorization;
use Utopia\Exception;

class Audit
{
    const COLLECTION = 'audit';

    /**
     * @var Database
     */
    private Database $db;

    /**
     * @param  Database  $db
     */
    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    public function setup(): void
    {
        if (! $this->db->exists($this->db->getDefaultDatabase())) {
            throw new Exception('You need to create the database before running Audit setup');
        }

        $attributes = [
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
     * Log.
     *
     * Add specific event log
     *
     * @param  string  $userId
     * @param  string  $event
     * @param  string  $resource
     * @param  string  $userAgent
     * @param  string  $ip
     * @param  string  $location
     * @param  array  $data
     * @return bool
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
     * Get All Logs By User ID.
     *
     * @param  string  $userId
     * @param  int  $limit
     * @param  int  $offset
     * @param  Document|null  $orderAfter
     * @return array
     */
    public function getLogsByUser(string $userId, int $limit = 25, int $offset = 0, Document $orderAfter = null): array
    {
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
     * Get Logs Count By User ID.
     *
     * @param  string  $userId
     * @return int
     */
    public function countLogsByUser(string $userId): int
    {
        $result = Authorization::skip(function () use ($userId) {
            return $this->db->count(
                collection: Audit::COLLECTION,
                queries: $this->buildQuery(['userId' => $userId], Query::TYPE_EQUAL)
            );
        });

        return $result;
    }

    /**
     * Get All Logs By Resource.
     *
     * @param  string  $resource
     * @param  int  $limit
     * @param  int  $offset
     * @param  Document|null  $orderAfter
     * @return array
     */
    public function getLogsByResource(string $resource, int $limit = 25, int $offset = 0, Document $orderAfter = null): array
    {
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
     * Get Logs Count By Resource.
     *
     * @param  string  $resource
     * @return int
     */
    public function countLogsByResource(string $resource): int
    {
        $results = Authorization::skip(function () use ($resource) {
            return $this->db->count(
                collection: Audit::COLLECTION,
                queries: $this->buildQuery(['resource' => $resource], Query::TYPE_EQUAL)
            );
        });

        return $results;
    }

    /**
     * Get All Logs By User and Events.
     *
     * @param  string  $userId
     * @param  array  $events
     * @param  int  $limit
     * @param  int  $offset
     * @param  Document|null  $orderAfter
     * @return array
     */
    public function getLogsByUserAndEvents(string $userId, array $events, int $limit = 25, int $offset = 0, Document $orderAfter = null): array
    {
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
     * Get Logs Count By User and Events.
     *
     * @param  string  $userId
     * @param  array  $events
     * @return int
     */
    public function countLogsByUserAndEvents(string $userId, array $events): int
    {
        $results = Authorization::skip(function () use ($userId, $events) {
            return $this->db->count(
                collection: Audit::COLLECTION,
                queries: $this->buildQuery([
                    'userId' => $userId,
                    'event' => $events,
                ], Query::TYPE_EQUAL)
            );
        });

        return $results;
    }

    /**
     * Get All Logs By Resource and Events.
     *
     * @param  string  $resource
     * @param  array  $events
     * @param  int  $limit
     * @param  int  $offset
     * @param  Document|null  $orderAfter
     * @return array
     */
    public function getLogsByResourceAndEvents(string $resource, array $events, int $limit = 25, int $offset = 0, Document $orderAfter = null): array
    {
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
     * Get All Logs By Resource and Events.
     *
     * @param  string  $resource
     * @param  array  $events
     * @return int
     */
    public function countLogsByResourceAndEvents(string $resource, array $events): int
    {
        $results = Authorization::skip(function () use ($resource, $events) {
            return $this->db->count(
                collection: Audit::COLLECTION,
                queries: $this->buildQuery([
                    'resource' => $resource,
                    'event' => $events,
                ], Query::TYPE_EQUAL)
            );
        });

        return $results;
    }

    /**
     * Delete all logs older than $timestamp seconds
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
                    $this->db->deleteDocument(Audit::COLLECTION, $document['$id']);
                }
            } while (! empty($documents));
        });

        return true;
    }

    /**
     * Builds an array of Query objects from
     * an assoc array of $key => $value pairs
     *
     * The $method is applied to each k/v pair
     *
     * @param  array  $values
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
