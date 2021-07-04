<?php

namespace Utopia\Audit;

use Utopia\Database\Database;
use Utopia\Database\Document;
use Utopia\Database\Query;
use Utopia\Database\Validator\Authorization;
use Utopia\Exception;

class Audit
{
    const COLLECTION = "audit";

    /**
     * @var Database
     */
    private $db;

    /**
     * @param Database $adapter
     */
    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    public function setup(): void
    {
        if (!$this->db->exists()) {
            throw new Exception("You need to create the databse before running Audit setup");
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
                'type' => Database::VAR_INTEGER,
                'size' => 0,
                'required' => false,
                'signed' => true,
                'array' => false,
                'filters' => [],
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
                '$id' => 'index1',
                'type' => Database::INDEX_KEY,
                'attributes' => ['userId'],
                'lengths' => [],
                'orders' => [],
            ]),
            new Document([
                '$id' => 'index2',
                'type' => Database::INDEX_KEY,
                'attributes' => ['event'],
                'lengths' => [],
                'orders' => [],
            ]),
            new Document([
                '$id' => 'index3',
                'type' => Database::INDEX_KEY,
                'attributes' => ['resource'],
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
        ];

        $this->db->createCollection(Audit::COLLECTION, $attributes, $indexes);

    }

    /**
     * Log.
     *
     * Add specific event log
     *
     * @param string $userId
     * @param string $event
     * @param string $resource
     * @param string $userAgent
     * @param string $ip
     * @param string $location
     * @param array  $data
     *
     * @return bool
     */
    public function log(string $userId, string $event, string $resource, string $userAgent, string $ip, string $location, array $data = []): bool
    {
        Authorization::disable();
        $this->db->createDocument(Audit::COLLECTION, new Document([
            '$read' => [],
            '$write' => [],
            'userId' => $userId,
            'event' => $event,
            'resource' => $resource,
            'userAgent' => $userAgent,
            'ip' => $ip,
            'location' => $location,
            'data' => $data,
            'time' => \time(),
        ]));
        Authorization::reset();
        return true;
    }

    /**
     * Get All Logs By User ID.
     *
     * @param string $userId
     *
     * @return array
     */
    public function getLogsByUser(string $userId): array
    {
        Authorization::disable();
        $result = $this->db->find(Audit::COLLECTION, [
            new Query('userId', Query::TYPE_EQUAL, [$userId]),
        ], 25, 0, ['_id'], ['DESC']);
        Authorization::reset();
        return $result;
    }

    /**
     * Get All Logs By Resource.
     *
     * @param string $resource
     *
     * @return array
     */
    public function getLogsByResource(string $resource): array
    {
        Authorization::disable();
        $results = $this->db->find(Audit::COLLECTION, [
            new Query('resource', Query::TYPE_EQUAL, [$resource]),
        ], 25, 0, ['_id'], ['DESC']);
        Authorization::reset();
        return $results;
    }

    /**
     * Get All Logs By User and Actions.
     *
     * Get all user logs logs by given action names
     *
     * @param string $userId
     * @param array $events
     *
     * @return array
     */
    public function getLogsByUserAndEvents(string $userId, array $events): array
    {
        Authorization::disable();
        $results = $this->db->find(Audit::COLLECTION, [
            new Query('userId', Query::TYPE_EQUAL, [$userId]),
            new Query('event', Query::TYPE_EQUAL, $events),
        ], 25, 0, ['_id'], ['DESC']);
        Authorization::reset();
        return $results;
    }

    /**
     * Delete all logs older than $timestamp seconds
     *
     * @param int $timestamp
     *
     * @return bool
     */
    public function cleanup(int $timestamp): bool
    {
        Authorization::disable();
        do {
            $documents = $this->db->find(Audit::COLLECTION, [
                new Query('time', Query::TYPE_LESSER, [$timestamp]),
            ]);
    
            foreach ($documents as $document) {
                $this->db->deleteDocument(Audit::COLLECTION, $document['$id']);
            }
        } while(!empty($documents));
        Authorization::reset();
        return true;
    }
}
