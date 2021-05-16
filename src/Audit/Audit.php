<?php

namespace Utopia\Audit;

use Utopia\Database\Database;
use Utopia\Database\Document;
use Utopia\Database\Query;
use Utopia\Database\Validator\Authorization;

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
        $this->init();
    }

    private function init(): void
    {
        if (!$this->db->exists()) {
            $this->db->create();
            $this->db->createCollection(Audit::COLLECTION);
            $this->db->createAttribute(Audit::COLLECTION, 'userId', Database::VAR_STRING, Database::LENGTH_KEY, true);
            $this->db->createAttribute(Audit::COLLECTION, 'event', Database::VAR_STRING, 255, true);
            $this->db->createAttribute(Audit::COLLECTION, 'resource', Database::VAR_STRING, 255, false);
            $this->db->createAttribute(Audit::COLLECTION, 'userAgent', Database::VAR_STRING, 65534, true);
            $this->db->createAttribute(Audit::COLLECTION, 'ip', Database::VAR_STRING, 45, true);
            $this->db->createAttribute(Audit::COLLECTION, 'location', Database::VAR_STRING, 45, false);
            $this->db->createAttribute(Audit::COLLECTION, 'time', Database::VAR_INTEGER, 0, true, false);
            $this->db->createAttribute(Audit::COLLECTION, 'data', Database::VAR_STRING, 16777216, false,true,false,['json']);

            $this->db->createIndex(Audit::COLLECTION, 'index_1', Database::INDEX_KEY, ['userId']);
            $this->db->createIndex(Audit::COLLECTION, 'index_2', Database::INDEX_KEY, ['event']);
            $this->db->createIndex(Audit::COLLECTION, 'index_3', Database::INDEX_KEY, ['resource']);

        }
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
            'time' => \time()
        ]));
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
        ]);
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
        ]);
        Authorization::reset();
        return $results;
    }

    /**
     * Get All Logs By User and Actions.
     *
     * Get all user logs logs by given action names
     *
     * @param string $userId
     * @param array $actions
     *
     * @return array
     */
    public function getLogsByUserAndActions(string $userId, array $actions): array
    {
        Authorization::disable();
        $results = $this->db->find(Audit::COLLECTION, [
            new Query('userId', Query::TYPE_EQUAL, [$userId]),
            new Query('event', Query::TYPE_EQUAL, $actions),
        ]);
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
        $documents = $this->db->find(Audit::COLLECTION, [
            new Query('time', Query::TYPE_LESSER, [$timestamp]),
        ]);

        foreach ($documents as $document) {
            $this->db->deleteDocument(Audit::COLLECTION, $document['$id']);
        }
        Authorization::reset();
        return true;
    }
}
