<?php

namespace Utopia\Audit;
use Utopia\Database\Database;
use Utopia\Database\Document;
use Utopia\Database\Query;

class Audit
{
    const COLLECTION = "abuse.abuse";
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

    private function init() {
        if(!$this->db->exists()) {
            $this->db->create();
            $this->db->createCollection(Audit::COLLECTION);
            $this->db->createAttribute(Audit::COLLECTION, 'userId', Database::VAR_STRING, 45, true);
            $this->db->createAttribute(Audit::COLLECTION,'event',Database::VAR_STRING,45,true);
            $this->db->createAttribute(Audit::COLLECTION,'resource',Database::VAR_STRING,45,false);
            $this->db->createAttribute(Audit::COLLECTION,'userAgent',Database::VAR_STRING,65534,true);
            $this->db->createAttribute(Audit::COLLECTION,'ip',Database::VAR_STRING,45,true);
            $this->db->createAttribute(Audit::COLLECTION,'location',Database::VAR_STRING,45,false);
            $this->db->createAttribute(Audit::COLLECTION,'time',Database::VAR_INTEGER,0,true,false);
            $this->db->createAttribute(Audit::COLLECTION,'data',Database::VAR_STRING,0,false);

            $this->db->createIndex(Audit::COLLECTION, 'index_1', Database::INDEX_KEY, ['userId']);
            $this->db->createIndex(Audit::COLLECTION, 'index_1', Database::INDEX_KEY, ['event']);
            $this->db->createIndex(Audit::COLLECTION, 'index_1', Database::INDEX_KEY, ['resource']);
            

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
        $this->db->createDocument(Audit::COLLECTION, new Document([
            '$read' => [],
            '$write' => [],
            'userId' => $userId,
            'event' => $event,
            'resource' => $resource,
            'userAgent' => $userAgent,
            'ip' => $ip,
            'location' => $location,
            'data' => $data
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
        return $this->db->find(Audit::COLLECTION, [
            new Query('userId', Query::TYPE_EQUAL, [$userId])
        ]);
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
        return $this->db->find(Audit::COLLECTION, [
            new Query('resource', Query::TYPE_EQUAL, [$resource])
        ]);
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
        return $this->db->find(Audit::COLLECTION, [
            new Query('userId', Query::TYPE_EQUAL, [$userId]),
            new Query('event',Query::TYPE_EQUAL, $actions)
        ]);
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
        $documents = $this->db->find(Audit::COLLECTION, [
            new Query('time', Query::TYPE_LESSER, [$timestamp])
        ]);
        
        foreach ($documents as $document) {
            $this->db->deleteDocument(Audit::COLLECTION,$document['$id']);
        }
        return true;
    }
}
