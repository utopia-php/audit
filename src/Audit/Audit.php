<?php

namespace Utopia\Audit;

class Audit
{
    /**
     * @var Adapter
     */
    private $adapter;

    /**
     * @param Adapter $adapter
     */
    public function __construct(Adapter $adapter)
    {
        $this->adapter = $adapter;
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
        return $this->adapter->log($userId, $event, $resource, $userAgent, $ip, $location, $data);
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
        return $this->adapter->getLogsByUser($userId);
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
        return $this->adapter->getLogsByResource($resource);
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
        return $this->adapter->getLogsByUserAndActions($userId, $actions);
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
        return $this->adapter->cleanup($timestamp);
    }
}
