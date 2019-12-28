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
    public function log(string $userId, string $event, string $resource, string $userAgent, string $ip, string $location, array $data = []):bool
    {
        return $this->adapter->log($userId, $event, $resource, $userAgent, $ip, $location, $data);
    }

    /**
     * Get All Logs By User and Actions.
     *
     * Get all user logs logs by given action names
     *
     * @param int $userId
     *
     * @return array
     */
    public function getLogsByUser(string $userId):array
    {
        return $this->adapter->getLogsByUser($userId);
    }

    /**
     * Get All Logs By User and Actions.
     *
     * Get all user logs logs by given action names
     *
     * @param int   $userId
     * @param array $actions
     *
     * @return array
     */
    public function getLogsByUserAndActions(string $userId, array $actions):array
    {
        return $this->adapter->getLogsByUserAndActions($userId, $actions);
    }
}
