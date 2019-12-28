<?php

namespace Utopia\Audit;

class Audit
{
    /**
     * @var Adapter
     */
    private $adapter;

    /**
     * @var int
     */
    private $userId;

    /**
     * @var int
     */
    private $userType;

    /**
     * @var string
     */
    private $userAgent;

    /**
     * @var string
     */
    private $ip;

    /**
     * @var string
     */
    private $location;

    /**
     * @param Adapter $adapter
     * @param string  $userId
     * @param int     $userType
     * @param string  $userAgent
     * @param string  $ip
     * @param string  $location
     */
    public function __construct(Adapter $adapter, $userId, $userType, $userAgent, $ip, $location)
    {
        $this->adapter = $adapter;
        $this->userId = $userId;
        $this->userType = $userType;
        $this->userAgent = $userAgent;
        $this->ip = $ip;
        $this->location = $location;
    }

    /**
     * Log.
     *
     * Add specific event log
     *
     * @param string $event
     * @param string $resource
     * @param array  $data
     *
     * @return bool
     */
    public function log($event, $resource = '', array $data = []):bool
    {
        return $this->adapter->log($this->userId, $this->userType, $event, $resource, $this->userAgent, $this->ip, $this->location, $data);
    }

    /**
     * Get All Logs By User and Actions.
     *
     * Get all user logs logs by given action names
     *
     * @param int $userId
     * @param int $userType
     *
     * @return array
     */
    public function getLogsByUser($userId, $userType):array
    {
        return $this->adapter->getLogsByUser($userId, $userType);
    }

    /**
     * Get All Logs By User and Actions.
     *
     * Get all user logs logs by given action names
     *
     * @param int   $userId
     * @param int   $userType
     * @param array $actions
     *
     * @return array
     */
    public function getLogsByUserAndActions($userId, $userType, array $actions):array
    {
        return $this->adapter->getLogsByUserAndActions($userId, $userType, $actions);
    }
}
