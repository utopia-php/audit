<?php

namespace Utopia\Audit;

use Exception;

abstract class Adapter
{
    protected $namespace = '';

    /**
     * Set Namespace.
     *
     * Set namespace to divide different scope of data sets
     *
     * @param $namespace
     *
     * @throws Exception
     *
     * @return bool
     */
    public function setNamespace($namespace):bool
    {
        if (empty($namespace)) {
            throw new Exception('Missing namespace');
        }

        $this->namespace = $namespace;

        return true;
    }

    /**
     * Get Namespace.
     *
     * Get namespace of current set scope
     *
     * @throws Exception
     *
     * @return string
     */
    public function getNamespace():string
    {
        if (empty($this->namespace)) {
            throw new Exception('Missing namespace');
        }

        return $this->namespace;
    }

    /**
     * Log.
     *
     * Add specific event log
     *
     * @param string $userId
     * @param int    $userType
     * @param string $event
     * @param string $resource
     * @param string $userAgent
     * @param string $ip
     * @param string $location
     * @param array  $data
     *
     * @return
     */
    abstract public function log(string $userId, int $userType, string $event, string $resource, string $userAgent, string $ip, string $location, array $data):bool;

    /**
     * Get All Logs By User.
     *
     * Get all user logs
     *
     * @param string $userId
     * @param int $userType
     *
     * @return array
     */
    abstract public function getLogsByUser(string $userId, int $userType):array;

    /**
     * Get All Logs By User and Actions.
     *
     * Get all user logs by given action names
     *
     * @param string $userId
     * @param int    $userType
     * @param array  $actions
     *
     * @return array
     */
    abstract public function getLogsByUserAndActions(string $userId, int $userType, array $actions):array;
}
