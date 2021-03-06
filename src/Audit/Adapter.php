<?php

namespace Utopia\Audit;

use Exception;

abstract class Adapter
{
    /**
     * @var string
     */
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
    public function setNamespace(string $namespace): bool
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
    public function getNamespace(): string
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
     * @param string $event
     * @param string $resource
     * @param string $userAgent
     * @param string $ip
     * @param string $location
     * @param array  $data
     *
     * @return bool
     */
    abstract public function log(string $userId, string $event, string $resource, string $userAgent, string $ip, string $location, array $data): bool;

    /**
     * Get All Logs By User.
     *
     * Get all user logs
     *
     * @param string $userId
     *
     * @return array
     */
    abstract public function getLogsByUser(string $userId): array;

    /**
     * Get All Logs By Resource.
     *
     * @param string $resource
     *
     * @return array
     */
    abstract public function getLogsByResource(string $resource): array;

    /**
     * Get All Logs By User and Actions.
     *
     * Get all user logs by given action names
     *
     * @param string $userId
     * @param array  $actions
     *
     * @return array
     */
    abstract public function getLogsByUserAndActions(string $userId, array $actions): array;

    /**
     * Delete all logs older than $timestamp seconds
     *
     * @param int $timestamp
     * 
     * @return bool
     */
    abstract public function cleanup(int $timestamp): bool;
}
