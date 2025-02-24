<?php

namespace Utopia\Audit;

use ArrayObject;

/**
 * @extends ArrayObject<string, mixed>
 */
class Log extends ArrayObject
{
    protected string $ip;
    protected string $country;
    protected string $event;
    protected string $hostname;
    protected \DateTime $time;
    protected string $userAgent;
    protected string $location;
    protected string $resource;
    protected string $resourceId;
    protected string $resourceType;
    protected string $resourceParent;
    protected string $resourceInternalId;
    protected string $userType;
    protected string $userId;
    protected string $userInternalId;
    protected string $projectId;
    protected string $projectInternalId;
    protected string $teamId;
    protected string $teamInternalId;

    /**
     * @var array<string, mixed>
     */
    protected array $data;

    /**
     * @return string
     */
    public function getIp(): string
    {
        return $this->ip;
    }

    /**
     * @param string $ip
     * @return Log
     */
    public function setIp(string $ip): Log
    {
        $this->ip = $ip;
        return $this;
    }

    /**
     * @return string
     */
    public function getCountry(): string
    {
        return $this->country;
    }

    /**
     * @param string $country
     * @return Log
     */
    public function setCountry(string $country): Log
    {
        $this->country = $country;
        return $this;
    }

    /**
     * @return string
     */
    public function getEvent(): string
    {
        return $this->event;
    }

    /**
     * @param string $event
     * @return Log
     */
    public function setEvent(string $event): Log
    {
        $this->event = $event;
        return $this;
    }

    /**
     * @return string
     */
    public function getHostname(): string
    {
        return $this->hostname;
    }

    /**
     * @param string $hostname
     * @return Log
     */
    public function setHostname(string $hostname): Log
    {
        $this->hostname = $hostname;
        return $this;
    }

    /**
     * @return \DateTime
     */
    public function getTime(): \DateTime
    {
        return $this->time;
    }

    /**
     * @param \DateTime $time
     * @return Log
     */
    public function setTime(\DateTime $time): Log
    {
        $this->time = $time;
        return $this;
    }

    /**
     * @return string
     */
    public function getUserAgent(): string
    {
        return $this->userAgent;
    }

    /**
     * @param string $userAgent
     * @return Log
     */
    public function setUserAgent(string $userAgent): Log
    {
        $this->userAgent = $userAgent;
        return $this;
    }

    /**
     * @return string
     */
    public function getLocation(): string
    {
        return $this->location;
    }

    /**
     * @param string $location
     * @return Log
     */
    public function setLocation(string $location): Log
    {
        $this->location = $location;
        return $this;
    }

    /**
     * @return string
     */
    public function getResource(): string
    {
        return $this->resource;
    }

    /**
     * @param string $resource
     * @return Log
     */
    public function setResource(string $resource): Log
    {
        $this->resource = $resource;
        return $this;
    }

    /**
     * @return string
     */
    public function getResourceId(): string
    {
        return $this->resourceId;
    }

    /**
     * @param string $resourceId
     * @return Log
     */
    public function setResourceId(string $resourceId): Log
    {
        $this->resourceId = $resourceId;
        return $this;
    }

    /**
     * @return string
     */
    public function getResourceType(): string
    {
        return $this->resourceType;
    }

    /**
     * @param string $resourceType
     * @return Log
     */
    public function setResourceType(string $resourceType): Log
    {
        $this->resourceType = $resourceType;
        return $this;
    }

    /**
     * @return string
     */
    public function getResourceParent(): string
    {
        return $this->resourceParent;
    }

    /**
     * @param string $resourceParent
     * @return Log
     */
    public function setResourceParent(string $resourceParent): Log
    {
        $this->resourceParent = $resourceParent;
        return $this;
    }

    /**
     * @return string
     */
    public function getResourceInternalId(): string
    {
        return $this->resourceInternalId;
    }

    /**
     * @param string $resourceInternalId
     * @return Log
     */
    public function setResourceInternalId(string $resourceInternalId): Log
    {
        $this->resourceInternalId = $resourceInternalId;
        return $this;
    }

    /**
     * @return string
     */
    public function getUserType(): string
    {
        return $this->userType;
    }

    /**
     * @param string $userType
     * @return Log
     */
    public function setUserType(string $userType): Log
    {
        $this->userType = $userType;
        return $this;
    }

    /**
     * @return string
     */
    public function getUserId(): string
    {
        return $this->userId;
    }

    /**
     * @param string $userId
     * @return Log
     */
    public function setUserId(string $userId): Log
    {
        $this->userId = $userId;
        return $this;
    }

    /**
     * @return string
     */
    public function getUserInternalId(): string
    {
        return $this->userInternalId;
    }

    /**
     * @param string $userInternalId
     * @return Log
     */
    public function setUserInternalId(string $userInternalId): Log
    {
        $this->userInternalId = $userInternalId;
        return $this;
    }

    /**
     * @return string
     */
    public function getProjectId(): string
    {
        return $this->projectId;
    }

    /**
     * @param string $projectId
     * @return Log
     */
    public function setProjectId(string $projectId): Log
    {
        $this->projectId = $projectId;
        return $this;
    }

    /**
     * @return string
     */
    public function getProjectInternalId(): string
    {
        return $this->projectInternalId;
    }

    /**
     * @param string $projectInternalId
     * @return Log
     */
    public function setProjectInternalId(string $projectInternalId): Log
    {
        $this->projectInternalId = $projectInternalId;
        return $this;
    }

    /**
     * @return string
     */
    public function getTeamId(): string
    {
        return $this->teamId;
    }

    /**
     * @param string $teamId
     * @return Log
     */
    public function setTeamId(string $teamId): Log
    {
        $this->teamId = $teamId;
        return $this;
    }

    /**
     * @return string
     */
    public function getTeamInternalId(): string
    {
        return $this->teamInternalId;
    }

    /**
     * @param string $teamInternalId
     * @return Log
     */
    public function setTeamInternalId(string $teamInternalId): Log
    {
        $this->teamInternalId = $teamInternalId;
        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        return $this->data;
    }

    /**
     * @param array<string, mixed> $data
     * @return Log
     */
    public function setData(array $data): Log
    {
        $this->data = $data;
        return $this;
    }
}
