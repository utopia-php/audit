<?php

namespace Utopia\Audit;

use ArrayObject;

/**
 * Audit Log
 *
 * Represents a single audit log entry with structured data.
 * Extends ArrayObject to provide array-like access while maintaining type safety.
 *
 * @extends ArrayObject<string, mixed>
 */
class Log extends ArrayObject
{
    /**
     * Construct a new audit log object.
     *
     * @param array<string, mixed> $input
     */
    public function __construct(array $input = [])
    {
        parent::__construct($input);
    }

    /**
     * Get the log ID.
     *
     * @return string
     */
    public function getId(): string
    {
        $id = $this->getAttribute('$id', '');
        return is_string($id) ? $id : '';
    }

    /**
     * Get the user ID associated with this log entry.
     *
     * @return string|null
     */
    public function getUserId(): ?string
    {
        $userId = $this->getAttribute('userId');
        return is_string($userId) ? $userId : null;
    }

    /**
     * Get the actor ID associated with this log entry.
     *
     * @return string|null
     */
    public function getActorId(): ?string
    {
        $actorId = $this->getAttribute('actorId');
        return is_string($actorId) ? $actorId : null;
    }

    /**
     * Get the actor type associated with this log entry.
     *
     * @return string|null
     */
    public function getActorType(): ?string
    {
        $actorType = $this->getAttribute('actorType');
        return is_string($actorType) ? $actorType : null;
    }

    /**
     * Get the actor internal ID associated with this log entry.
     *
     * @return string|null
     */
    public function getActorInternalId(): ?string
    {
        $actorInternalId = $this->getAttribute('actorInternalId');
        return is_string($actorInternalId) ? $actorInternalId : null;
    }

    /**
     * Get the event name.
     *
     * @return string
     */
    public function getEvent(): string
    {
        $event = $this->getAttribute('event', '');
        return is_string($event) ? $event : '';
    }

    /**
     * Get the resource identifier.
     *
     * @return string
     */
    public function getResource(): string
    {
        $resource = $this->getAttribute('resource', '');
        return is_string($resource) ? $resource : '';
    }

    /**
     * Get the SDK name associated with this log entry.
     *
     * Optional column: returns null when the SDK was never recorded, mirroring
     * the other nullable actor columns (getActorId/getActorInternalId).
     *
     * @return string|null
     */
    public function getSdk(): ?string
    {
        $sdk = $this->getAttribute('sdk');
        return is_string($sdk) ? $sdk : null;
    }

    /**
     * Get the SDK version associated with this log entry.
     *
     * Optional column: returns null when the SDK version was never recorded.
     *
     * @return string|null
     */
    public function getSdkVersion(): ?string
    {
        $sdkVersion = $this->getAttribute('sdkVersion');
        return is_string($sdkVersion) ? $sdkVersion : null;
    }

    /**
     * Get the user agent string.
     *
     * @return string
     */
    public function getUserAgent(): string
    {
        $userAgent = $this->getAttribute('userAgent', '');
        return is_string($userAgent) ? $userAgent : '';
    }

    /**
     * Get the IP address.
     *
     * @return string
     */
    public function getIp(): string
    {
        $ip = $this->getAttribute('ip', '');
        return is_string($ip) ? $ip : '';
    }

    /**
     * Get the timestamp.
     *
     * @return string
     */
    public function getTime(): string
    {
        $time = $this->getAttribute('time', '');
        return is_string($time) ? $time : '';
    }

    /**
     * Get the additional data.
     *
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        $data = $this->getAttribute('data', []);
        return is_array($data) ? $data : [];
    }

    /**
     * Get the tenant ID (for multi-tenant setups).
     *
     * @return int|null
     */
    public function getTenant(): ?int
    {
        $tenant = $this->getAttribute('tenant');

        if ($tenant === null) {
            return null;
        }

        if (is_int($tenant)) {
            return $tenant;
        }

        if (is_numeric($tenant)) {
            return (int) $tenant;
        }

        return null;
    }

    /**
     * Get an attribute by key.
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    public function getAttribute(string $key, mixed $default = null): mixed
    {
        return $this->offsetExists($key) ? $this->offsetGet($key) : $default;
    }

    /**
     * Set an attribute.
     *
     * @param string $key
     * @param mixed $value
     * @return self
     */
    public function setAttribute(string $key, mixed $value): self
    {
        $this->offsetSet($key, $value);
        return $this;
    }

    /**
     * Remove an attribute.
     *
     * @param string $key
     * @return self
     */
    public function removeAttribute(string $key): self
    {
        if ($this->offsetExists($key)) {
            $this->offsetUnset($key);
        }
        return $this;
    }

    /**
     * Check if an attribute exists.
     *
     * @param string $key
     * @return bool
     */
    public function isSet(string $key): bool
    {
        return $this->offsetExists($key);
    }

    /**
     * Get all attributes as an array.
     *
     * @return array<string, mixed>
     */
    public function getArrayCopy(): array
    {
        return parent::getArrayCopy();
    }
}
