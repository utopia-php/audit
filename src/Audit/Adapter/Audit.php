<?php

namespace Utopia\Audit\Adapter;

use Utopia\Audit\Adapter;
use Utopia\Audit\Log;
use Utopia\Database\Database;
use Utopia\Database\Document;
use Utopia\Database\Exception\Authorization as AuthorizationException;
use Utopia\Database\Exception\Structure as StructureException;
use Utopia\Database\Validator\Authorization;

class Audit extends Adapter
{
    public function getCollection(): string
    {
        return 'audit';
    }

    public function getAttributes(): array
    {
        return [
            [
                '$id' => 'userId',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ], [
                '$id' => 'event',
                'type' => Database::VAR_STRING,
                'size' => 255,
                'required' => true,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ], [
                '$id' => 'resource',
                'type' => Database::VAR_STRING,
                'size' => 255,
                'required' => false,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ], [
                '$id' => 'userAgent',
                'type' => Database::VAR_STRING,
                'size' => 65534,
                'required' => true,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ], [
                '$id' => 'ip',
                'type' => Database::VAR_STRING,
                'size' => 45,
                'required' => true,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ], [
                '$id' => 'location',
                'type' => Database::VAR_STRING,
                'size' => 45,
                'required' => false,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ], [
                '$id' => 'time',
                'type' => Database::VAR_DATETIME,
                'format' => '',
                'size' => 0,
                'signed' => true,
                'required' => false,
                'array' => false,
                'filters' => ['datetime'],
            ], [
                '$id' => 'data',
                'type' => Database::VAR_STRING,
                'size' => 16777216,
                'required' => false,
                'signed' => true,
                'array' => false,
                'filters' => ['json'],
            ],
        ];
    }

    public function getIndexes(): array
    {
        return [
            [
                '$id' => 'index2',
                'type' => Database::INDEX_KEY,
                'attributes' => ['event'],
                'lengths' => [],
                'orders' => [],
            ], [
                '$id' => 'index4',
                'type' => Database::INDEX_KEY,
                'attributes' => ['userId', 'event'],
                'lengths' => [],
                'orders' => [],
            ], [
                '$id' => 'index5',
                'type' => Database::INDEX_KEY,
                'attributes' => ['resource', 'event'],
                'lengths' => [],
                'orders' => [],
            ], [
                '$id' => 'index-time',
                'type' => Database::INDEX_KEY,
                'attributes' => ['time'],
                'lengths' => [],
                'orders' => [Database::ORDER_DESC],
            ],
        ];
    }

    /**
     * Add event log.
     *
     * @param Log $log
     * @return bool
     *
     * @throws AuthorizationException
     * @throws StructureException
     * @throws \Exception
     * @throws \Throwable
     */
    public function log(Log $log): bool
    {
        Authorization::skip(function () use ($log) {
            $this->db->createDocument($this->getCollection(), new Document([
                '$permissions' => [],
                'userId' => $log->getUserId(),
                'event' => $log->getEvent(),
                'resource' => $log->getResource(),
                'userAgent' => $log->getUserAgent(),
                'ip' => $log->getIp(),
                'location' => $log->getLocation(),
                'data' => $log->getData(),
                'time' => $log->getTime(),
            ]));
        });

        return true;
    }


    /**
     * Add multiple event logs in batch.
     *
     * @param array<Log> $events
     * @return bool
     *
     * @throws AuthorizationException
     * @throws StructureException
     * @throws \Exception
     * @throws \Throwable
     */
    public function logBatch(array $events): bool
    {
        Authorization::skip(function () use ($events) {
            $documents = array_map(function ($event) {
                return new Document([
                    '$permissions' => [],
                    'userId' => $event->getUserId(),
                    'event' => $event->getEvent(),
                    'resource' => $event->getResource(),
                    'userAgent' => $event->getUserAgent(),
                    'ip' => $event->getIp(),
                    'location' => $event->getLocation(),
                    'data' => $event->getData(),
                    'time' => $event->getTime(),
                ]);
            }, $events);

            $this->db->createDocuments(
                $this->getCollection(),
                $documents
            );
        });

        return true;
    }
}
