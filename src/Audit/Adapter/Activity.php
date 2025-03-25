<?php

namespace Utopia\Audit\Adapter;

use Utopia\Audit\Adapter;
use Utopia\Audit\Log;
use Utopia\Database\Database;

class Activity extends Adapter
{
    public static function getCollection(): string
    {
        return 'activities';
    }

    public static function getAttributes(): array
    {
        return [
            [
                // can be user, app, guest
                '$id' => 'userType',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'userId',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'userInternalId',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                // example: database/ID if resourceType = collection
                '$id' => 'resourceParent',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => false,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                // example: collections
                '$id' => 'resourceType',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                // example: collections.id
                '$id' => 'resourceId',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'resourceInternalId',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => false,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'event',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'resource',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => false,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'userAgent',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'ip',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'country',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => false,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'time',
                'type' => Database::VAR_DATETIME,
                'format' => '',
                'size' => 0,
                'signed' => true,
                'required' => false,
                'array' => false,
                'filters' => ['datetime'],
            ],
            [
                '$id' => 'data',
                'type' => Database::VAR_STRING,
                'size' => 16777216,
                'required' => false,
                'signed' => true,
                'array' => false,
                'filters' => ['json'],
            ],
            [
                '$id' => 'projectId',
                'type' => Database::VAR_STRING,
                'format' => '',
                'size' => Database::LENGTH_KEY,
                'signed' => true,
                'required' => true,
                'default' => null,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'projectInternalId',
                'type' => Database::VAR_STRING,
                'format' => '',
                'size' => Database::LENGTH_KEY,
                'signed' => true,
                'required' => true,
                'default' => null,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'teamId',
                'type' => Database::VAR_STRING,
                'format' => '',
                'size' => Database::LENGTH_KEY,
                'signed' => true,
                'required' => true,
                'default' => null,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'teamInternalId',
                'type' => Database::VAR_STRING,
                'format' => '',
                'size' => Database::LENGTH_KEY,
                'signed' => true,
                'required' => true,
                'default' => null,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'hostname',
                'type' => Database::VAR_STRING,
                'format' => '',
                'size' => Database::LENGTH_KEY,
                'signed' => true,
                'required' => true,
                'default' => null,
                'array' => false,
                'filters' => [],
            ],
        ];
    }

    public static function getIndexes(): array
    {
        return [
            [
                '$id' => '_key_event',
                'type' => Database::INDEX_KEY,
                'attributes' => ['event'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_user_internal_and_event',
                'type' => Database::INDEX_KEY,
                'attributes' => ['userInternalId', 'event'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_resource_and_event',
                'type' => Database::INDEX_KEY,
                'attributes' => ['resource', 'event'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_time',
                'type' => Database::INDEX_KEY,
                'attributes' => ['time'],
                'lengths' => [],
                'orders' => [Database::ORDER_DESC],
            ],
            [
                '$id' => '_key_project_internal_id',
                'type' => Database::INDEX_KEY,
                'attributes' => ['projectInternalId'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_team_internal_id',
                'type' => Database::INDEX_KEY,
                'attributes' => ['teamInternalId'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_user_internal_id',
                'type' => Database::INDEX_KEY,
                'attributes' => ['userInternalId'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_user_type',
                'type' => Database::INDEX_KEY,
                'attributes' => ['userType'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_country',
                'type' => Database::INDEX_KEY,
                'attributes' => ['country'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_hostname',
                'type' => Database::INDEX_KEY,
                'attributes' => ['hostname'],
                'lengths' => [],
                'orders' => [],
            ],
        ];
    }

    public function filter(Log $log): Log
    {
        unset($log['location']);
        return $log;
    }
}
