# Utopia Audit

[![Build Status](https://travis-ci.org/utopia-php/audit.svg?branch=master)](https://travis-ci.com/utopia-php/audit)
![Total Downloads](https://img.shields.io/packagist/dt/utopia-php/audit.svg)
[![Discord](https://img.shields.io/discord/564160730845151244)](https://appwrite.io/discord)

Utopia framework audit library is simple and lite library for managing application user logs. This library is aiming to be as simple and easy to learn and use. This library is maintained by the [Appwrite team](https://appwrite.io).

Although this library is part of the [Utopia Framework](https://github.com/utopia-php/framework) project it is dependency free, and can be used as standalone with any other PHP project or framework.

## Features

- **Adapter Pattern**: Support for multiple storage backends through adapters
- **Default Database Adapter**: Built-in support for utopia-php/database
- **Extensible**: Easy to create custom adapters for different storage solutions
- **Batch Operations**: Support for logging multiple events at once
- **Query Support**: Rich querying capabilities for retrieving logs

## Getting Started

Install using composer:
```bash
composer require utopia-php/audit
```

## Usage

### Using the Database Adapter (Default)

The simplest way to use Utopia Audit is with the built-in Database adapter:

```php
<?php

require_once __DIR__ . '/../../vendor/autoload.php';

use PDO;
use Utopia\Audit\Audit;
use Utopia\Cache\Cache;
use Utopia\Cache\Adapter\None as NoCache;
use Utopia\Database\Adapter\MySQL;
use Utopia\Database\Database;
use Utopia\Audit\Adapter\Database as DatabaseAdapter;

$dbHost = '127.0.0.1';
$dbUser = 'travis';
$dbPass = '';
$dbPort = '3306';

$pdo = new PDO("mysql:host={$dbHost};port={$dbPort};charset=utf8mb4", $dbUser, $dbPass, [
    PDO::ATTR_TIMEOUT => 3,
    PDO::ATTR_PERSISTENT => true,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES => true,
    PDO::ATTR_STRINGIFY_FETCHES => true,
]);
        
$cache = new Cache(new NoCache());

$database = new Database(new MySQL($pdo), $cache);
$database->setNamespace('namespace');

// Create audit instance with Database adapter
$audit = new Audit(new DatabaseAdapter($database));
$audit->setup();
```

### Using a Custom Adapter

You can create custom adapters by extending the `Utopia\Audit\Adapter` abstract class:

```php
<?php

use Utopia\Audit\Audit;
use Utopia\Audit\Adapter\Database as DatabaseAdapter;
use Utopia\Database\Database;

// Using the Database adapter directly
$adapter = new DatabaseAdapter($database);
$audit = new Audit($adapter);
```

### Basic Operations

**Create Log**

A simple example for logging a user action in the audit DB.

```php
$userId = 'user-unique-id';
$event = 'deleted'; // Log specific action name
$resource = 'database/document-1'; // Resource unique ID (great for filtering specific logs)
$userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36'; // Set user-agent
$ip = '127.0.0.1'; // User IP
$location = 'US'; // Country name or code
$data = ['key1' => 'value1','key2' => 'value2']; // Any key-value pair you need to log

$audit->log($userId, $event, $resource, $userAgent, $ip, $location, $data);
```

**Get Logs By User**

Fetch all logs by given user ID

```php
$logs = $audit->getLogsByUser(
    'userId' // User unique ID
); // Returns an array of all logs for specific user
```

**Get Logs By User and Action**

Fetch all logs by given user ID and a specific event name

```php
$logs = $audit->getLogsByUserAndEvents( 
    'userId', // User unique ID
    ['update', 'delete'] // List of selected event to fetch
); // Returns an array of all logs for specific user filtered by given actions
```

**Get Logs By Resource**

Fetch all logs by a given resource name

```php
$logs = $audit->getLogsByResource(
    'resource-name', // Resource Name
); // Returns an array of all logs for the specific resource
```

**Batch Logging**

Log multiple events at once for better performance:

```php
use Utopia\Database\DateTime;

$events = [
    [
        'userId' => 'user-1',
        'event' => 'create',
        'resource' => 'database/document/1',
        'userAgent' => 'Mozilla/5.0...',
        'ip' => '127.0.0.1',
        'location' => 'US',
        'data' => ['key' => 'value'],
        'time' => DateTime::now()
    ],
    [
        'userId' => 'user-2',
        'event' => 'update',
        'resource' => 'database/document/2',
        'userAgent' => 'Mozilla/5.0...',
        'ip' => '192.168.1.1',
        'location' => 'UK',
        'data' => ['key' => 'value'],
        'time' => DateTime::now()
    ]
];

$documents = $audit->logBatch($events);
```

## Adapters

Utopia Audit uses an adapter pattern to support different storage backends. Currently available adapters:

### Database Adapter (Default)

The Database adapter uses [utopia-php/database](https://github.com/utopia-php/database) to store audit logs in a database.


### ClickHouse Adapter

The ClickHouse adapter uses [ClickHouse](https://clickhouse.com/) for high-performance analytical queries on massive amounts of log data. It communicates with ClickHouse via HTTP interface using Utopia Fetch.

**Features:**
- Optimized for analytical queries and aggregations
- Handles billions of log entries efficiently
- Column-oriented storage for fast queries
- Automatic partitioning by month
- Bloom filter indexes for fast lookups

**Usage:**

```php
<?php

use Utopia\Audit\Audit;
use Utopia\Audit\Adapter\ClickHouse;

// Create ClickHouse adapter
$adapter = new ClickHouse(
    host: 'localhost',
    database: 'audit',
    username: 'default',
    password: '',
    port: 8123,
    table: 'audit_logs'
);

$audit = new Audit($adapter);
$audit->setup(); // Creates database and table

// Use as normal
$document = $audit->log(
    userId: 'user-123',
    event: 'document.create',
    resource: 'database/document/1',
    userAgent: 'Mozilla/5.0...',
    ip: '127.0.0.1',
    location: 'US',
    data: ['key' => 'value']
);
```

**Performance Benefits:**
- Ideal for high-volume logging (millions of events per day)
- Fast aggregation queries (counts, analytics)
- Efficient storage with compression
- Automatic data partitioning and retention policies

### Creating Custom Adapters

To create a custom adapter, extend the `Utopia\Audit\Adapter` abstract class and implement all required methods:

```php
<?php

namespace MyApp\Audit;

use Utopia\Audit\Adapter;
use Utopia\Database\Document;

class CustomAdapter extends Adapter
{
    public function getName(): string
    {
        return 'Custom';
    }

    public function setup(): void
    {
        // Initialize your storage backend
    }

    public function create(array $log): Document
    {
        // Store a single log entry
    }

    public function createBatch(array $logs): array
    {
        // Store multiple log entries
    }

    public function getByUser(string $userId, array $queries = []): array
    {
        // Retrieve logs by user ID
    }

    // Implement other required methods...
}
```

Then use your custom adapter:

```php
$adapter = new CustomAdapter();
$audit = new Audit($adapter);
```

## System Requirements

Utopia Framework requires PHP 8.0 or later. We recommend using the latest PHP version whenever possible.

## Copyright and license

The MIT License (MIT) [http://www.opensource.org/licenses/mit-license.php](http://www.opensource.org/licenses/mit-license.php)
