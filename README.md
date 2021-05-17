# Utopia Audit

[![Build Status](https://travis-ci.org/utopia-php/audit.svg?branch=master)](https://travis-ci.com/utopia-php/audit)
![Total Downloads](https://img.shields.io/packagist/dt/utopia-php/audit.svg)
[![Discord](https://img.shields.io/discord/564160730845151244)](https://appwrite.io/discord)

Utopia framework audit library is simple and lite library for managing application user logs. This library is aiming to be as simple and easy to learn and use. This library is maintained by the [Appwrite team](https://appwrite.io).

Although this library is part of the [Utopia Framework](https://github.com/utopia-php/framework) project it is dependency free, and can be used as standalone with any other PHP project or framework.

## Getting Started

Install using composer:
```bash
composer require utopia-php/audit
```

Init the audit object:

```php
<?php

require_once __DIR__ . '/../../vendor/autoload.php';

use PDO;
use PDO;
use Utopia\Audit\Audit;
use Utopia\Cache\Cache;
use Utopia\Cache\Adapter\None as NoCache;
use Utopia\Database\Adapter\MySQL;
use Utopia\Database\Database;


$dbHost = '127.0.0.1';
$dbUser = 'travis';
$dbPass = '';

$pdo = new PDO("mysql:host={$dbHost}", $dbUser, $dbPass, array(
    PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8',
    PDO::ATTR_TIMEOUT => 5 // Seconds
));

// Connection settings
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);   // Return arrays
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);        // Handle all errors with exceptions 

$cache = new Cache(new NoCache());

$database = new Database(new MySQL($pdo),$cache);
$database->setNamespace('namespace');

$audit = new Audit($database);
$audit->setup();
```

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

Fetch all logs by given user ID and a specific action name

```php
$logs = $audit->getLogsByUserAndActions(
    'userId', // User unique ID
    ['update', 'delete'] // List of selected action to fetch
); // Returns an array of all logs for specific user filtered by given actions
```

**Get Logs By Resource**

Fetch all logs by a given resource name

```php
$logs = $audit->getLogsByResource(
    'resource-name', // Resource Name
); // Returns an array of all logs for the specific resource
```

## System Requirements

Utopia Framework requires PHP 7.4 or later. We recommend using the latest PHP version whenever possible.

## Authors

**Eldad Fux**

+ [https://twitter.com/eldadfux](https://twitter.com/eldadfux)
+ [https://github.com/eldadfux](https://github.com/eldadfux)

## Copyright and license

The MIT License (MIT) [http://www.opensource.org/licenses/mit-license.php](http://www.opensource.org/licenses/mit-license.php)
