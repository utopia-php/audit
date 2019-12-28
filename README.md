# Utopia Audit

[![Build Status](https://travis-ci.org/utopia-php/audit.svg?branch=master)](https://travis-ci.org/utopia-php/audit)
![Total Downloads](https://img.shields.io/packagist/dt/utopia-php/audit.svg)
[![Discord](https://img.shields.io/discord/564160730845151244)](https://discord.gg/GSeTUeA)

Utopia framework audit library is simple and lite library for managing application user logs. This library is aiming to be as simple and easy to learn and use.

Although this library is part of the [Utopia Framework](https://github.com/utopia-php/framework) project it is dependency free, and can be used as standalone with any other PHP project or framework.

## Getting Started

Install using composer:
```bash
composer require utopia-php/audit
```

**Log Action**

A simple example for logging a user action in the audit DB.

```php
<?php

require_once __DIR__ . '/../../vendor/autoload.php';

use Utopia\Abuse\Abuse;
use Utopia\Abuse\Adapters\TimeLimit;

// Limit login attempts to 10 time in 5 minutes time frame
$adapter    = new TimeLimit('login-attempt-from-{{ip}}', 10, (60 * 5), function () {/* init and return PDO connection... */});

$adapter
    ->setNamespace('namespace') // DB table namespace
    ->setParam('{{ip}}', '127.0.0.1')
;

$abuse      = new Abuse($adapter);

// Use vars to resolve adapter key

if(!$abuse->check()) {
    throw new Exception('Service was abused!'); // throw error and return X-Rate limit headers here
}
```

**Get Logs By User**

Fetch all logs by given user ID

```php
<?php

require_once __DIR__ . '/../../vendor/autoload.php';

use Utopia\Abuse\Abuse;
use Utopia\Abuse\Adapters\ReCaptcha;

// Limit login attempts to 10 time in 5 minutes time frame
$adapter    = new ReCaptcha('secret-api-key', $_POST['g-recaptcha-response'], $_SERVER['REMOTE_ADDR']);
$abuse      = new Abuse($adapter);

if(!$abuse->check()) {
    throw new Exception('Service was abused!'); // throw error and return X-Rate limit headers here
}
```

**Get Logs By User and Action**

Fetch all logs by given user ID and a specific action name

```php
<?php

require_once __DIR__ . '/../../vendor/autoload.php';

use Utopia\Abuse\Abuse;
use Utopia\Abuse\Adapters\ReCaptcha;

// Limit login attempts to 10 time in 5 minutes time frame
$adapter    = new ReCaptcha('secret-api-key', $_POST['g-recaptcha-response'], $_SERVER['REMOTE_ADDR']);
$abuse      = new Abuse($adapter);

if(!$abuse->check()) {
    throw new Exception('Service was abused!'); // throw error and return X-Rate limit headers here
}
```

## System Requirements

Utopia Framework requires PHP 7.0 or later. We recommend using the latest PHP version whenever possible.

## Authors

**Eldad Fux**

+ [https://twitter.com/eldadfux](https://twitter.com/eldadfux)
+ [https://github.com/eldadfux](https://github.com/eldadfux)

## Copyright and license

The MIT License (MIT) [http://www.opensource.org/licenses/mit-license.php](http://www.opensource.org/licenses/mit-license.php)