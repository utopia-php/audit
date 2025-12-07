<?php

namespace Utopia\Tests;

use PDO;
use PHPUnit\Framework\TestCase;
use Utopia\Audit\Audit;
use Utopia\Cache\Adapter\None as NoCache;
use Utopia\Cache\Cache;
use Utopia\Database\Adapter\MariaDB;
use Utopia\Database\Database;
use Utopia\Audit\Adapter;

/**
 * Database Adapter Tests
 *
 * Tests the Audit library using the Database adapter (MariaDB/MySQL)
 */
class AuditDatabaseTest extends TestCase
{
    use AuditBase;

    protected function initializeAudit(): void
    {
        $dbHost = 'mariadb';
        $dbPort = '3306';
        $dbUser = 'root';
        $dbPass = 'password';

        $pdo = new PDO("mysql:host={$dbHost};port={$dbPort};charset=utf8mb4", $dbUser, $dbPass, MariaDB::getPdoAttributes());
        $cache = new Cache(new NoCache());
        $database = new Database(new MariaDB($pdo), $cache);
        $database->setDatabase('utopiaTests');
        $database->setNamespace('namespace');

        $adapter = new Adapter\Database($database);
        $this->audit = new Audit($adapter);
        if (! $database->exists('utopiaTests')) {
            $database->create();
            $this->audit->setup();
        }
    }
}
