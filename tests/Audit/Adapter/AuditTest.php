<?php

namespace Utopia\Tests\Adapter;

use PDO;
use Utopia\Audit\Adapter\Audit;
use Utopia\Cache\Adapter\None as NoCache;
use Utopia\Cache\Cache;
use Utopia\Database\Adapter\MariaDB;
use Utopia\Database\Database;
use Utopia\Tests\Base;

class AuditTest extends Base
{
    protected Audit $audit;

    public function setUp(): void
    {
        if (isset(static::$adapter)) {
            return;
        }

        $dbHost = 'mariadb';
        $dbPort = '3306';
        $dbUser = 'root';
        $dbPass = 'password';

        $pdo = new PDO("mysql:host={$dbHost};port={$dbPort};charset=utf8mb4", $dbUser, $dbPass, MariaDB::getPdoAttributes());

        $cache = new Cache(new NoCache());

        $database = (new Database(new MariaDB($pdo), $cache))
            ->setDatabase('utopiaTests')
            ->setNamespace('namespace');

        static::$adapter = new Audit($database);

        if ($database->exists('utopiaTests')) {
            $database->delete('utopiaTests');
        }

        $database->create('utopiaTests');

        $this->getAdapter()?->setup();

        $this->createLogs();
    }
}
