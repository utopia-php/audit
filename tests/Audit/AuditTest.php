<?php

namespace Utopia\Tests;

use PDO;
use PHPUnit\Framework\TestCase;
use Utopia\Audit\Audit;
use Utopia\Cache\Adapter\None as NoCache;
use Utopia\Cache\Cache;
use Utopia\Database\Adapter\MariaDB;
use Utopia\Database\Database;
use Utopia\Database\DateTime;
use Utopia\Database\Query;

class AuditTest extends TestCase
{
    protected Audit $audit;

    public function setUp(): void
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

        $this->audit = new Audit($database);
        if (! $database->exists('utopiaTests')) {
            $database->create();
            $this->audit->setup();
        }

        $this->createLogs();
    }

    public function tearDown(): void
    {
        $this->audit->cleanup(DateTime::now());
    }

    public function createLogs(): void
    {
        $userId = 'userId';
        $userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36';
        $ip = '127.0.0.1';
        $location = 'US';
        $data = ['key1' => 'value1', 'key2' => 'value2'];

        $this->assertTrue($this->audit->log($userId, 'update', 'database/document/1', $userAgent, $ip, $location, $data));
        $this->assertTrue($this->audit->log($userId, 'update', 'database/document/2', $userAgent, $ip, $location, $data));
        $this->assertTrue($this->audit->log($userId, 'delete', 'database/document/2', $userAgent, $ip, $location, $data));
        $this->assertTrue($this->audit->log(null, 'insert', 'user/null', $userAgent, $ip, $location, $data));
    }

    public function testGetLogsByUser(): void
    {
        $logs = $this->audit->getLogsByUser('userId');
        $this->assertEquals(3, \count($logs));

        $logsCount = $this->audit->countLogsByUser('userId');
        $this->assertEquals(3, $logsCount);

        $logs1 = $this->audit->getLogsByUser('userId', [Query::limit(1), Query::offset(1)]);
        $this->assertEquals(1, \count($logs1));
        $this->assertEquals($logs1[0]->getId(), $logs[1]->getId());

        $logs2 = $this->audit->getLogsByUser('userId', [Query::limit(1), Query::offset(1)]);
        $this->assertEquals(1, \count($logs2));
        $this->assertEquals($logs2[0]->getId(), $logs[1]->getId());
    }

    public function testGetLogsByUserAndEvents(): void
    {
        $logs1 = $this->audit->getLogsByUserAndEvents('userId', ['update']);
        $logs2 = $this->audit->getLogsByUserAndEvents('userId', ['update', 'delete']);

        $this->assertEquals(2, \count($logs1));
        $this->assertEquals(3, \count($logs2));

        $logsCount1 = $this->audit->countLogsByUserAndEvents('userId', ['update']);
        $logsCount2 = $this->audit->countLogsByUserAndEvents('userId', ['update', 'delete']);

        $this->assertEquals(2, $logsCount1);
        $this->assertEquals(3, $logsCount2);

        $logs3 = $this->audit->getLogsByUserAndEvents('userId', ['update', 'delete'], [Query::limit(1), Query::offset(1)]);

        $this->assertEquals(1, \count($logs3));
        $this->assertEquals($logs3[0]->getId(), $logs2[1]->getId());

        $logs4 = $this->audit->getLogsByUserAndEvents('userId', ['update', 'delete'], [Query::limit(1), Query::offset(1)]);

        $this->assertEquals(1, \count($logs4));
        $this->assertEquals($logs4[0]->getId(), $logs2[1]->getId());
    }

    public function testGetLogsByResourceAndEvents(): void
    {
        $logs1 = $this->audit->getLogsByResourceAndEvents('database/document/1', ['update']);
        $logs2 = $this->audit->getLogsByResourceAndEvents('database/document/2', ['update', 'delete']);

        $this->assertEquals(1, \count($logs1));
        $this->assertEquals(2, \count($logs2));

        $logsCount1 = $this->audit->countLogsByResourceAndEvents('database/document/1', ['update']);
        $logsCount2 = $this->audit->countLogsByResourceAndEvents('database/document/2', ['update', 'delete']);

        $this->assertEquals(1, $logsCount1);
        $this->assertEquals(2, $logsCount2);

        $logs3 = $this->audit->getLogsByResourceAndEvents('database/document/2', ['update', 'delete'], [Query::limit(1), Query::offset(1)]);

        $this->assertEquals(1, \count($logs3));
        $this->assertEquals($logs3[0]->getId(), $logs2[1]->getId());

        $logs4 = $this->audit->getLogsByResourceAndEvents('database/document/2', ['update', 'delete'], [Query::limit(1), Query::offset(1)]);

        $this->assertEquals(1, \count($logs4));
        $this->assertEquals($logs4[0]->getId(), $logs2[1]->getId());
    }

    public function testGetLogsByResource(): void
    {
        $logs1 = $this->audit->getLogsByResource('database/document/1');
        $logs2 = $this->audit->getLogsByResource('database/document/2');

        $this->assertEquals(1, \count($logs1));
        $this->assertEquals(2, \count($logs2));

        $logsCount1 = $this->audit->countLogsByResource('database/document/1');
        $logsCount2 = $this->audit->countLogsByResource('database/document/2');

        $this->assertEquals(1, $logsCount1);
        $this->assertEquals(2, $logsCount2);

        $logs3 = $this->audit->getLogsByResource('database/document/2', [Query::limit(1), Query::offset(1)]);
        $this->assertEquals(1, \count($logs3));
        $this->assertEquals($logs3[0]->getId(), $logs2[1]->getId());

        $logs4 = $this->audit->getLogsByResource('database/document/2', [Query::limit(1), Query::offset(1)]);
        $this->assertEquals(1, \count($logs4));
        $this->assertEquals($logs4[0]->getId(), $logs2[1]->getId());

        $logs5 = $this->audit->getLogsByResource('user/null');
        $this->assertEquals(1, \count($logs5));
        $this->assertNull($logs5[0]['userId']);
        $this->assertEquals('127.0.0.1', $logs5[0]['ip']);
    }

    public function testLogByBatch(): void
    {
        // First cleanup existing logs
        $this->audit->cleanup(DateTime::now());

        $userId = 'batchUserId';
        $userAgent = 'Mozilla/5.0 (Test User Agent)';
        $ip = '192.168.1.1';
        $location = 'UK';

        // Create timestamps 1 minute apart
        $timestamp1 = DateTime::formatTz(DateTime::addSeconds(new \DateTime(), -120)) ?? '';
        $timestamp2 = DateTime::formatTz(DateTime::addSeconds(new \DateTime(), -60)) ?? '';
        $timestamp3 = DateTime::formatTz(DateTime::now()) ?? '';

        $batchEvents = [
            [
                'userId' => $userId,
                'event' => 'create',
                'resource' => 'database/document/batch1',
                'userAgent' => $userAgent,
                'ip' => $ip,
                'location' => $location,
                'data' => ['key' => 'value1'],
                'timestamp' => $timestamp1
            ],
            [
                'userId' => $userId,
                'event' => 'update',
                'resource' => 'database/document/batch2',
                'userAgent' => $userAgent,
                'ip' => $ip,
                'location' => $location,
                'data' => ['key' => 'value2'],
                'timestamp' => $timestamp2
            ],
            [
                'userId' => $userId,
                'event' => 'delete',
                'resource' => 'database/document/batch3',
                'userAgent' => $userAgent,
                'ip' => $ip,
                'location' => $location,
                'data' => ['key' => 'value3'],
                'timestamp' => $timestamp3
            ],
            [
                'userId' => null,
                'event' => 'insert',
                'resource' => 'user1/null',
                'userAgent' => $userAgent,
                'ip' => $ip,
                'location' => $location,
                'data' => ['key' => 'value4'],
                'timestamp' => $timestamp3
            ]
        ];

        // Test batch insertion
        $this->assertTrue($this->audit->logBatch($batchEvents));

        // Verify the number of logs inserted
        $logs = $this->audit->getLogsByUser($userId);
        $this->assertEquals(3, count($logs));

        // Verify chronological order (newest first due to orderDesc)
        $this->assertEquals('delete', $logs[0]->getAttribute('event'));
        $this->assertEquals('update', $logs[1]->getAttribute('event'));
        $this->assertEquals('create', $logs[2]->getAttribute('event'));

        // Verify timestamps were preserved
        $this->assertEquals($timestamp3, $logs[0]->getAttribute('time'));
        $this->assertEquals($timestamp2, $logs[1]->getAttribute('time'));
        $this->assertEquals($timestamp1, $logs[2]->getAttribute('time'));

        // Test resource-based retrieval
        $resourceLogs = $this->audit->getLogsByResource('database/document/batch2');
        $this->assertEquals(1, count($resourceLogs));
        $this->assertEquals('update', $resourceLogs[0]->getAttribute('event'));

        // Test resource with userId null
        $resourceLogs = $this->audit->getLogsByResource('user1/null');
        $this->assertEquals(1, count($resourceLogs));
        foreach ($resourceLogs as $log) {
            $this->assertEquals('insert', $log->getAttribute('event'));
            $this->assertNull($log['userId']);
        }

        // Test event-based retrieval
        $eventLogs = $this->audit->getLogsByUserAndEvents($userId, ['create', 'delete']);
        $this->assertEquals(2, count($eventLogs));
    }

    public function testGetLogsCustomFilters(): void
    {
        $logs = $this->audit->getLogsByUser('userId', queries: [
            Query::greaterThan('time', DateTime::addSeconds(new \DateTime(), -10))
        ]);

        $this->assertEquals(3, \count($logs));
    }

    public function testCleanup(): void
    {
        sleep(3);
        // First delete all the logs
        $status = $this->audit->cleanup(DateTime::now());
        $this->assertEquals($status, true);

        // Check that all logs have been deleted
        $logs = $this->audit->getLogsByUser('userId');
        $this->assertEquals(0, \count($logs));

        // Add three sample logs
        $userId = 'userId';
        $userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36';
        $ip = '127.0.0.1';
        $location = 'US';
        $data = ['key1' => 'value1', 'key2' => 'value2'];

        $this->assertEquals($this->audit->log($userId, 'update', 'database/document/1', $userAgent, $ip, $location, $data), true);
        sleep(5);
        $this->assertEquals($this->audit->log($userId, 'update', 'database/document/2', $userAgent, $ip, $location, $data), true);
        sleep(5);
        $this->assertEquals($this->audit->log($userId, 'delete', 'database/document/2', $userAgent, $ip, $location, $data), true);
        sleep(5);

        // DELETE logs older than 11 seconds and check that status is true
        $status = $this->audit->cleanup(DateTime::addSeconds(new \DateTime(), -11));
        $this->assertEquals($status, true);

        // Check if 1 log has been deleted
        $logs = $this->audit->getLogsByUser('userId');
        $this->assertEquals(2, \count($logs));
    }
}
