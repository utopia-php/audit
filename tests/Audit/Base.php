<?php

namespace Utopia\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\Audit\Adapter;
use Utopia\Audit\Log;
use Utopia\Database\DateTime;

abstract class Base extends TestCase
{
    protected Adapter $adapter;

    public function tearDown(): void
    {
        $this->adapter->cleanup(DateTime::now());
    }

    public function createLogs(): void
    {
        $userId = 'userId';
        $userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36';
        $ip = '127.0.0.1';
        $location = 'US';
        $data = ['key1' => 'value1', 'key2' => 'value2'];

        $log = (new Log())
            ->setUserId($userId)
            ->setUserAgent($userAgent)
            ->setIp($ip)
            ->setLocation($location)
            ->setResource('database/document/1')
            ->setEvent('update')
            ->setData($data);

        $this->assertTrue($this->adapter->log($log));

        $log = (new Log())
            ->setUserId($userId)
            ->setUserAgent($userAgent)
            ->setIp($ip)
            ->setLocation($location)
            ->setResource('database/document/2')
            ->setEvent('update')
            ->setData($data);

        $this->assertTrue($this->adapter->log($log));

        $log = (new Log())
            ->setUserId($userId)
            ->setUserAgent($userAgent)
            ->setIp($ip)
            ->setLocation($location)
            ->setResource('database/document/2')
            ->setEvent('delete')
            ->setData($data);

        $this->assertTrue($this->adapter->log($log));
    }

    public function testGetLogsByUser(): void
    {
        $logs = $this->adapter->getLogsByUser('userId');
        $this->assertEquals(3, \count($logs));

        $logsCount = $this->adapter->countLogsByUser('userId');
        $this->assertEquals(3, $logsCount);

        $logs1 = $this->adapter->getLogsByUser('userId', 1, 1);
        $this->assertEquals(1, \count($logs1));
        $this->assertEquals($logs1[0]->getId(), $logs[1]->getId());

        $logs2 = $this->adapter->getLogsByUser('userId', 1, 0, $logs[0]);
        $this->assertEquals(1, \count($logs2));
        $this->assertEquals($logs2[0]->getId(), $logs[1]->getId());
    }

    public function testGetLogsByUserAndEvents(): void
    {
        $logs1 = $this->adapter->getLogsByUserAndEvents('userId', ['update']);
        $logs2 = $this->adapter->getLogsByUserAndEvents('userId', ['update', 'delete']);

        $this->assertEquals(2, \count($logs1));
        $this->assertEquals(3, \count($logs2));

        $logsCount1 = $this->adapter->countLogsByUserAndEvents('userId', ['update']);
        $logsCount2 = $this->adapter->countLogsByUserAndEvents('userId', ['update', 'delete']);

        $this->assertEquals(2, $logsCount1);
        $this->assertEquals(3, $logsCount2);

        $logs3 = $this->adapter->getLogsByUserAndEvents('userId', ['update', 'delete'], 1, 1);

        $this->assertEquals(1, \count($logs3));
        $this->assertEquals($logs3[0]->getId(), $logs2[1]->getId());

        $logs4 = $this->adapter->getLogsByUserAndEvents('userId', ['update', 'delete'], 1, 0, $logs2[0]);

        $this->assertEquals(1, \count($logs4));
        $this->assertEquals($logs4[0]->getId(), $logs2[1]->getId());
    }

    public function testGetLogsByResourceAndEvents(): void
    {
        $logs1 = $this->adapter->getLogsByResourceAndEvents('database/document/1', ['update']);
        $logs2 = $this->adapter->getLogsByResourceAndEvents('database/document/2', ['update', 'delete']);

        $this->assertEquals(1, \count($logs1));
        $this->assertEquals(2, \count($logs2));

        $logsCount1 = $this->adapter->countLogsByResourceAndEvents('database/document/1', ['update']);
        $logsCount2 = $this->adapter->countLogsByResourceAndEvents('database/document/2', ['update', 'delete']);

        $this->assertEquals(1, $logsCount1);
        $this->assertEquals(2, $logsCount2);

        $logs3 = $this->adapter->getLogsByResourceAndEvents('database/document/2', ['update', 'delete'], 1, 1);

        $this->assertEquals(1, \count($logs3));
        $this->assertEquals($logs3[0]->getId(), $logs2[1]->getId());

        $logs4 = $this->adapter->getLogsByResourceAndEvents('database/document/2', ['update', 'delete'], 1, 0, $logs2[0]);

        $this->assertEquals(1, \count($logs4));
        $this->assertEquals($logs4[0]->getId(), $logs2[1]->getId());
    }

    public function testGetLogsByResource(): void
    {
        $logs1 = $this->adapter->getLogsByResource('database/document/1');
        $logs2 = $this->adapter->getLogsByResource('database/document/2');

        $this->assertEquals(1, \count($logs1));
        $this->assertEquals(2, \count($logs2));

        $logsCount1 = $this->adapter->countLogsByResource('database/document/1');
        $logsCount2 = $this->adapter->countLogsByResource('database/document/2');

        $this->assertEquals(1, $logsCount1);
        $this->assertEquals(2, $logsCount2);

        $logs3 = $this->adapter->getLogsByResource('database/document/2', 1, 1);
        $this->assertEquals(1, \count($logs3));
        $this->assertEquals($logs3[0]->getId(), $logs2[1]->getId());

        $logs4 = $this->adapter->getLogsByResource('database/document/2', 1, 0, $logs2[0]);
        $this->assertEquals(1, \count($logs4));
        $this->assertEquals($logs4[0]->getId(), $logs2[1]->getId());
    }

    public function testLogByBatch(): void
    {
        // First cleanup existing logs
        $this->adapter->cleanup(DateTime::now());

        $userId = 'batchUserId';
        $userAgent = 'Mozilla/5.0 (Test User Agent)';
        $ip = '192.168.1.1';
        $location = 'UK';

        // Create timestamps 1 minute apart
        $timestamp1 = \date_add(new \DateTime(), new \DateInterval('PT-120S'));
        $timestamp2 = \date_add(new \DateTime(), new \DateInterval('PT-60S'));
        $timestamp3 = new \DateTime();

        $batchEvents = [
            (new Log())
                ->setUserId($userId)
                ->setEvent('create')
                ->setResource('database/document/batch1')
                ->setUserAgent($userAgent)
                ->setIp($ip)
                ->setLocation($location)
                ->setData(['key' => 'value1'])
                ->setTime($timestamp1),
            (new Log())
                ->setUserId($userId)
                ->setEvent('update')
                ->setResource('database/document/batch2')
                ->setUserAgent($userAgent)
                ->setIp($ip)
                ->setLocation($location)
                ->setData(['key' => 'value2'])
                ->setTime($timestamp2),
            (new Log())
                ->setUserId($userId)
                ->setEvent('delete')
                ->setResource('database/document/batch3')
                ->setUserAgent($userAgent)
                ->setIp($ip)
                ->setLocation($location)
                ->setData(['key' => 'value3'])
                ->setTime($timestamp3),
        ];

        // Test batch insertion
        $this->assertTrue($this->adapter->logBatch($batchEvents));

        // Verify the number of logs inserted
        $logs = $this->adapter->getLogsByUser($userId);
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
        $resourceLogs = $this->adapter->getLogsByResource('database/document/batch2');
        $this->assertEquals(1, count($resourceLogs));
        $this->assertEquals('update', $resourceLogs[0]->getAttribute('event'));

        // Test event-based retrieval
        $eventLogs = $this->adapter->getLogsByUserAndEvents($userId, ['create', 'delete']);
        $this->assertEquals(2, count($eventLogs));
    }

    public function testCleanup(): void
    {
        sleep(3);
        // First delete all the logs
        $status = $this->adapter->cleanup(DateTime::now());
        $this->assertEquals($status, true);

        // Check that all logs have been deleted
        $logs = $this->adapter->getLogsByUser('userId');
        $this->assertEquals(0, \count($logs));

        // Add three sample logs
        $log = (new Log())
            ->setUserId('userId')
            ->setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36')
            ->setIp('127.0.0.1')
            ->setLocation('US')
            ->setResource('database/document/1')
            ->setEvent('update')
            ->setData(['key1' => 'value1', 'key2' => 'value2']);

        $this->assertEquals($this->adapter->log($log), true);
        sleep(5);

        $log = (new Log())
            ->setUserId('userId')
            ->setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36')
            ->setIp('127.0.0.1')
            ->setLocation('US')
            ->setResource('database/document/2')
            ->setEvent('update')
            ->setData(['key1' => 'value1', 'key2' => 'value2']);

        $this->assertEquals($this->adapter->log($log), true);
        sleep(5);

        $log = (new Log())
            ->setUserId('userId')
            ->setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36')
            ->setIp('127.0.0.1')
            ->setLocation('US')
            ->setResource('database/document/2')
            ->setEvent('delete')
            ->setData(['key1' => 'value1', 'key2' => 'value2']);

        $this->assertEquals($this->adapter->log($log), true);
        sleep(5);

        // DELETE logs older than 11 seconds and check that status is true
        $status = $this->adapter->cleanup(DateTime::addSeconds(new \DateTime(), -11));
        $this->assertEquals($status, true);

        // Check if 1 log has been deleted
        $logs = $this->adapter->getLogsByUser('userId');
        $this->assertEquals(2, \count($logs));
    }
}
