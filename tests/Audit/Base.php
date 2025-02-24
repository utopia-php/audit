<?php

namespace Utopia\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\Audit\Adapter;
use Utopia\Audit\Log;
use Utopia\Database\DateTime;

abstract class Base extends TestCase
{
    protected static ?Adapter $adapter;

    public function getAdapter(): ?Adapter
    {
        return self::$adapter;
    }

    public function createLogs(): void
    {
        $log = (new Log())
            ->setData(['key1' => 'value1', 'key2' => 'value2'])
            ->setEvent('update')
            ->setHostname('')
            ->setIp('127.0.0.1')
            ->setLocation('US')
            ->setProjectId('1')
            ->setProjectInternalId('1')
            ->setResource('database/document/1')
            ->setResourceId('db1')
            ->setResourceInternalId('1')
            ->setResourceParent('parent')
            ->setResourceType('database')
            ->setTeamId('1')
            ->setTeamInternalId('1')
            ->setTime(DateTime::now())
            ->setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36')
            ->setUserId('userId')
            ->setUserInternalId('1')
            ->setUserType('anonymous');

        $this->assertTrue($this->getAdapter()->log($log));

        $log = $log
            ->setResource('database/document/2')
            ->setTime(DateTime::now());

        $this->assertTrue($this->getAdapter()->log($log));

        $log = $log
            ->setResource('database/document/2')
            ->setEvent('delete')
            ->setTime(DateTime::now());

        $this->assertTrue($this->getAdapter()->log($log));
    }

    public static function tearDownAfterClass(): void
    {
        static::$adapter->cleanup(DateTime::now());
        static::$adapter = null;
    }

    public function testGetLogsByUser(): void
    {
        $logs = $this->getAdapter()->getLogsByUser('userId');
        $this->assertEquals(3, \count($logs));

        $logsCount = $this->getAdapter()->countLogsByUser('userId');
        $this->assertEquals(3, $logsCount);

        $logs1 = $this->getAdapter()->getLogsByUser('userId', 1, 1);
        $this->assertEquals(1, \count($logs1));
        $this->assertEquals($logs1[0]->getId(), $logs[1]->getId());

        $logs2 = $this->getAdapter()->getLogsByUser('userId', 1, 0, $logs[0]);
        $this->assertEquals(1, \count($logs2));
        $this->assertEquals($logs2[0]->getId(), $logs[1]->getId());
    }

    public function testGetLogsByUserAndEvents(): void
    {
        $logs1 = $this->getAdapter()->getLogsByUserAndEvents('userId', ['update']);
        $logs2 = $this->getAdapter()->getLogsByUserAndEvents('userId', ['update', 'delete']);

        $this->assertEquals(2, \count($logs1));
        $this->assertEquals(3, \count($logs2));

        $logsCount1 = $this->getAdapter()->countLogsByUserAndEvents('userId', ['update']);
        $logsCount2 = $this->getAdapter()->countLogsByUserAndEvents('userId', ['update', 'delete']);

        $this->assertEquals(2, $logsCount1);
        $this->assertEquals(3, $logsCount2);

        $logs3 = $this->getAdapter()->getLogsByUserAndEvents('userId', ['update', 'delete'], 1, 1);

        $this->assertEquals(1, \count($logs3));
        $this->assertEquals($logs3[0]->getId(), $logs2[1]->getId());

        $logs4 = $this->getAdapter()->getLogsByUserAndEvents('userId', ['update', 'delete'], 1, 0, $logs2[0]);

        $this->assertEquals(1, \count($logs4));
        $this->assertEquals($logs4[0]->getId(), $logs2[1]->getId());
    }

    public function testGetLogsByResourceAndEvents(): void
    {
        $logs1 = $this->getAdapter()->getLogsByResourceAndEvents('database/document/1', ['update']);
        $logs2 = $this->getAdapter()->getLogsByResourceAndEvents('database/document/2', ['update', 'delete']);

        $this->assertEquals(1, \count($logs1));
        $this->assertEquals(2, \count($logs2));

        $logsCount1 = $this->getAdapter()->countLogsByResourceAndEvents('database/document/1', ['update']);
        $logsCount2 = $this->getAdapter()->countLogsByResourceAndEvents('database/document/2', ['update', 'delete']);

        $this->assertEquals(1, $logsCount1);
        $this->assertEquals(2, $logsCount2);

        $logs3 = $this->getAdapter()->getLogsByResourceAndEvents('database/document/2', ['update', 'delete'], 1, 1);

        $this->assertEquals(1, \count($logs3));
        $this->assertEquals($logs3[0]->getId(), $logs2[1]->getId());

        $logs4 = $this->getAdapter()->getLogsByResourceAndEvents('database/document/2', ['update', 'delete'], 1, 0, $logs2[0]);

        $this->assertEquals(1, \count($logs4));
        $this->assertEquals($logs4[0]->getId(), $logs2[1]->getId());
    }

    public function testGetLogsByResource(): void
    {
        $logs1 = $this->getAdapter()->getLogsByResource('database/document/1');
        $logs2 = $this->getAdapter()->getLogsByResource('database/document/2');

        $this->assertEquals(1, \count($logs1));
        $this->assertEquals(2, \count($logs2));

        $logsCount1 = $this->getAdapter()->countLogsByResource('database/document/1');
        $logsCount2 = $this->getAdapter()->countLogsByResource('database/document/2');

        $this->assertEquals(1, $logsCount1);
        $this->assertEquals(2, $logsCount2);

        $logs3 = $this->getAdapter()->getLogsByResource('database/document/2', 1, 1);
        $this->assertEquals(1, \count($logs3));
        $this->assertEquals($logs3[0]->getId(), $logs2[1]->getId());

        $logs4 = $this->getAdapter()->getLogsByResource('database/document/2', 1, 0, $logs2[0]);
        $this->assertEquals(1, \count($logs4));
        $this->assertEquals($logs4[0]->getId(), $logs2[1]->getId());
    }

    public function testLogByBatch(): void
    {
        // First cleanup existing logs
        $this->getAdapter()->cleanup(DateTime::now());

        $userId = 'batchUserId';
        $userAgent = 'Mozilla/5.0 (Test User Agent)';
        $ip = '192.168.1.1';
        $location = 'UK';

        // Create timestamps 1 minute apart
        $timestamp1 = DateTime::formatTz(DateTime::addSeconds(new \DateTime(), -120)) ?? '';
        $timestamp2 = DateTime::formatTz(DateTime::addSeconds(new \DateTime(), -60)) ?? '';
        $timestamp3 = DateTime::formatTz(DateTime::now());

        $batchEvents = [
            (new Log())
                ->setData(['key1' => 'value1'])
                ->setEvent('create')
                ->setHostname('')
                ->setIp('127.0.0.1')
                ->setLocation('US')
                ->setProjectId('1')
                ->setProjectInternalId('1')
                ->setResource('database/document/batch1')
                ->setResourceId('db1')
                ->setResourceInternalId('1')
                ->setResourceParent('parent')
                ->setResourceType('database')
                ->setTeamId('1')
                ->setTeamInternalId('1')
                ->setTime($timestamp1)
                ->setUserAgent($userAgent)
                ->setUserId($userId)
                ->setUserInternalId('1')
                ->setUserType('anonymous'),
            (new Log())
                ->setData(['key1' => 'value2'])
                ->setEvent('update')
                ->setHostname('')
                ->setIp('127.0.0.1')
                ->setLocation('US')
                ->setProjectId('1')
                ->setProjectInternalId('1')
                ->setResource('database/document/batch2')
                ->setResourceId('db1')
                ->setResourceInternalId('1')
                ->setResourceParent('parent')
                ->setResourceType('database')
                ->setTeamId('1')
                ->setTeamInternalId('1')
                ->setTime($timestamp2)
                ->setUserAgent($userAgent)
                ->setUserId($userId)
                ->setUserInternalId('1')
                ->setUserType('anonymous'),
            (new Log())
                ->setData(['key1' => 'value3'])
                ->setEvent('delete')
                ->setHostname('')
                ->setIp('127.0.0.1')
                ->setLocation('US')
                ->setProjectId('1')
                ->setProjectInternalId('1')
                ->setResource('database/document/batch3')
                ->setResourceId('db1')
                ->setResourceInternalId('1')
                ->setResourceParent('parent')
                ->setResourceType('database')
                ->setTeamId('1')
                ->setTeamInternalId('1')
                ->setTime($timestamp3)
                ->setUserAgent($userAgent)
                ->setUserId($userId)
                ->setUserInternalId('1')
                ->setUserType('anonymous')
        ];

        // Test batch insertion
        $this->assertTrue($this->getAdapter()->logBatch($batchEvents));

        // Verify the number of logs inserted
        $logs = $this->getAdapter()->getLogsByUser($userId);
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
        $resourceLogs = $this->getAdapter()->getLogsByResource('database/document/batch2');
        $this->assertEquals(1, count($resourceLogs));
        $this->assertEquals('update', $resourceLogs[0]->getAttribute('event'));

        // Test event-based retrieval
        $eventLogs = $this->getAdapter()->getLogsByUserAndEvents($userId, ['create', 'delete']);
        $this->assertEquals(2, count($eventLogs));
    }

    public function testCleanup(): void
    {
        sleep(3);
        // First delete all the logs
        $status = $this->getAdapter()->cleanup(DateTime::now());
        $this->assertEquals($status, true);

        // Check that all logs have been deleted
        $logs = $this->getAdapter()->getLogsByUser('userId');
        $this->assertEquals(0, \count($logs));

        // Add three sample logs
        $log = (new Log())
            ->setData(['key1' => 'value1', 'key2' => 'value2'])
            ->setEvent('update')
            ->setHostname('')
            ->setIp('127.0.0.1')
            ->setLocation('US')
            ->setProjectId('1')
            ->setProjectInternalId('1')
            ->setResource('database/document/1')
            ->setResourceId('db1')
            ->setResourceInternalId('1')
            ->setResourceParent('parent')
            ->setResourceType('database')
            ->setTeamId('1')
            ->setTeamInternalId('1')
            ->setTime(DateTime::now())
            ->setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36')
            ->setUserId('userId')
            ->setUserInternalId('1')
            ->setUserType('anonymous');

        $this->assertEquals($this->getAdapter()->log($log), true);
        sleep(5);

        $log = (new Log())
            ->setData(['key1' => 'value1', 'key2' => 'value2'])
            ->setEvent('update')
            ->setHostname('')
            ->setIp('127.0.0.1')
            ->setLocation('US')
            ->setProjectId('1')
            ->setProjectInternalId('1')
            ->setResource('database/document/2')
            ->setResourceId('db1')
            ->setResourceInternalId('1')
            ->setResourceParent('parent')
            ->setResourceType('database')
            ->setTeamId('1')
            ->setTeamInternalId('1')
            ->setTime(DateTime::now())
            ->setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36')
            ->setUserId('userId')
            ->setUserInternalId('1')
            ->setUserType('anonymous');

        $this->assertEquals($this->getAdapter()->log($log), true);
        sleep(5);

        $log = (new Log())
            ->setData(['key1' => 'value1', 'key2' => 'value2'])
            ->setEvent('update')
            ->setHostname('')
            ->setIp('127.0.0.1')
            ->setLocation('US')
            ->setProjectId('1')
            ->setProjectInternalId('1')
            ->setResource('database/document/3')
            ->setResourceId('db1')
            ->setResourceInternalId('1')
            ->setResourceParent('parent')
            ->setResourceType('database')
            ->setTeamId('1')
            ->setTeamInternalId('1')
            ->setTime(DateTime::now())
            ->setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36')
            ->setUserId('userId')
            ->setUserInternalId('1')
            ->setUserType('anonymous');

        $this->assertEquals($this->getAdapter()->log($log), true);
        sleep(5);

        // DELETE logs older than 11 seconds and check that status is true
        $status = $this->getAdapter()->cleanup(DateTime::addSeconds(new \DateTime(), -11));
        $this->assertEquals($status, true);

        // Check if 1 log has been deleted
        $logs = $this->getAdapter()->getLogsByUser('userId');
        $this->assertEquals(2, \count($logs));
    }
}
