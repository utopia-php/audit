<?php

namespace Utopia\Tests\Audit\Adapter;

use Exception;
use PHPUnit\Framework\TestCase;
use Utopia\Audit\Adapter\ClickHouse;
use Utopia\Audit\Audit;
use Utopia\Audit\Query;
use Utopia\Tests\Audit\AuditBase;

/**
 * ClickHouse Adapter Tests
 *
 * Tests ClickHouse-specific features and configurations.
 * Generic audit functionality tests are in AuditBase trait.
 */
class ClickHouseTest extends TestCase
{
    use AuditBase;

    protected function initializeAudit(): void
    {
        $clickHouse = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse',
            port: 8123
        );

        $clickHouse->setDatabase('default');

        $this->audit = new Audit($clickHouse);
        $this->audit->setup();
    }

    /**
     * Test constructor validates host
     */
    public function testConstructorValidatesHost(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('ClickHouse host is not a valid hostname or IP address');

        new ClickHouse(
            host: '',
            username: 'default',
            password: ''
        );
    }

    /**
     * Test constructor validates port range
     */
    public function testConstructorValidatesPortTooLow(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('ClickHouse port must be between 1 and 65535');

        new ClickHouse(
            host: 'localhost',
            username: 'default',
            password: '',
            port: 0
        );
    }

    /**
     * Test constructor validates port range upper bound
     */
    public function testConstructorValidatesPortTooHigh(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('ClickHouse port must be between 1 and 65535');

        new ClickHouse(
            host: 'localhost',
            username: 'default',
            password: '',
            port: 65536
        );
    }

    /**
     * Test constructor with valid parameters
     */
    public function testConstructorWithValidParameters(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'testuser',
            password: 'testpass',
            port: 8443,
            secure: true
        );

        $this->assertInstanceOf(ClickHouse::class, $adapter);
        $this->assertEquals('ClickHouse', $adapter->getName());
    }

    /**
     * Test getName returns correct adapter name
     */
    public function testGetName(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $this->assertEquals('ClickHouse', $adapter->getName());
    }

    /**
     * Test setDatabase validates empty identifier
     */
    public function testSetDatabaseValidatesEmpty(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Database cannot be empty');

        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $adapter->setDatabase('');
    }

    /**
     * Test setDatabase validates identifier length
     */
    public function testSetDatabaseValidatesLength(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Database cannot exceed 255 characters');

        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $adapter->setDatabase(str_repeat('a', 256));
    }

    /**
     * Test setDatabase validates identifier format
     */
    public function testSetDatabaseValidatesFormat(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Database must start with a letter or underscore');

        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $adapter->setDatabase('123invalid');
    }

    /**
     * Test setDatabase rejects SQL keywords
     */
    public function testSetDatabaseRejectsKeywords(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Database cannot be a reserved SQL keyword');

        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $adapter->setDatabase('SELECT');
    }

    /**
     * Test setDatabase with valid identifier
     */
    public function testSetDatabaseWithValidIdentifier(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $result = $adapter->setDatabase('my_database_123');
        $this->assertInstanceOf(ClickHouse::class, $result);
    }

    /**
     * Test setNamespace allows empty string
     */
    public function testSetNamespaceAllowsEmpty(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $result = $adapter->setNamespace('');
        $this->assertInstanceOf(ClickHouse::class, $result);
        $this->assertEquals('', $adapter->getNamespace());
    }

    /**
     * Test setNamespace validates identifier format
     */
    public function testSetNamespaceValidatesFormat(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Namespace must start with a letter or underscore');

        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $adapter->setNamespace('9invalid');
    }

    /**
     * Test setNamespace with valid identifier
     */
    public function testSetNamespaceWithValidIdentifier(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $result = $adapter->setNamespace('project_123');
        $this->assertInstanceOf(ClickHouse::class, $result);
        $this->assertEquals('project_123', $adapter->getNamespace());
    }

    /**
     * Test setSecure method
     */
    public function testSetSecure(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse',
            port: 8123,
            secure: false
        );

        $result = $adapter->setSecure(true);
        $this->assertInstanceOf(ClickHouse::class, $result);
    }

    /**
     * Test shared tables configuration
     */
    public function testSharedTablesConfiguration(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        // Test initial state
        $this->assertFalse($adapter->isSharedTables());
        $this->assertNull($adapter->getTenant());

        // Test setting shared tables
        $result = $adapter->setSharedTables(true);
        $this->assertInstanceOf(ClickHouse::class, $result);
        $this->assertTrue($adapter->isSharedTables());

        // Test setting tenant
        $result2 = $adapter->setTenant(12345);
        $this->assertInstanceOf(ClickHouse::class, $result2);
        $this->assertEquals(12345, $adapter->getTenant());

        // Test setting tenant to null
        $adapter->setTenant(null);
        $this->assertNull($adapter->getTenant());
    }

    /**
     * Test batch operations with special characters
     */
    public function testBatchOperationsWithSpecialCharacters(): void
    {
        // Test batch with special characters in data
        $batchEvents = [
            [
                'userId' => 'user`with`backticks',
                'event' => 'create',
                'resource' => 'doc/"quotes"',
                'userAgent' => "User'Agent\"With'Quotes",
                'ip' => '192.168.1.1',
                'location' => 'UK',
                'data' => ['special' => "data with 'quotes'"],
                'time' => \Utopia\Database\DateTime::formatTz(\Utopia\Database\DateTime::now()) ?? ''
            ]
        ];

        $result = $this->audit->logBatch($batchEvents);
        $this->assertTrue($result);

        // Verify retrieval
        $logs = $this->audit->getLogsByUser('user`with`backticks');
        $this->assertGreaterThan(0, count($logs));
    }

    /**
     * Test that ClickHouse adapter has all required attributes
     */
    public function testClickHouseAdapterAttributes(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $attributes = $adapter->getAttributes();
        $attributeIds = array_map(fn ($attr) => $attr['$id'], $attributes);

        // Verify all expected attributes exist
        $expectedAttributes = [
            'userType',
            'userId',
            'userInternalId',
            'resourceParent',
            'resourceType',
            'resourceId',
            'resourceInternalId',
            'event',
            'resource',
            'userAgent',
            'ip',
            'country',
            'time',
            'data',
            'projectId',
            'projectInternalId',
            'teamId',
            'teamInternalId',
            'hostname'
        ];

        foreach ($expectedAttributes as $expected) {
            $this->assertContains($expected, $attributeIds, "Attribute '{$expected}' not found in ClickHouse adapter");
        }
    }

    /**
     * Test that ClickHouse adapter has all required indexes
     */
    public function testClickHouseAdapterIndexes(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $indexes = $adapter->getIndexes();
        $indexIds = array_map(fn ($idx) => $idx['$id'], $indexes);

        // Verify all ClickHouse-specific indexes exist
        $expectedClickHouseIndexes = [
            '_key_user_internal_and_event',
            '_key_project_internal_id',
            '_key_team_internal_id',
            '_key_user_internal_id',
            '_key_user_type',
            '_key_country',
            '_key_hostname'
        ];

        foreach ($expectedClickHouseIndexes as $expected) {
            $this->assertContains($expected, $indexIds, "ClickHouse index '{$expected}' not found in ClickHouse adapter");
        }

        // Verify parent indexes are also included (with parent naming convention)
        $parentExpectedIndexes = ['idx_event', 'idx_userId_event', 'idx_resource_event', 'idx_time_desc'];
        foreach ($parentExpectedIndexes as $expected) {
            $this->assertContains($expected, $indexIds, "Parent index '{$expected}' not found in ClickHouse adapter");
        }
    }

    /**
     * Test find method with simple query
     */
    public function testFindWithSimpleQuery(): void
    {
        // Create test data
        $this->audit->log(
            userId: 'testuser1',
            event: 'create',
            resource: 'document/123',
            userAgent: 'Test Agent',
            ip: '192.168.1.1',
            location: 'US',
            data: ['action' => 'test']
        );

        $this->audit->log(
            userId: 'testuser2',
            event: 'update',
            resource: 'document/456',
            userAgent: 'Test Agent',
            ip: '192.168.1.2',
            location: 'UK',
            data: ['action' => 'test']
        );

        /** @var ClickHouse $adapter */
        $adapter = $this->audit->getAdapter();

        // Test equal query
        $logs = $adapter->find([
            Query::equal('userId', 'testuser1')
        ]);

        $this->assertIsArray($logs);
        $this->assertGreaterThan(0, count($logs));

        foreach ($logs as $log) {
            $this->assertEquals('testuser1', $log->getAttribute('userId'));
        }
    }

    /**
     * Test find method with multiple filters
     */
    public function testFindWithMultipleFilters(): void
    {
        // Create test data
        $this->audit->log(
            userId: 'user123',
            event: 'create',
            resource: 'collection/test',
            userAgent: 'Test Agent',
            ip: '10.0.0.1',
            location: 'US',
            data: []
        );

        $this->audit->log(
            userId: 'user123',
            event: 'delete',
            resource: 'collection/test2',
            userAgent: 'Test Agent',
            ip: '10.0.0.1',
            location: 'US',
            data: []
        );

        /** @var ClickHouse $adapter */
        $adapter = $this->audit->getAdapter();

        // Test with multiple filters
        $logs = $adapter->find([
            Query::equal('userId', 'user123'),
            Query::equal('event', 'create')
        ]);

        $this->assertIsArray($logs);
        $this->assertGreaterThan(0, count($logs));

        foreach ($logs as $log) {
            $this->assertEquals('user123', $log->getAttribute('userId'));
            $this->assertEquals('create', $log->getAttribute('event'));
        }
    }

    /**
     * Test find method with IN query
     */
    public function testFindWithInQuery(): void
    {
        // Create test data
        $events = ['login', 'logout', 'create'];
        foreach ($events as $event) {
            $this->audit->log(
                userId: 'userMulti',
                event: $event,
                resource: 'test',
                userAgent: 'Test Agent',
                ip: '127.0.0.1',
                location: 'US',
                data: []
            );
        }

        /** @var ClickHouse $adapter */
        $adapter = $this->audit->getAdapter();

        // Test IN query
        $logs = $adapter->find([
            Query::equal('userId', 'userMulti'),
            Query::in('event', ['login', 'logout'])
        ]);

        $this->assertIsArray($logs);
        $this->assertCount(2, $logs);

        foreach ($logs as $log) {
            $this->assertContains($log->getAttribute('event'), ['login', 'logout']);
        }
    }

    /**
     * Test find method with ordering
     */
    public function testFindWithOrdering(): void
    {
        // Create test data with different events
        $this->audit->log(
            userId: 'orderUser',
            event: 'zzz_event',
            resource: 'test',
            userAgent: 'Test Agent',
            ip: '127.0.0.1',
            location: 'US',
            data: []
        );

        sleep(1); // Ensure different timestamps

        $this->audit->log(
            userId: 'orderUser',
            event: 'aaa_event',
            resource: 'test',
            userAgent: 'Test Agent',
            ip: '127.0.0.1',
            location: 'US',
            data: []
        );

        /** @var ClickHouse $adapter */
        $adapter = $this->audit->getAdapter();

        // Test ascending order
        $logs = $adapter->find([
            Query::equal('userId', 'orderUser'),
            Query::orderAsc('event')
        ]);

        $this->assertIsArray($logs);
        $this->assertGreaterThanOrEqual(2, count($logs));
        $this->assertEquals('aaa_event', $logs[0]->getAttribute('event'));

        // Test descending order
        $logs = $adapter->find([
            Query::equal('userId', 'orderUser'),
            Query::orderDesc('event')
        ]);

        $this->assertIsArray($logs);
        $this->assertGreaterThanOrEqual(2, count($logs));
        $this->assertEquals('zzz_event', $logs[0]->getAttribute('event'));
    }

    /**
     * Test find method with limit and offset
     */
    public function testFindWithLimitAndOffset(): void
    {
        // Create multiple test logs
        for ($i = 1; $i <= 5; $i++) {
            $this->audit->log(
                userId: 'paginationUser',
                event: "event_{$i}",
                resource: "resource_{$i}",
                userAgent: 'Test Agent',
                ip: '127.0.0.1',
                location: 'US',
                data: ['index' => $i]
            );
        }

        /** @var ClickHouse $adapter */
        $adapter = $this->audit->getAdapter();

        // Test limit
        $logs = $adapter->find([
            Query::equal('userId', 'paginationUser'),
            Query::limit(2)
        ]);

        $this->assertIsArray($logs);
        $this->assertCount(2, $logs);

        // Test offset
        $logs = $adapter->find([
            Query::equal('userId', 'paginationUser'),
            Query::orderAsc('event'),
            Query::limit(2),
            Query::offset(2)
        ]);

        $this->assertIsArray($logs);
        $this->assertLessThanOrEqual(2, count($logs));
    }

    /**
     * Test find method with between query
     */
    public function testFindWithBetweenQuery(): void
    {
        $time1 = '2023-01-01 00:00:00+00:00';
        $time2 = '2023-06-01 00:00:00+00:00';
        $time3 = '2023-12-31 23:59:59+00:00';

        // Create test data with different times using logBatch
        $this->audit->logBatch([
            [
                'userId' => 'betweenUser',
                'event' => 'event1',
                'resource' => 'test',
                'userAgent' => 'Test Agent',
                'ip' => '127.0.0.1',
                'location' => 'US',
                'data' => [],
                'time' => $time1
            ],
            [
                'userId' => 'betweenUser',
                'event' => 'event2',
                'resource' => 'test',
                'userAgent' => 'Test Agent',
                'ip' => '127.0.0.1',
                'location' => 'US',
                'data' => [],
                'time' => $time2
            ],
            [
                'userId' => 'betweenUser',
                'event' => 'event3',
                'resource' => 'test',
                'userAgent' => 'Test Agent',
                'ip' => '127.0.0.1',
                'location' => 'US',
                'data' => [],
                'time' => $time3
            ]
        ]);

        /** @var ClickHouse $adapter */
        $adapter = $this->audit->getAdapter();

        // Test between query
        $logs = $adapter->find([
            Query::equal('userId', 'betweenUser'),
            Query::between('time', '2023-05-01 00:00:00+00:00', '2023-12-31 00:00:00+00:00')
        ]);

        $this->assertIsArray($logs);
        $this->assertGreaterThan(0, count($logs));
    }
}
