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
        $host = getenv('CLICKHOUSE_HOST') ?: 'clickhouse';
        $username = getenv('CLICKHOUSE_USER') ?: 'default';
        $password = getenv('CLICKHOUSE_PASSWORD') ?: 'clickhouse';
        $port = (int) (getenv('CLICKHOUSE_PORT') ?: 8123);
        $secure = (bool) (getenv('CLICKHOUSE_SECURE') ?: false);

        $clickHouse = new ClickHouse(
            host: $host,
            username: $username,
            password: $password,
            port: $port,
            secure: $secure
        );

        if ($database = getenv('CLICKHOUSE_DATABASE')) {
            $clickHouse->setDatabase($database);
        } else {
            $clickHouse->setDatabase('default');
        }

        $this->audit = new Audit($clickHouse);
        $this->audit->setup();
    }

    /**
     * Provide required attributes for ClickHouse adapter tests.
     *
     * @return array<string, mixed>
     */
    protected function getRequiredAttributes(): array
    {
        return [
            'userType' => 'member',
            'resourceType' => 'document',
            'resourceId' => 'res-1',
            'projectId' => 'proj-1',
            'projectInternalId' => 'proj-int-1',
            'teamId' => 'team-1',
            'teamInternalId' => 'team-int-1',
            'hostname' => 'example.org',
        ];
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

        $batchEvents = $this->applyRequiredAttributesToBatch($batchEvents);
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
     * Test parsing of complex resource paths into resourceType/resourceId/resourceParent
     */
    public function testParseResourceComplexPath(): void
    {
        $userId = 'parseUser';
        $userAgent = 'UnitTestAgent/1.0';
        $ip = '127.0.0.1';
        $location = 'US';

        $resource = 'database/6978484940ff05762e1a/table/697848498066e3d2ef64';

        // Ensure we don't provide resourceType/resourceId in data so adapter must parse it
        $data = ['example' => 'value'];

        // Merge required adapter attributes so ClickHouse won't reject the log,
        // but ensure we do NOT supply resourceType/resourceId/resourceParent so adapter parses them
        $required = $this->getRequiredAttributes();
        unset($required['resourceType'], $required['resourceId'], $required['resourceParent']);
        $dataWithAttributes = array_merge($data, $required);

        $log = $this->audit->log($userId, 'create', $resource, $userAgent, $ip, $location, $dataWithAttributes);

        $this->assertInstanceOf(\Utopia\Audit\Log::class, $log);

        $this->assertEquals('table', $log->getAttribute('resourceType'));
        $this->assertEquals('697848498066e3d2ef64', $log->getAttribute('resourceId'));
        $this->assertEquals('database/6978484940ff05762e1a', $log->getAttribute('resourceParent'));
    }

    /**
     * Directly test the protected parseResource method via reflection.
     */
    public function testParseResourceMethod(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $method = new \ReflectionMethod($adapter, 'parseResource');
        $method->setAccessible(true);

        $resource = 'database/6978484940ff05762e1a/table/697848498066e3d2ef64';
        $parsed = $method->invoke($adapter, $resource);

        $this->assertIsArray($parsed);
        $this->assertArrayHasKey('resourceId', $parsed);
        $this->assertArrayHasKey('resourceType', $parsed);
        $this->assertArrayHasKey('resourceParent', $parsed);

        $this->assertEquals('697848498066e3d2ef64', $parsed['resourceId']);
        $this->assertEquals('table', $parsed['resourceType']);
        $this->assertEquals('database/6978484940ff05762e1a', $parsed['resourceParent']);
    }

    public function testCursorAfterPaginatesLogs(): void
    {
        $page1 = $this->audit->find([
            Query::orderAsc('id'),
            Query::limit(2),
        ]);

        $this->assertCount(2, $page1);

        $page2 = $this->audit->find([
            Query::orderAsc('id'),
            Query::limit(2),
            Query::cursorAfter($page1[count($page1) - 1]),
        ]);

        $this->assertGreaterThanOrEqual(1, count($page2));
        foreach ($page2 as $log) {
            $this->assertNotEquals($page1[0]->getId(), $log->getId());
            $this->assertNotEquals($page1[1]->getId(), $log->getId());
        }
    }

    public function testCursorBeforeReversesPagination(): void
    {
        $all = $this->audit->find([
            Query::orderAsc('id'),
            Query::limit(50),
        ]);

        $this->assertGreaterThanOrEqual(3, count($all));

        $before = $this->audit->find([
            Query::orderAsc('id'),
            Query::limit(2),
            Query::cursorBefore($all[count($all) - 1]),
        ]);

        $this->assertCount(2, $before);
        $this->assertEquals($all[count($all) - 3]->getId(), $before[0]->getId());
        $this->assertEquals($all[count($all) - 2]->getId(), $before[1]->getId());
    }

    public function testCursorAcceptsAssociativeArray(): void
    {
        $all = $this->audit->find([
            Query::orderAsc('id'),
            Query::limit(50),
        ]);

        $this->assertGreaterThanOrEqual(2, count($all));

        $page = $this->audit->find([
            Query::orderAsc('id'),
            Query::limit(50),
            Query::cursorAfter(['id' => $all[0]->getId()]),
        ]);

        $this->assertEquals(count($all) - 1, count($page));
        $this->assertEquals($all[1]->getId(), $page[0]->getId());
    }

    public function testCountWithMaxBound(): void
    {
        $unbounded = $this->audit->count();
        $this->assertGreaterThanOrEqual(4, $unbounded);

        $bounded = $this->audit->count([], max: 2);
        $this->assertEquals(2, $bounded);

        $boundedAboveTotal = $this->audit->count([], max: 10_000);
        $this->assertEquals($unbounded, $boundedAboveTotal);
    }

    public function testCountByUserWithMaxBound(): void
    {
        $unbounded = $this->audit->countLogsByUser('userId');
        $this->assertEquals(3, $unbounded);

        $bounded = $this->audit->countLogsByUser('userId', max: 1);
        $this->assertEquals(1, $bounded);
    }
}
