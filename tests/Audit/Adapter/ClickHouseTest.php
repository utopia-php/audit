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
            'actorType' => 'member',
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
     * Test setTable validates empty identifier
     */
    public function testSetTableValidatesEmpty(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Table cannot be empty');

        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $adapter->setTable('');
    }

    /**
     * Test setTable validates identifier length
     */
    public function testSetTableValidatesLength(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Table cannot exceed 255 characters');

        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $adapter->setTable(str_repeat('a', 256));
    }

    /**
     * Test setTable validates identifier format
     */
    public function testSetTableValidatesFormat(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Table must start with a letter or underscore');

        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $adapter->setTable('123invalid');
    }

    /**
     * Test setTable rejects SQL keywords
     */
    public function testSetTableRejectsKeywords(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Table cannot be a reserved SQL keyword');

        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $adapter->setTable('SELECT');
    }

    /**
     * Test setTable with valid identifier
     */
    public function testSetTableWithValidIdentifier(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $result = $adapter->setTable('my_audit_logs');
        $this->assertInstanceOf(ClickHouse::class, $result);
        $this->assertEquals('my_audit_logs', $adapter->getTable());
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
                'actorId' => 'actor`with`backticks',
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
        $logs = $this->audit->getLogsByUser('actor`with`backticks');
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
            'actorType',
            'actorId',
            'actorInternalId',
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
            '_key_actor_internal_and_event',
            '_key_project_internal_id',
            '_key_team_internal_id',
            '_key_actor_internal_id',
            '_key_actor_type',
            '_key_country',
            '_key_hostname'
        ];

        foreach ($expectedClickHouseIndexes as $expected) {
            $this->assertContains($expected, $indexIds, "ClickHouse index '{$expected}' not found in ClickHouse adapter");
        }

        // Verify parent indexes are also included (with parent naming convention)
        $parentExpectedIndexes = ['idx_event', 'idx_actorId_event', 'idx_resource_event', 'idx_time_desc'];
        foreach ($parentExpectedIndexes as $expected) {
            $this->assertContains($expected, $indexIds, "Parent index '{$expected}' not found in ClickHouse adapter");
        }
    }

    /**
     * Test parsing of complex resource paths into resourceType/resourceId/resourceParent
     */
    public function testParseResourceComplexPath(): void
    {
        $actorId = 'parseActor';
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

        $log = $this->audit->log($actorId, 'create', $resource, $userAgent, $ip, $location, $dataWithAttributes);

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

    public function testNotEqualQuery(): void
    {
        // Fixture: 3x event=update/delete for actor, plus 1x event=insert for null actor
        $logs = $this->audit->find([
            Query::notEqual('event', 'update'),
        ]);
        // 1 delete + 1 insert = 2
        $this->assertCount(2, $logs);
        foreach ($logs as $log) {
            $this->assertNotEquals('update', $log->getEvent());
        }
    }

    public function testNotContainsQuery(): void
    {
        $logs = $this->audit->find([
            Query::notContains('event', ['update', 'delete']),
        ]);
        // Only the insert log
        $this->assertCount(1, $logs);
        $this->assertEquals('insert', $logs[0]->getEvent());
    }

    public function testLesserEqualAndGreaterEqualQueries(): void
    {
        $now = (new \DateTime())->modify('+1 minute');
        $past = (new \DateTime())->modify('-1 hour');

        $allLe = $this->audit->find([
            Query::lessThanEqual('time', \Utopia\Database\DateTime::format($now)),
        ]);
        $this->assertGreaterThanOrEqual(4, count($allLe));

        $noneLe = $this->audit->find([
            Query::lessThanEqual('time', \Utopia\Database\DateTime::format($past)),
        ]);
        $this->assertCount(0, $noneLe);

        $allGe = $this->audit->find([
            Query::greaterThanEqual('time', \Utopia\Database\DateTime::format($past)),
        ]);
        $this->assertGreaterThanOrEqual(4, count($allGe));
    }

    public function testNotBetweenQuery(): void
    {
        $past = (new \DateTime())->modify('-2 hour');
        $oldPast = (new \DateTime())->modify('-3 hour');

        $logs = $this->audit->find([
            Query::notBetween(
                'time',
                \Utopia\Database\DateTime::format($oldPast),
                \Utopia\Database\DateTime::format($past),
            ),
        ]);
        // All 4 fixture logs are outside the past window
        $this->assertGreaterThanOrEqual(4, count($logs));
    }

    public function testIsNullAndIsNotNullQueries(): void
    {
        $nullActor = $this->audit->find([
            Query::isNull('actorId'),
        ]);
        // Only the insert log has null actorId
        $this->assertCount(1, $nullActor);
        $this->assertEquals('insert', $nullActor[0]->getEvent());

        $notNullActor = $this->audit->find([
            Query::isNotNull('actorId'),
        ]);
        $this->assertCount(3, $notNullActor);
    }

    public function testStartsWithAndEndsWithQueries(): void
    {
        $resourcePrefix = $this->audit->find([
            Query::startsWith('resource', 'database/'),
        ]);
        // 3 logs are on database/document/*
        $this->assertCount(3, $resourcePrefix);
        foreach ($resourcePrefix as $log) {
            $this->assertStringStartsWith('database/', $log->getResource());
        }

        $endsWithNull = $this->audit->find([
            Query::endsWith('resource', '/null'),
        ]);
        // 'user/null' is the only match
        $this->assertCount(1, $endsWithNull);
        $this->assertEquals('user/null', $endsWithNull[0]->getResource());
    }

    public function testContainsRejectsEmptyValues(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Contains queries require at least one value.');

        $this->audit->find([
            Query::contains('event', []),
        ]);
    }

    public function testNotContainsRejectsEmptyValues(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('NotContains queries require at least one value.');

        $this->audit->find([
            Query::notContains('event', []),
        ]);
    }

    public function testEqualRejectsEmptyValues(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Equal queries require at least one value.');

        $this->audit->find([
            new Query(Query::TYPE_EQUAL, 'event', []),
        ]);
    }

    public function testSelectProjectsRequestedColumns(): void
    {
        $logs = $this->audit->find([
            Query::select(['event', 'resource']),
            Query::equal('actorId', 'userId'),
            Query::limit(1),
        ]);

        $this->assertGreaterThanOrEqual(1, count($logs));

        $row = $logs[0]->getArrayCopy();
        // `id` is always projected so the Log model still has its identifier
        $this->assertArrayHasKey('$id', $row);
        // Requested columns present
        $this->assertArrayHasKey('event', $row);
        $this->assertArrayHasKey('resource', $row);
        // Unrequested columns are absent
        $this->assertArrayNotHasKey('userAgent', $row);
        $this->assertArrayNotHasKey('ip', $row);
        $this->assertArrayNotHasKey('data', $row);
    }

    public function testSelectAutoIncludesTenantWhenShared(): void
    {
        $host = getenv('CLICKHOUSE_HOST') ?: 'clickhouse';
        $port = (int) (getenv('CLICKHOUSE_PORT') ?: 8123);

        $adapter = new ClickHouse(
            host: $host,
            username: 'default',
            password: 'clickhouse',
            port: $port,
        );
        $adapter->setNamespace('select_tenant_test');
        $adapter->setSharedTables(true);
        $adapter->setTenant(7);
        $adapter->setup();

        $audit = new Audit($adapter);
        $audit->log('u1', 'create', 'doc/1', 'agent', '127.0.0.1', 'US', $this->getRequiredAttributes());

        $logs = $audit->find([
            Query::select(['event']),
            Query::limit(1),
        ]);

        $this->assertCount(1, $logs);
        $row = $logs[0]->getArrayCopy();
        $this->assertArrayHasKey('$id', $row);
        $this->assertArrayHasKey('event', $row);
        // tenant is always projected when sharedTables is on, even if the
        // caller didn't list it
        $this->assertArrayHasKey('tenant', $row);
    }

    public function testSelectRejectsUnknownColumn(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid attribute name: bogus_column');

        $this->audit->find([
            Query::select(['bogus_column']),
        ]);
    }

    public function testSelectRejectsEmptyValues(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Select queries require at least one value.');

        $this->audit->find([
            Query::select([]),
        ]);
    }

    public function testNotStartsWithFilter(): void
    {
        $logs = $this->audit->find([
            Query::notStartsWith('resource', 'database/'),
        ]);
        // From fixture: only 'user/null' doesn't start with 'database/'
        $this->assertCount(1, $logs);
        $this->assertEquals('user/null', $logs[0]->getResource());
    }

    public function testNotEndsWithFilter(): void
    {
        $logs = $this->audit->find([
            Query::notEndsWith('resource', '/null'),
        ]);
        // From fixture: 3 logs are on database/document/{1,2,2}
        $this->assertCount(3, $logs);
        foreach ($logs as $log) {
            $this->assertStringStartsNotWith('user/', $log->getResource());
        }
    }

    public function testRegexFilter(): void
    {
        $logs = $this->audit->find([
            Query::regex('resource', '^database/document/\\d+$'),
        ]);
        // From fixture: 3 database/document/{1,2,2} rows match
        $this->assertCount(3, $logs);
    }

    public function testOrderRandomReturnsRows(): void
    {
        $logs = $this->audit->find([
            Query::orderRandom(),
            Query::limit(2),
        ]);
        // Hard to assert randomness; just confirm the query executes and limits.
        $this->assertCount(2, $logs);
    }

    public function testOrderRandomRejectedWithCursor(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Cursor pagination cannot be combined with orderRandom');

        $this->audit->find([
            Query::orderRandom(),
            Query::cursorAfter(['id' => 'whatever']),
        ]);
    }

    public function testOrderRandomRejectedWithColumnOrder(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('orderRandom cannot be combined with orderAsc/orderDesc');

        $this->audit->find([
            Query::orderRandom(),
            Query::orderDesc('time'),
        ]);
    }
}
