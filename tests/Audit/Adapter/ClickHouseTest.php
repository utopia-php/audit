<?php

namespace Utopia\Tests\Audit\Adapter;

use Exception;
use PHPUnit\Framework\TestCase;
use Utopia\Audit\Adapter\ClickHouse;
use Utopia\Audit\Audit;
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
        $attributeIds = array_map(fn($attr) => $attr['$id'], $attributes);

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
        $indexIds = array_map(fn($idx) => $idx['$id'], $indexes);

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
}
