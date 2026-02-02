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
     * Test compression setting validation with invalid type
     */
    public function testSetCompressionValidatesInvalidType(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid compression type 'invalid'");

        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $adapter->setCompression('invalid');
    }

    /**
     * Test constructor with invalid compression type
     */
    public function testConstructorValidatesInvalidCompression(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid compression type 'bzip2'");

        new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse',
            compression: 'bzip2'
        );
    }

    /**
     * Test valid compression types
     */
    public function testCompressionSettings(): void
    {
        // Test constructor with each valid compression type
        $adapterNone = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse',
            compression: ClickHouse::COMPRESSION_NONE
        );
        $this->assertEquals(ClickHouse::COMPRESSION_NONE, $adapterNone->getCompression());

        $adapterGzip = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse',
            compression: ClickHouse::COMPRESSION_GZIP
        );
        $this->assertEquals(ClickHouse::COMPRESSION_GZIP, $adapterGzip->getCompression());

        $adapterLz4 = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse',
            compression: ClickHouse::COMPRESSION_LZ4
        );
        $this->assertEquals(ClickHouse::COMPRESSION_LZ4, $adapterLz4->getCompression());

        // Test setter method
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $result = $adapter->setCompression(ClickHouse::COMPRESSION_GZIP);
        $this->assertInstanceOf(ClickHouse::class, $result);
        $this->assertEquals(ClickHouse::COMPRESSION_GZIP, $adapter->getCompression());

        $adapter->setCompression(ClickHouse::COMPRESSION_NONE);
        $this->assertEquals(ClickHouse::COMPRESSION_NONE, $adapter->getCompression());
    }

    /**
     * Test timeout validation - too low
     */
    public function testTimeoutValidationTooLow(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Timeout must be between');

        new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse',
            timeout: 500 // Below minimum of 1000ms
        );
    }

    /**
     * Test timeout validation - too high
     */
    public function testTimeoutValidationTooHigh(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Timeout must be between');

        new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse',
            timeout: 700_000 // Above maximum of 600000ms
        );
    }

    /**
     * Test valid timeout settings
     */
    public function testTimeoutSettings(): void
    {
        // Test constructor with custom timeout
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse',
            timeout: 60_000
        );
        $this->assertEquals(60_000, $adapter->getTimeout());

        // Test setter method
        $result = $adapter->setTimeout(120_000);
        $this->assertInstanceOf(ClickHouse::class, $result);
        $this->assertEquals(120_000, $adapter->getTimeout());
    }

    /**
     * Test setTimeout validates range
     */
    public function testSetTimeoutValidatesRange(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Timeout must be between');

        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $adapter->setTimeout(100); // Below minimum
    }

    /**
     * Test ping method returns true for healthy connection
     */
    public function testPingHealthyConnection(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $result = $adapter->ping();
        $this->assertTrue($result);
    }

    /**
     * Test ping method returns false for bad connection
     */
    public function testPingUnhealthyConnection(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'wrongpassword'
        );

        // Should return false instead of throwing exception
        $result = $adapter->ping();
        $this->assertFalse($result);
    }

    /**
     * Test getServerVersion returns version string
     */
    public function testGetServerVersion(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse'
        );

        $version = $adapter->getServerVersion();
        $this->assertNotNull($version);
        $this->assertIsString($version);
        // ClickHouse version format: XX.Y.Z.W
        $this->assertMatchesRegularExpression('/^\d+\.\d+/', $version);
    }

    /**
     * Test getServerVersion returns null for bad connection
     */
    public function testGetServerVersionBadConnection(): void
    {
        $adapter = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'wrongpassword'
        );

        $version = $adapter->getServerVersion();
        $this->assertNull($version);
    }

    /**
     * Test that operations work with gzip compression enabled
     */
    public function testOperationsWithGzipCompression(): void
    {
        $clickHouse = new ClickHouse(
            host: 'clickhouse',
            username: 'default',
            password: 'clickhouse',
            port: 8123,
            compression: ClickHouse::COMPRESSION_GZIP
        );

        $clickHouse->setDatabase('default');
        $clickHouse->setNamespace('gzip_test');

        $audit = new \Utopia\Audit\Audit($clickHouse);
        $audit->setup();

        // Test single log insertion with compression
        $requiredAttributes = $this->getRequiredAttributes();
        $data = array_merge(['test' => 'gzip_compression'], $requiredAttributes);

        $log = $audit->log(
            'gzipuser',
            'create',
            'document/gzip1',
            'Mozilla/5.0',
            '127.0.0.1',
            'US',
            $data
        );

        $this->assertInstanceOf(\Utopia\Audit\Log::class, $log);
        $this->assertEquals('gzipuser', $log->getAttribute('userId'));

        // Test batch insertion with compression
        $batchEvents = [
            [
                'userId' => 'gzipuser',
                'event' => 'update',
                'resource' => 'document/gzip2',
                'userAgent' => 'Mozilla/5.0',
                'ip' => '127.0.0.1',
                'location' => 'US',
                'data' => ['batch' => 'gzip'],
                'time' => \Utopia\Database\DateTime::formatTz(\Utopia\Database\DateTime::now()) ?? ''
            ]
        ];
        $batchEvents = $this->applyRequiredAttributesToBatch($batchEvents);

        $result = $audit->logBatch($batchEvents);
        $this->assertTrue($result);

        // Verify retrieval works
        $logs = $audit->getLogsByUser('gzipuser');
        $this->assertGreaterThanOrEqual(2, count($logs));

        // Cleanup
        $audit->cleanup(new \DateTime('+1 hour'));
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
}
