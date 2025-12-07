<?php

namespace Utopia\Audit\Adapter;

use Exception;
use Utopia\Database\Document;
use Utopia\Fetch\Client;

/**
 * ClickHouse Adapter for Audit
 *
 * This adapter stores audit logs in ClickHouse using HTTP interface.
 * ClickHouse is optimized for analytical queries and can handle massive amounts of log data.
 */
class ClickHouse extends SQL
{
    private const DEFAULT_PORT = 8123;

    private const DEFAULT_TABLE = 'audits';

    private string $host;

    private int $port;

    private string $database;

    private string $table;

    private string $username;

    private string $password;

    protected string $namespace = '';

    protected ?int $tenant = null;

    protected bool $sharedTables = false;

    /**
     * @param string $host ClickHouse host
     * @param string $database ClickHouse database name
     * @param string $username ClickHouse username (default: 'default')
     * @param string $password ClickHouse password (default: '')
     * @param int $port ClickHouse HTTP port (default: 8123)
     * @param string $table Table name for audit logs (default: 'audits')
     */
    public function __construct(
        string $host,
        string $database,
        string $username = 'default',
        string $password = '',
        int $port = self::DEFAULT_PORT,
        string $table = self::DEFAULT_TABLE
    ) {
        $this->host = $host;
        $this->port = $port;
        $this->database = $database;
        $this->table = $table;
        $this->username = $username;
        $this->password = $password;
    }

    /**
     * Get adapter name.
     */
    public function getName(): string
    {
        return 'ClickHouse';
    }

    /**
     * Set the namespace for multi-project support.
     * Namespace is used as a prefix for table names.
     *
     * @param string $namespace
     * @return self
     */
    public function setNamespace(string $namespace): self
    {
        $this->namespace = $namespace;
        return $this;
    }

    /**
     * Get the namespace.
     *
     * @return string
     */
    public function getNamespace(): string
    {
        return $this->namespace;
    }

    /**
     * Set the tenant ID for multi-tenant support.
     * Tenant is used to isolate audit logs by tenant.
     *
     * @param int|null $tenant
     * @return self
     */
    public function setTenant(?int $tenant): self
    {
        $this->tenant = $tenant;
        return $this;
    }

    /**
     * Get the tenant ID.
     *
     * @return int|null
     */
    public function getTenant(): ?int
    {
        return $this->tenant;
    }

    /**
     * Set whether tables are shared across tenants.
     * When enabled, a tenant column is added to the table for data isolation.
     *
     * @param bool $sharedTables
     * @return self
     */
    public function setSharedTables(bool $sharedTables): self
    {
        $this->sharedTables = $sharedTables;
        return $this;
    }

    /**
     * Get whether tables are shared across tenants.
     *
     * @return bool
     */
    public function isSharedTables(): bool
    {
        return $this->sharedTables;
    }

    /**
     * Get the table name with namespace prefix.
     * Namespace is used to isolate tables for different projects/applications.
     *
     * @return string
     */
    private function getTableName(): string
    {
        $tableName = $this->table;

        if (!empty($this->namespace)) {
            $tableName = $this->namespace . '_' . $tableName;
        }

        return $tableName;
    }

    /**
     * Format timestamp for ClickHouse DateTime64.
     * Removes timezone information and ensures proper format.
     *
     * @param string $timestamp
     * @return string
     */
    private function formatTimestamp(string $timestamp): string
    {
        // Remove timezone suffix (e.g., +00:00, Z) if present
        // ClickHouse expects format: 2025-12-07 23:19:29.056
        $timestamp = preg_replace('/([+-]\d{2}:\d{2}|Z)$/', '', $timestamp);
        // Replace T with space if present
        $timestamp = str_replace('T', ' ', $timestamp);
        return $timestamp ?? '';
    }

    /**
     * Execute a ClickHouse query via HTTP interface using Fetch Client.
     *
     * @param array<string, mixed> $params
     * @throws Exception
     */
    private function query(string $sql, array $params = []): string
    {
        $url = "http://{$this->host}:{$this->port}/";

        // Replace parameters in query
        foreach ($params as $key => $value) {
            if (is_int($value) || is_float($value)) {
                // Numeric values should not be quoted
                $strValue = (string) $value;
            } elseif (is_string($value)) {
                $strValue = "'" . addslashes($value) . "'";
            } elseif (is_null($value)) {
                $strValue = 'NULL';
            } elseif (is_bool($value)) {
                $strValue = $value ? '1' : '0';
            } elseif (is_array($value)) {
                $encoded = json_encode($value);
                if (is_string($encoded)) {
                    $strValue = "'" . addslashes($encoded) . "'";
                } else {
                    $strValue = 'NULL';
                }
            } else {
                /** @var scalar $value */
                $strValue = "'" . addslashes((string) $value) . "'";
            }
            $sql = str_replace(":{$key}", $strValue, $sql);
        }

        // Build headers with authentication
        $client = new Client();
        $client->addHeader('X-ClickHouse-User', $this->username);
        $client->addHeader('X-ClickHouse-Key', $this->password);
        $client->addHeader('X-ClickHouse-Database', $this->database);
        $client->setTimeout(30);

        try {
            $response = $client->fetch(
                url: $url,
                method: Client::METHOD_POST,
                body: ['query' => $sql]
            );

            if ($response->getStatusCode() !== 200) {
                $body = $response->getBody();
                $bodyStr = is_string($body) ? $body : '';
                throw new Exception("ClickHouse query failed (HTTP {$response->getStatusCode()}): {$bodyStr}");
            }

            $body = $response->getBody();
            return is_string($body) ? $body : '';
        } catch (Exception $e) {
            throw new Exception("ClickHouse connection error: {$e->getMessage()}");
        }
    }

    /**
     * Setup ClickHouse table structure.
     *
     * Creates the database and table if they don't exist.
     * Uses schema definitions from the base SQL adapter.
     *
     * @throws Exception
     */
    public function setup(): void
    {
        // Create database if not exists
        $createDbSql = "CREATE DATABASE IF NOT EXISTS {$this->database}";
        $this->query($createDbSql);

        // Build column definitions from base adapter schema
        // Override time column to be NOT NULL since it's used in partition key
        $columns = [
            'id String',
        ];

        foreach ($this->getAttributes() as $attribute) {
            /** @var string $id */
            $id = $attribute['$id'];

            // Special handling for time column - must be NOT NULL for partition key
            if ($id === 'time') {
                $columns[] = 'time DateTime64(3)';
            } else {
                $columns[] = $this->getColumnDefinition($id);
            }
        }

        // Add tenant column only if tables are shared across tenants
        if ($this->sharedTables) {
            $columns[] = 'tenant Nullable(UInt64)';  // Supports 11-digit MySQL auto-increment IDs
        }

        // Build indexes from base adapter schema
        $indexes = [];
        foreach ($this->getIndexes() as $index) {
            /** @var string $indexName */
            $indexName = $index['$id'];
            /** @var array<string> $attributes */
            $attributes = $index['attributes'];
            $attributeList = implode(', ', $attributes);
            $indexes[] = "INDEX {$indexName} ({$attributeList}) TYPE bloom_filter GRANULARITY 1";
        }

        $tableName = $this->getTableName();

        // Create table with MergeTree engine for optimal performance
        $createTableSql = "
            CREATE TABLE IF NOT EXISTS {$this->database}.{$tableName} (
                " . implode(",\n                ", $columns) . ",
                " . implode(",\n                ", $indexes) . "
            )
            ENGINE = MergeTree()
            ORDER BY (time, id)
            PARTITION BY toYYYYMM(time)
            SETTINGS index_granularity = 8192
        ";

        $this->query($createTableSql);
    }

    /**
     * Create an audit log entry.
     *
     * @throws Exception
     */
    public function create(array $log): Document
    {
        $id = uniqid('audit_', true);
        // Format: 2025-12-07 23:19:29.056
        $microtime = microtime(true);
        $time = date('Y-m-d H:i:s', (int) $microtime) . '.' . sprintf('%03d', ($microtime - floor($microtime)) * 1000);

        $tableName = $this->getTableName();

        // Build column list and values based on sharedTables setting
        $columns = ['id', 'userId', 'event', 'resource', 'userAgent', 'ip', 'location', 'time', 'data'];
        $placeholders = [':id', ':userId', ':event', ':resource', ':userAgent', ':ip', ':location', ':time', ':data'];

        $params = [
            'id' => $id,
            'userId' => $log['userId'] ?? null,
            'event' => $log['event'],
            'resource' => $log['resource'],
            'userAgent' => $log['userAgent'],
            'ip' => $log['ip'],
            'location' => $log['location'] ?? null,
            'time' => $time,
            'data' => json_encode($log['data'] ?? []),
        ];

        if ($this->sharedTables) {
            $columns[] = 'tenant';
            $placeholders[] = ':tenant';
            $params['tenant'] = $this->tenant;
        }

        $insertSql = "
            INSERT INTO {$this->database}.{$tableName}
            (" . implode(', ', $columns) . ")
            VALUES (
                " . implode(", ", $placeholders) . "
            )
        ";

        $this->query($insertSql, $params);

        $result = [
            '$id' => $id,
            'userId' => $log['userId'] ?? null,
            'event' => $log['event'],
            'resource' => $log['resource'],
            'userAgent' => $log['userAgent'],
            'ip' => $log['ip'],
            'location' => $log['location'] ?? null,
            'time' => $time,
            'data' => $log['data'] ?? [],
        ];

        if ($this->sharedTables) {
            $result['tenant'] = $this->tenant;
        }

        return new Document($result);
    }

    /**
     * Create multiple audit log entries in batch.
     *
     * @throws Exception
     */
    public function createBatch(array $logs): array
    {
        if (empty($logs)) {
            return [];
        }

        $values = [];
        foreach ($logs as $log) {
            $id = uniqid('audit_', true);
            $userIdVal = $log['userId'] ?? null;
            $userId = ($userIdVal !== null)
                ? "'" . addslashes((string) $userIdVal) . "'"
                : 'NULL';
            $locationVal = $log['location'] ?? null;
            $location = ($locationVal !== null)
                ? "'" . addslashes((string) $locationVal) . "'"
                : 'NULL';

            $formattedTimestamp = $this->formatTimestamp($log['timestamp']);

            if ($this->sharedTables) {
                $tenant = $this->tenant !== null ? (int) $this->tenant : 'NULL';
                $values[] = sprintf(
                    "('%s', %s, '%s', '%s', '%s', '%s', %s, '%s', '%s', %s)",
                    $id,
                    $userId,
                    addslashes((string) $log['event']),
                    addslashes((string) $log['resource']),
                    addslashes((string) $log['userAgent']),
                    addslashes((string) $log['ip']),
                    $location,
                    $formattedTimestamp,
                    addslashes((string) json_encode($log['data'] ?? [])),
                    $tenant
                );
            } else {
                $values[] = sprintf(
                    "('%s', %s, '%s', '%s', '%s', '%s', %s, '%s', '%s')",
                    $id,
                    $userId,
                    addslashes((string) $log['event']),
                    addslashes((string) $log['resource']),
                    addslashes((string) $log['userAgent']),
                    addslashes((string) $log['ip']),
                    $location,
                    $formattedTimestamp,
                    addslashes((string) json_encode($log['data'] ?? []))
                );
            }
        }

        $tableName = $this->getTableName();

        // Build column list based on sharedTables setting
        $columns = 'id, userId, event, resource, userAgent, ip, location, time, data';
        if ($this->sharedTables) {
            $columns .= ', tenant';
        }

        $insertSql = "
            INSERT INTO {$this->database}.{$tableName}
            ({$columns})
            VALUES " . implode(', ', $values);

        $this->query($insertSql);

        // Return documents
        $documents = [];
        foreach ($logs as $log) {
            $result = [
                '$id' => uniqid('audit_', true),
                'userId' => $log['userId'] ?? null,
                'event' => $log['event'],
                'resource' => $log['resource'],
                'userAgent' => $log['userAgent'],
                'ip' => $log['ip'],
                'location' => $log['location'] ?? null,
                'time' => $log['timestamp'],
                'data' => $log['data'] ?? [],
            ];

            if ($this->sharedTables) {
                $result['tenant'] = $this->tenant;
            }

            $documents[] = new Document($result);
        }

        return $documents;
    }

    /**
     * Parse ClickHouse query result into Documents.
     *
     * @return array<int, Document>
     */
    private function parseResults(string $result): array
    {
        if (empty(trim($result))) {
            return [];
        }

        $lines = explode("\n", trim($result));
        $documents = [];

        foreach ($lines as $line) {
            if (empty(trim($line))) {
                continue;
            }

            $columns = explode("\t", $line);
            // Expect 9 columns without sharedTables, 10 with sharedTables
            $expectedColumns = $this->sharedTables ? 10 : 9;
            if (count($columns) < $expectedColumns) {
                continue;
            }

            $data = json_decode($columns[8], true) ?? [];

            // Convert ClickHouse timestamp format back to ISO 8601
            // ClickHouse: 2025-12-07 23:33:54.493
            // ISO 8601:   2025-12-07T23:33:54.493+00:00
            $time = $columns[7];
            if (strpos($time, 'T') === false) {
                $time = str_replace(' ', 'T', $time) . '+00:00';
            }

            $document = [
                '$id' => $columns[0],
                'userId' => $columns[1] === '\\N' ? null : $columns[1],
                'event' => $columns[2],
                'resource' => $columns[3],
                'userAgent' => $columns[4],
                'ip' => $columns[5],
                'location' => $columns[6] === '\\N' ? null : $columns[6],
                'time' => $time,
                'data' => $data,
            ];

            // Add tenant only if sharedTables is enabled
            if ($this->sharedTables && isset($columns[9])) {
                $document['tenant'] = $columns[9] === '\\N' ? null : (int) $columns[9];
            }

            $documents[] = new Document($document);
        }

        return $documents;
    }

    /**
     * Get the SELECT column list for queries.
     * Returns 9 columns if not using shared tables, 10 if using shared tables.
     *
     * @return string
     */
    private function getSelectColumns(): string
    {
        if ($this->sharedTables) {
            return 'id, userId, event, resource, userAgent, ip, location, time, data, tenant';
        }
        return 'id, userId, event, resource, userAgent, ip, location, time, data';
    }

    /**
     * Build tenant filter clause based on current tenant context.
     *
     * @return string
     */
    private function getTenantFilter(): string
    {
        if (!$this->sharedTables || $this->tenant === null) {
            return '';
        }

        return " AND tenant = {$this->tenant}";
    }
    /**
     * Get logs by user ID.
     *
     * @throws Exception
     */
    public function getByUser(string $userId, array $queries = []): array
    {
        $limit = 25;
        $offset = 0;

        // Parse simple limit/offset from queries (simplified version)
        foreach ($queries as $query) {
            if (is_object($query) && method_exists($query, 'getMethod') && method_exists($query, 'getValue')) {
                if ($query->getMethod() === 'limit') {
                    $limit = (int) $query->getValue();
                } elseif ($query->getMethod() === 'offset') {
                    $offset = (int) $query->getValue();
                }
            }
        }

        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();

        $sql = "
            SELECT " . $this->getSelectColumns() . "
            FROM {$this->database}.{$tableName}
            WHERE userId = :userId{$tenantFilter}
            ORDER BY time DESC
            LIMIT :limit OFFSET :offset
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, [
            'userId' => $userId,
            'limit' => $limit,
            'offset' => $offset,
        ]);

        return $this->parseResults($result);
    }

    /**
     * Count logs by user ID.
     *
     * @throws Exception
     */
    public function countByUser(string $userId, array $queries = []): int
    {
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();

        $sql = "
            SELECT count() as count
            FROM {$this->database}.{$tableName}
            WHERE userId = :userId{$tenantFilter}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, ['userId' => $userId]);

        return (int) trim($result);
    }

    /**
     * Get logs by resource.
     *
     * @throws Exception
     */
    public function getByResource(string $resource, array $queries = []): array
    {
        $limit = 25;
        $offset = 0;

        foreach ($queries as $query) {
            if (is_object($query) && method_exists($query, 'getMethod') && method_exists($query, 'getValue')) {
                if ($query->getMethod() === 'limit') {
                    $limit = (int) $query->getValue();
                } elseif ($query->getMethod() === 'offset') {
                    $offset = (int) $query->getValue();
                }
            }
        }

        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();

        $sql = "
            SELECT " . $this->getSelectColumns() . "
            FROM {$this->database}.{$tableName}
            WHERE resource = :resource{$tenantFilter}
            ORDER BY time DESC
            LIMIT :limit OFFSET :offset
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, [
            'resource' => $resource,
            'limit' => $limit,
            'offset' => $offset,
        ]);

        return $this->parseResults($result);
    }

    /**
     * Count logs by resource.
     *
     * @throws Exception
     */
    public function countByResource(string $resource, array $queries = []): int
    {
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();

        $sql = "
            SELECT count() as count
            FROM {$this->database}.{$tableName}
            WHERE resource = :resource{$tenantFilter}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, ['resource' => $resource]);

        return (int) trim($result);
    }

    /**
     * Get logs by user and events.
     *
     * @throws Exception
     */
    public function getByUserAndEvents(string $userId, array $events, array $queries = []): array
    {
        $limit = 25;
        $offset = 0;

        foreach ($queries as $query) {
            if (is_object($query) && method_exists($query, 'getMethod') && method_exists($query, 'getValue')) {
                if ($query->getMethod() === 'limit') {
                    $limit = (int) $query->getValue();
                } elseif ($query->getMethod() === 'offset') {
                    $offset = (int) $query->getValue();
                }
            }
        }

        $eventsList = implode("', '", array_map('addslashes', $events));
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();

        $sql = "
            SELECT " . $this->getSelectColumns() . "
            FROM {$this->database}.{$tableName}
            WHERE userId = :userId AND event IN ('{$eventsList}'){$tenantFilter}
            ORDER BY time DESC
            LIMIT :limit OFFSET :offset
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, [
            'userId' => $userId,
            'limit' => $limit,
            'offset' => $offset,
        ]);

        return $this->parseResults($result);
    }

    /**
     * Count logs by user and events.
     *
     * @throws Exception
     */
    public function countByUserAndEvents(string $userId, array $events, array $queries = []): int
    {
        $eventsList = implode("', '", array_map('addslashes', $events));
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();

        $sql = "
            SELECT count() as count
            FROM {$this->database}.{$tableName}
            WHERE userId = :userId AND event IN ('{$eventsList}'){$tenantFilter}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, ['userId' => $userId]);

        return (int) trim($result);
    }

    /**
     * Get logs by resource and events.
     *
     * @throws Exception
     */
    public function getByResourceAndEvents(string $resource, array $events, array $queries = []): array
    {
        $limit = 25;
        $offset = 0;

        foreach ($queries as $query) {
            if (is_object($query) && method_exists($query, 'getMethod') && method_exists($query, 'getValue')) {
                if ($query->getMethod() === 'limit') {
                    $limit = (int) $query->getValue();
                } elseif ($query->getMethod() === 'offset') {
                    $offset = (int) $query->getValue();
                }
            }
        }

        $eventsList = implode("', '", array_map('addslashes', $events));
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();

        $sql = "
            SELECT " . $this->getSelectColumns() . "
            FROM {$this->database}.{$tableName}
            WHERE resource = :resource AND event IN ('{$eventsList}'){$tenantFilter}
            ORDER BY time DESC
            LIMIT :limit OFFSET :offset
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, [
            'resource' => $resource,
            'limit' => $limit,
            'offset' => $offset,
        ]);

        return $this->parseResults($result);
    }

    /**
     * Count logs by resource and events.
     *
     * @throws Exception
     */
    public function countByResourceAndEvents(string $resource, array $events, array $queries = []): int
    {
        $eventsList = implode("', '", array_map('addslashes', $events));
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();

        $sql = "
            SELECT count() as count
            FROM {$this->database}.{$tableName}
            WHERE resource = :resource AND event IN ('{$eventsList}'){$tenantFilter}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, ['resource' => $resource]);

        return (int) trim($result);
    }

    /**
     * Delete logs older than the specified datetime.
     *
     * ClickHouse uses ALTER TABLE DELETE with synchronous mutations.
     *
     * @throws Exception
     */
    public function cleanup(string $datetime): bool
    {
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();

        // Use DELETE statement for synchronous deletion (ClickHouse 23.3+)
        // Falls back to ALTER TABLE DELETE with mutations_sync for older versions
        $sql = "
            DELETE FROM {$this->database}.{$tableName}
            WHERE time < :datetime{$tenantFilter}
        ";

        $this->query($sql, ['datetime' => $datetime]);

        return true;
    }
}
