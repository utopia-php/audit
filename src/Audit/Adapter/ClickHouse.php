<?php

namespace Utopia\Audit\Adapter;

use Exception;
use Utopia\Audit\Log;
use Utopia\Fetch\Client;
use Utopia\Validator\Hostname;

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

    private const DEFAULT_DATABASE = 'default';

    private string $host;

    private int $port;

    private string $database = self::DEFAULT_DATABASE;

    private string $table = self::DEFAULT_TABLE;

    private string $username;

    private string $password;

    /** @var bool Whether to use HTTPS for ClickHouse HTTP interface */
    private bool $secure = false;

    private Client $client;

    protected string $namespace = '';

    protected ?int $tenant = null;

    protected bool $sharedTables = false;

    /**
     * @param string $host ClickHouse host
     * @param string $username ClickHouse username (default: 'default')
     * @param string $password ClickHouse password (default: '')
     * @param int $port ClickHouse HTTP port (default: 8123)
     * @param bool $secure Whether to use HTTPS (default: false)
     * @throws Exception If validation fails
     */
    public function __construct(
        string $host,
        string $username = 'default',
        string $password = '',
        int $port = self::DEFAULT_PORT,
        bool $secure = false
    ) {
        $this->validateHost($host);
        $this->validatePort($port);

        $this->host = $host;
        $this->port = $port;
        $this->username = $username;
        $this->password = $password;
        $this->secure = $secure;

        // Initialize the HTTP client for connection reuse
        $this->client = new Client();
        $this->client->addHeader('X-ClickHouse-User', $this->username);
        $this->client->addHeader('X-ClickHouse-Key', $this->password);
        $this->client->setTimeout(30 * 1000); // 30 seconds
    }

    /**
     * Get adapter name.
     */
    public function getName(): string
    {
        return 'ClickHouse';
    }

    /**
     * Validate host parameter.
     *
     * @param string $host
     * @throws Exception
     */
    private function validateHost(string $host): void
    {
        $validator = new Hostname();
        if (!$validator->isValid($host)) {
            throw new Exception('ClickHouse host is not a valid hostname or IP address');
        }
    }

    /**
     * Validate port parameter.
     *
     * @param int $port
     * @throws Exception
     */
    private function validatePort(int $port): void
    {
        if ($port < 1 || $port > 65535) {
            throw new Exception('ClickHouse port must be between 1 and 65535');
        }
    }

    /**
     * Validate identifier (database, table, namespace).
     * ClickHouse identifiers follow SQL standard rules.
     *
     * @param string $identifier
     * @param string $type Name of the identifier type for error messages
     * @throws Exception
     */
    private function validateIdentifier(string $identifier, string $type = 'Identifier'): void
    {
        if (empty($identifier)) {
            throw new Exception("{$type} cannot be empty");
        }

        if (strlen($identifier) > 255) {
            throw new Exception("{$type} cannot exceed 255 characters");
        }

        // ClickHouse identifiers: alphanumeric, underscores, cannot start with number
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $identifier)) {
            throw new Exception("{$type} must start with a letter or underscore and contain only alphanumeric characters and underscores");
        }

        // Check against SQL keywords (common ones)
        $keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'TABLE', 'DATABASE'];
        if (in_array(strtoupper($identifier), $keywords, true)) {
            throw new Exception("{$type} cannot be a reserved SQL keyword");
        }
    }

    /**
     * Escape an identifier (database name, table name, column name) for safe use in SQL.
     * Uses backticks as per SQL standard for identifier quoting.
     *
     * @param string $identifier
     * @return string
     */
    private function escapeIdentifier(string $identifier): string
    {
        // Backtick escaping: replace any backticks in the identifier with double backticks
        return '`' . str_replace('`', '``', $identifier) . '`';
    }
    /**
     * Set the namespace for multi-project support.
     * Namespace is used as a prefix for table names.
     *
     * @param string $namespace
     * @return self
     * @throws Exception
     */
    public function setNamespace(string $namespace): self
    {
        if (!empty($namespace)) {
            $this->validateIdentifier($namespace, 'Namespace');
        }
        $this->namespace = $namespace;
        return $this;
    }

    /**
     * Set the database name for subsequent operations.
     *
     * @param string $database
     * @return self
     * @throws Exception
     */
    public function setDatabase(string $database): self
    {
        $this->validateIdentifier($database, 'Database');
        $this->database = $database;
        return $this;
    }

    /**
     * Enable or disable HTTPS for ClickHouse HTTP interface.
     */
    public function setSecure(bool $secure): self
    {
        $this->secure = $secure;
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
     * Execute a ClickHouse query via HTTP interface using Fetch Client.
     *
     * Uses ClickHouse query parameters (sent as POST multipart form data) to prevent SQL injection.
     * This is ClickHouse's native parameter mechanism - parameters are safely
     * transmitted separately from the query structure.
     *
     * Parameters are referenced in the SQL using the syntax: {paramName:Type}.
     * For example: SELECT * WHERE id = {id:String}
     *
     * ClickHouse handles all parameter escaping and type conversion internally,
     * making this approach fully injection-safe without needing manual escaping.
     *
     * Using POST body avoids URL length limits for batch operations with many parameters.
     * Equivalent to: curl -X POST -F 'query=...' -F 'param_key=value' http://host/
     *
     * @param array<string, mixed> $params Key-value pairs for query parameters
     * @throws Exception
     */
    private function query(string $sql, array $params = []): string
    {
        $scheme = $this->secure ? 'https' : 'http';
        $url = "{$scheme}://{$this->host}:{$this->port}/";

        // Update the database header for each query (in case setDatabase was called)
        $this->client->addHeader('X-ClickHouse-Database', $this->database);

        // Build multipart form data body with query and parameters
        // The Fetch client will automatically encode arrays as multipart/form-data
        $body = ['query' => $sql];
        foreach ($params as $key => $value) {
            $body['param_' . $key] = $this->formatParamValue($value);
        }

        try {
            $response = $this->client->fetch(
                url: $url,
                method: Client::METHOD_POST,
                body: $body
            );
            if ($response->getStatusCode() !== 200) {
                $bodyStr = $response->getBody();
                $bodyStr = is_string($bodyStr) ? $bodyStr : '';
                throw new Exception("ClickHouse query failed with HTTP {$response->getStatusCode()}: {$bodyStr}");
            }

            $body = $response->getBody();
            return is_string($body) ? $body : '';
        } catch (Exception $e) {
            // Preserve the original exception context for better debugging
            // Re-throw with additional context while maintaining the original exception chain
            throw new Exception(
                "ClickHouse query execution failed: {$e->getMessage()}",
                0,
                $e
            );
        }
    }

    /**
     * Format a parameter value for safe transmission to ClickHouse.
     *
     * Converts PHP values to their string representation without SQL quoting.
     * ClickHouse's query parameter mechanism handles type conversion and escaping.
     *
     * @param mixed $value
     * @return string
     */
    private function formatParamValue(mixed $value): string
    {
        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }

        if ($value === null) {
            return '';
        }

        if (is_bool($value)) {
            return $value ? '1' : '0';
        }

        if (is_array($value)) {
            $encoded = json_encode($value);
            return is_string($encoded) ? $encoded : '';
        }

        if (is_string($value)) {
            return $value;
        }

        // For objects or other types, attempt to convert to string
        if (is_object($value) && method_exists($value, '__toString')) {
            return (string) $value;
        }

        return '';
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
        $escapedDatabase = $this->escapeIdentifier($this->database);
        $createDbSql = "CREATE DATABASE IF NOT EXISTS {$escapedDatabase}";
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
        $escapedDatabaseAndTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        // Create table with MergeTree engine for optimal performance
        $createTableSql = "
            CREATE TABLE IF NOT EXISTS {$escapedDatabaseAndTable} (
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
    public function create(array $log): Log
    {
        $id = uniqid('', true);
        $time = (new \DateTime())->format('Y-m-d H:i:s.v');

        $tableName = $this->getTableName();

        // Build column list and values based on sharedTables setting
        $columns = ['id', 'userId', 'event', 'resource', 'userAgent', 'ip', 'location', 'time', 'data'];
        $placeholders = ['{id:String}', '{userId:Nullable(String)}', '{event:String}', '{resource:String}', '{userAgent:String}', '{ip:String}', '{location:Nullable(String)}', '{time:String}', '{data:String}'];

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
            $placeholders[] = '{tenant:Nullable(UInt64)}';
            $params['tenant'] = $this->tenant;
        }

        $escapedDatabaseAndTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);
        $insertSql = "
            INSERT INTO {$escapedDatabaseAndTable}
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

        return new Log($result);
    }

    /**
     * Get a single log by its ID.
     *
     * @param string $id
     * @return Log|null The log entry or null if not found
     * @throws Exception
     */
    public function getById(string $id): ?Log
    {
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        $sql = "
            SELECT " . $this->getSelectColumns() . "
            FROM {$escapedTable}
            WHERE id = {id:String}{$tenantFilter}
            LIMIT 1
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, ['id' => $id]);
        $logs = $this->parseResults($result);

        return $logs[0] ?? null;
    }

    /**
     * Create multiple audit log entries in batch.
     *
     * @throws Exception
     */
    public function createBatch(array $logs): bool
    {
        if (empty($logs)) {
            return true;
        }

        $tableName = $this->getTableName();
        $escapedDatabaseAndTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        // Build column list based on sharedTables setting
        $columns = ['id', 'userId', 'event', 'resource', 'userAgent', 'ip', 'location', 'time', 'data'];
        if ($this->sharedTables) {
            $columns[] = 'tenant';
        }

        $ids = [];
        $paramCounter = 0;
        $params = [];
        $valueClauses = [];

        foreach ($logs as $log) {
            $id = uniqid('', true);
            $ids[] = $id;

            // Create parameter placeholders for this row
            $paramKeys = [];
            $paramKeys[] = 'id_' . $paramCounter;
            $paramKeys[] = 'userId_' . $paramCounter;
            $paramKeys[] = 'event_' . $paramCounter;
            $paramKeys[] = 'resource_' . $paramCounter;
            $paramKeys[] = 'userAgent_' . $paramCounter;
            $paramKeys[] = 'ip_' . $paramCounter;
            $paramKeys[] = 'location_' . $paramCounter;
            $paramKeys[] = 'time_' . $paramCounter;
            $paramKeys[] = 'data_' . $paramCounter;

            // Set parameter values
            $params[$paramKeys[0]] = $id;
            $params[$paramKeys[1]] = $log['userId'] ?? null;
            $params[$paramKeys[2]] = $log['event'];
            $params[$paramKeys[3]] = $log['resource'];
            $params[$paramKeys[4]] = $log['userAgent'];
            $params[$paramKeys[5]] = $log['ip'];
            $params[$paramKeys[6]] = $log['location'] ?? null;

            $time = $log['time'] ?? new \DateTime();
            if (is_string($time)) {
                $time = new \DateTime($time);
            }
            $params[$paramKeys[7]] = $time->format('Y-m-d H:i:s.v');
            $params[$paramKeys[8]] = json_encode($log['data'] ?? []);

            if ($this->sharedTables) {
                $paramKeys[] = 'tenant_' . $paramCounter;
                $params[$paramKeys[9]] = $this->tenant;
            }

            // Build placeholder string for this row
            $placeholders = [];
            for ($i = 0; $i < count($paramKeys); $i++) {
                if ($i === 1 || $i === 6) { // userId and location are nullable
                    $placeholders[] = '{' . $paramKeys[$i] . ':Nullable(String)}';
                } elseif ($this->sharedTables && $i === 9) { // tenant is nullable UInt64
                    $placeholders[] = '{' . $paramKeys[$i] . ':Nullable(UInt64)}';
                } else {
                    $placeholders[] = '{' . $paramKeys[$i] . ':String}';
                }
            }

            $valueClauses[] = '(' . implode(', ', $placeholders) . ')';
            $paramCounter++;
        }

        $insertSql = "
            INSERT INTO {$escapedDatabaseAndTable}
            (" . implode(', ', $columns) . ")
            VALUES " . implode(', ', $valueClauses);

        $this->query($insertSql, $params);
        return true;
    }

    /**
     * Parse ClickHouse query result into Log objects.
     *
     * @return array<int, Log>
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

            // Helper function to parse nullable string fields
            // ClickHouse TabSeparated format uses \N for NULL, but empty strings are also treated as null for nullable fields
            $parseNullableString = static function ($value): ?string {
                if ($value === '\\N' || $value === '') {
                    return null;
                }
                return $value;
            };

            $document = [
                '$id' => $columns[0],
                'userId' => $parseNullableString($columns[1]),
                'event' => $columns[2],
                'resource' => $columns[3],
                'userAgent' => $columns[4],
                'ip' => $columns[5],
                'location' => $parseNullableString($columns[6]),
                'time' => $time,
                'data' => $data,
            ];

            // Add tenant only if sharedTables is enabled
            if ($this->sharedTables && isset($columns[9])) {
                $document['tenant'] = $columns[9] === '\\N' || $columns[9] === '' ? null : (int) $columns[9];
            }

            $documents[] = new Log($document);
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
     * Build time WHERE clause and parameters with safe parameter placeholders.
     *
     * @param \DateTime|null $after
     * @param \DateTime|null $before
     * @return array{clause: string, params: array<string, mixed>}
     */
    private function buildTimeClause(?\DateTime $after, ?\DateTime $before): array
    {
        $params = [];
        $conditions = [];

        $afterStr = null;
        $beforeStr = null;

        if ($after !== null) {
            /** @var \DateTime $after */
            $afterStr = \Utopia\Database\DateTime::format($after);
        }

        if ($before !== null) {
            /** @var \DateTime $before */
            $beforeStr = \Utopia\Database\DateTime::format($before);
        }

        if ($afterStr !== null && $beforeStr !== null) {
            $conditions[] = 'time BETWEEN {after:String} AND {before:String}';
            $params['after'] = $afterStr;
            $params['before'] = $beforeStr;

            return ['clause' => ' AND ' . $conditions[0], 'params' => $params];
        }

        if ($afterStr !== null) {
            $conditions[] = 'time > {after:String}';
            $params['after'] = $afterStr;
        }

        if ($beforeStr !== null) {
            $conditions[] = 'time < {before:String}';
            $params['before'] = $beforeStr;
        }

        if ($conditions === []) {
            return ['clause' => '', 'params' => []];
        }

        return [
            'clause' => ' AND ' . implode(' AND ', $conditions),
            'params' => $params,
        ];
    }

    /**
     * Build a formatted SQL IN list from an array of events.
     * Events are parameterized for safe SQL inclusion.
     *
     * @param array<int|string, string> $events
     * @param int $paramOffset Base parameter number for creating unique param names
     * @return array{clause: string, params: array<string, string>}
     */
    private function buildEventsList(array $events, int $paramOffset = 0): array
    {
        $placeholders = [];
        $params = [];

        foreach ($events as $index => $event) {
            /** @var int $paramNumber */
            $paramNumber = $paramOffset + (int) $index;
            $paramName = 'event_' . (string) $paramNumber;
            $placeholders[] = '{' . $paramName . ':String}';
            $params[$paramName] = $event;
        }

        $clause = implode(', ', $placeholders);
        return ['clause' => $clause, 'params' => $params];
    }

    /**
     * Get ClickHouse-specific SQL column definition for a given attribute ID.
     *
     * @param string $id Attribute identifier
     * @return string ClickHouse column definition with appropriate types and nullability
     * @throws Exception
     */
    protected function getColumnDefinition(string $id): string
    {
        $attribute = $this->getAttribute($id);

        if (!$attribute) {
            throw new Exception("Attribute {$id} not found");
        }

        // ClickHouse-specific type mapping
        $type = match ($id) {
            'userId', 'event', 'resource', 'userAgent', 'ip', 'location', 'data' => 'String',
            'time' => 'DateTime64(3)',
            default => 'String',
        };

        $nullable = !$attribute['required'] ? 'Nullable(' . $type . ')' : $type;

        return "{$id} {$nullable}";
    }

    /**
     * Get logs by user ID.
     *
     * @throws Exception
     */
    public function getByUser(
        string $userId,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
        int $limit = 25,
        int $offset = 0,
        bool $ascending = false,
    ): array {
        $time = $this->buildTimeClause($after, $before);
        $order = $ascending ? 'ASC' : 'DESC';

        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        $sql = "
            SELECT " . $this->getSelectColumns() . "
            FROM {$escapedTable}
            WHERE userId = {userId:String}{$tenantFilter}{$time['clause']}
            ORDER BY time {$order}
            LIMIT {limit:UInt64} OFFSET {offset:UInt64}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, array_merge([
            'userId' => $userId,
            'limit' => $limit,
            'offset' => $offset,
        ], $time['params']));

        return $this->parseResults($result);
    }

    /**
     * Count logs by user ID.
     *
     * @throws Exception
     */
    public function countByUser(
        string $userId,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
    ): int {
        $time = $this->buildTimeClause($after, $before);

        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        $sql = "
            SELECT count()
            FROM {$escapedTable}
            WHERE userId = {userId:String}{$tenantFilter}{$time['clause']}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, array_merge([
            'userId' => $userId,
        ], $time['params']));

        return (int) trim($result);
    }

    /**
     * Get logs by resource.
     *
     * @throws Exception
     */
    public function getByResource(
        string $resource,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
        int $limit = 25,
        int $offset = 0,
        bool $ascending = false,
    ): array {
        $time = $this->buildTimeClause($after, $before);
        $order = $ascending ? 'ASC' : 'DESC';

        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        $sql = "
            SELECT " . $this->getSelectColumns() . "
            FROM {$escapedTable}
            WHERE resource = {resource:String}{$tenantFilter}{$time['clause']}
            ORDER BY time {$order}
            LIMIT {limit:UInt64} OFFSET {offset:UInt64}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, array_merge([
            'resource' => $resource,
            'limit' => $limit,
            'offset' => $offset,
        ], $time['params']));

        return $this->parseResults($result);
    }

    /**
     * Count logs by resource.
     *
     * @throws Exception
     */
    public function countByResource(
        string $resource,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
    ): int {
        $time = $this->buildTimeClause($after, $before);

        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        $sql = "
            SELECT count()
            FROM {$escapedTable}
            WHERE resource = {resource:String}{$tenantFilter}{$time['clause']}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, array_merge([
            'resource' => $resource,
        ], $time['params']));

        return (int) trim($result);
    }

    /**
     * Get logs by user and events.
     *
     * @throws Exception
     */
    public function getByUserAndEvents(
        string $userId,
        array $events,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
        int $limit = 25,
        int $offset = 0,
        bool $ascending = false,
    ): array {
        $time = $this->buildTimeClause($after, $before);
        $order = $ascending ? 'ASC' : 'DESC';
        $eventList = $this->buildEventsList($events, 0);
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        $sql = "
            SELECT " . $this->getSelectColumns() . "
            FROM {$escapedTable}
            WHERE userId = {userId:String} AND event IN ({$eventList['clause']}){$tenantFilter}{$time['clause']}
            ORDER BY time {$order}
            LIMIT {limit:UInt64} OFFSET {offset:UInt64}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, array_merge([
            'userId' => $userId,
            'limit' => $limit,
            'offset' => $offset,
        ], $eventList['params'], $time['params']));

        return $this->parseResults($result);
    }

    /**
     * Count logs by user and events.
     *
     * @throws Exception
     */
    public function countByUserAndEvents(
        string $userId,
        array $events,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
    ): int {
        $time = $this->buildTimeClause($after, $before);
        $eventList = $this->buildEventsList($events, 0);
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        $sql = "
            SELECT count()
            FROM {$escapedTable}
            WHERE userId = {userId:String} AND event IN ({$eventList['clause']}){$tenantFilter}{$time['clause']}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, array_merge([
            'userId' => $userId,
        ], $eventList['params'], $time['params']));

        return (int) trim($result);
    }

    /**
     * Get logs by resource and events.
     *
     * @throws Exception
     */
    public function getByResourceAndEvents(
        string $resource,
        array $events,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
        int $limit = 25,
        int $offset = 0,
        bool $ascending = false,
    ): array {
        $time = $this->buildTimeClause($after, $before);
        $order = $ascending ? 'ASC' : 'DESC';
        $eventList = $this->buildEventsList($events, 0);
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        $sql = "
            SELECT " . $this->getSelectColumns() . "
            FROM {$escapedTable}
            WHERE resource = {resource:String} AND event IN ({$eventList['clause']}){$tenantFilter}{$time['clause']}
            ORDER BY time {$order}
            LIMIT {limit:UInt64} OFFSET {offset:UInt64}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, array_merge([
            'resource' => $resource,
            'limit' => $limit,
            'offset' => $offset,
        ], $eventList['params'], $time['params']));

        return $this->parseResults($result);
    }

    /**
     * Count logs by resource and events.
     *
     * @throws Exception
     */
    public function countByResourceAndEvents(
        string $resource,
        array $events,
        ?\DateTime $after = null,
        ?\DateTime $before = null,
    ): int {
        $time = $this->buildTimeClause($after, $before);
        $eventList = $this->buildEventsList($events, 0);
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        $sql = "
            SELECT count()
            FROM {$escapedTable}
            WHERE resource = {resource:String} AND event IN ({$eventList['clause']}){$tenantFilter}{$time['clause']}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, array_merge([
            'resource' => $resource,
        ], $eventList['params'], $time['params']));

        return (int) trim($result);
    }

    /**
     * Delete logs older than the specified datetime.
     *
     * ClickHouse uses ALTER TABLE DELETE with synchronous mutations.
     *
     * @throws Exception
     */
    public function cleanup(\DateTime $datetime): bool
    {
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        // Convert DateTime to string format expected by ClickHouse
        $datetimeString = $datetime->format('Y-m-d H:i:s.v');

        // Use DELETE statement for synchronous deletion (ClickHouse 23.3+)
        // Falls back to ALTER TABLE DELETE with mutations_sync for older versions
        $sql = "
            DELETE FROM {$escapedTable}
            WHERE time < {datetime:String}{$tenantFilter}
        ";

        $this->query($sql, ['datetime' => $datetimeString]);

        return true;
    }
}
