<?php

namespace Utopia\Audit\Adapter;

use Exception;
use Utopia\Audit\Log;
use Utopia\Audit\Query;
use Utopia\Database\Database;
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
        $this->client->setTimeout(30_000); // 30 seconds
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
     * Override getAttributes to provide extended attributes for ClickHouse.
     * Includes existing attributes from parent and adds new missing ones.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getAttributes(): array
    {
        $parentAttributes = parent::getAttributes();

        return [
            ...$parentAttributes,
            [
                '$id' => 'userType',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'userInternalId',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => false,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'resourceParent',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => false,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'resourceType',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'resourceId',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'resourceInternalId',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => false,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'country',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => false,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'projectId',
                'type' => Database::VAR_STRING,
                'format' => '',
                'size' => Database::LENGTH_KEY,
                'signed' => true,
                'required' => true,
                'default' => null,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'projectInternalId',
                'type' => Database::VAR_STRING,
                'format' => '',
                'size' => Database::LENGTH_KEY,
                'signed' => true,
                'required' => true,
                'default' => null,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'teamId',
                'type' => Database::VAR_STRING,
                'format' => '',
                'size' => Database::LENGTH_KEY,
                'signed' => true,
                'required' => true,
                'default' => null,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'teamInternalId',
                'type' => Database::VAR_STRING,
                'format' => '',
                'size' => Database::LENGTH_KEY,
                'signed' => true,
                'required' => true,
                'default' => null,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'hostname',
                'type' => Database::VAR_STRING,
                'format' => '',
                'size' => Database::LENGTH_KEY,
                'signed' => true,
                'required' => true,
                'default' => null,
                'array' => false,
                'filters' => [],
            ],
        ];
    }

    /**
     * Override getIndexes to provide extended indexes for ClickHouse.
     * Includes existing indexes from parent and adds new missing ones.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getIndexes(): array
    {
        $parentIndexes = parent::getIndexes();

        // New indexes to add
        return [
            ...$parentIndexes,
            [
                '$id' => '_key_user_internal_and_event',
                'type' => Database::INDEX_KEY,
                'attributes' => ['userInternalId', 'event'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_project_internal_id',
                'type' => Database::INDEX_KEY,
                'attributes' => ['projectInternalId'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_team_internal_id',
                'type' => Database::INDEX_KEY,
                'attributes' => ['teamInternalId'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_user_internal_id',
                'type' => Database::INDEX_KEY,
                'attributes' => ['userInternalId'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_user_type',
                'type' => Database::INDEX_KEY,
                'attributes' => ['userType'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_country',
                'type' => Database::INDEX_KEY,
                'attributes' => ['country'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_hostname',
                'type' => Database::INDEX_KEY,
                'attributes' => ['hostname'],
                'lengths' => [],
                'orders' => [],
            ],
        ];
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
            // Escape each attribute name to prevent SQL injection
            $escapedAttributes = array_map(fn ($attr) => $this->escapeIdentifier($attr), $attributes);
            $attributeList = implode(', ', $escapedAttributes);
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
     * Get column names from attributes.
     * Returns an array of column names excluding 'id' and 'tenant' which are handled separately.
     *
     * @return array<string> Column names
     */
    private function getColumnNames(): array
    {
        $columns = [];
        foreach ($this->getAttributes() as $attribute) {
            /** @var string $columnName */
            $columnName = $attribute['$id'];
            // Exclude id and tenant as they're handled separately
            if ($columnName !== 'id' && $columnName !== 'tenant') {
                $columns[] = $columnName;
            }
        }
        return $columns;
    }

    /**
     * Validate that an attribute name exists in the schema.
     * Prevents SQL injection by ensuring only valid column names are used.
     *
     * @param string $attributeName The attribute name to validate
     * @return bool True if valid
     * @throws Exception If attribute name is invalid
     */
    private function validateAttributeName(string $attributeName): bool
    {
        // Special case: 'id' is always valid
        if ($attributeName === 'id') {
            return true;
        }

        // Check if tenant is valid (only when sharedTables is enabled)
        if ($attributeName === 'tenant' && $this->sharedTables) {
            return true;
        }

        // Check against defined attributes
        foreach ($this->getAttributes() as $attribute) {
            if ($attribute['$id'] === $attributeName) {
                return true;
            }
        }

        throw new Exception("Invalid attribute name: {$attributeName}");
    }

    /**
     * Get attribute metadata by column name.
     * Searches through all attributes to find metadata for a specific column.
     *
     * @param string $columnName The column name to look up
     * @return array<string, mixed>|null The attribute metadata or null if not found
     */
    private function getAttributeMetadata(string $columnName): ?array
    {
        foreach ($this->getAttributes() as $attribute) {
            if ($attribute['$id'] === $columnName) {
                return $attribute;
            }
        }
        return null;
    }

    /**
     * Format datetime values for ClickHouse parameter binding.
     * Removes timezone suffixes which are incompatible with DateTime64 type comparisons.
     *
     * @param mixed $value The value to format
     * @return string Formatted string without timezone suffix
     */
    private function formatDateTimeParam(mixed $value): string
    {
        $strValue = $this->formatParamValue($value);
        // Remove timezone suffix if present (e.g., +00:00, -05:00)
        return preg_replace('/[+\\-]\\d{2}:\\d{2}$/', '', $strValue) ?? $strValue;
    }


    /**
     * Format datetime for ClickHouse compatibility.
     * Converts datetime to 'YYYY-MM-DD HH:MM:SS.mmm' format without timezone suffix.
     * ClickHouse DateTime64(3) type expects this format as timezone is handled by column metadata.
     *
     * @param \DateTime|string|null $dateTime The datetime value to format
     * @return string The formatted datetime string in ClickHouse compatible format
     * @throws Exception If the datetime string cannot be parsed
     */
    private function formatDateTimeForClickHouse($dateTime): string
    {
        if ($dateTime === null) {
            return (new \DateTime())->format('Y-m-d H:i:s.v');
        }

        if ($dateTime instanceof \DateTime) {
            return $dateTime->format('Y-m-d H:i:s.v');
        }

        if (is_string($dateTime)) {
            try {
                // Parse the datetime string, handling ISO 8601 format with timezone
                $dt = new \DateTime($dateTime);
                return $dt->format('Y-m-d H:i:s.v');
            } catch (\Exception $e) {
                throw new Exception("Invalid datetime string: {$dateTime}");
            }
        }

        // This is unreachable code but kept for completeness - all valid types are handled above
        // @phpstan-ignore-next-line
        throw new Exception('DateTime must be a DateTime object or string');
    }

    /**
     * Create an audit log entry.
     *
     * @param array<string, mixed> $log The log data
     * @throws Exception
     */
    public function create(array $log): Log
    {
        $id = uniqid('', true);
        // Format time - use provided time or current time
        /** @var string|\DateTime|null $logTime */
        $logTime = $log['time'] ?? null;
        $timeValue = $this->formatDateTimeForClickHouse($logTime);

        $tableName = $this->getTableName();

        // Build column list and placeholders dynamically from attributes
        $columns = ['id', 'time'];
        $placeholders = ['{id:String}', '{time:String}'];
        $params = [
            'id' => $id,
            'time' => $timeValue,
        ];

        // Get all column names from attributes
        $attributeColumns = $this->getColumnNames();

        foreach ($attributeColumns as $column) {
            if ($column === 'time') {
                // Skip time - already handled above
                continue;
            }

            if (isset($log[$column])) {
                $columns[] = $column;

                // Special handling for data column
                if ($column === 'data') {
                    /** @var array<string, mixed> $dataValue */
                    $dataValue = $log['data'] ?? [];
                    $params[$column] = json_encode($dataValue);
                    // data is nullable based on attributes
                    $placeholders[] = '{' . $column . ':Nullable(String)}';
                } elseif (in_array($column, ['userId', 'location', 'userInternalId', 'resourceParent', 'resourceInternalId', 'country'])) {
                    // Nullable string fields
                    $params[$column] = $log[$column];
                    $placeholders[] = '{' . $column . ':Nullable(String)}';
                } else {
                    // Required string fields
                    $params[$column] = $log[$column];
                    $placeholders[] = '{' . $column . ':String}';
                }
            }
        }

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

        $result = ['$id' => $id];

        // Add time
        $result['time'] = $timeValue;

        // Add all columns from log to result
        foreach ($attributeColumns as $column) {
            if ($column === 'time') {
                continue; // Already added
            }

            if ($column === 'data') {
                $result[$column] = $log['data'] ?? [];
            } elseif (isset($log[$column])) {
                $result[$column] = $log[$column];
            }
        }

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
        $escapedId = $this->escapeIdentifier('id');

        $sql = "
            SELECT " . $this->getSelectColumns() . "
            FROM {$escapedTable}
            WHERE {$escapedId} = {id:String}{$tenantFilter}
            LIMIT 1
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, ['id' => $id]);
        $logs = $this->parseResults($result);

        return $logs[0] ?? null;
    }

    /**
     * Find logs using Query objects.
     *
     * @param array<Query> $queries
     * @return array<Log>
     * @throws Exception
     */
    public function find(array $queries = []): array
    {
        $tableName = $this->getTableName();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        // Parse queries
        $parsed = $this->parseQueries($queries);

        // Build SELECT clause
        $selectColumns = $this->getSelectColumns();

        // Build WHERE clause
        $whereClause = '';
        $tenantFilter = $this->getTenantFilter();
        if (!empty($parsed['filters']) || $tenantFilter) {
            $conditions = $parsed['filters'];
            if ($tenantFilter) {
                $conditions[] = ltrim($tenantFilter, ' AND');
            }
            $whereClause = ' WHERE ' . implode(' AND ', $conditions);
        }

        // Build ORDER BY clause
        $orderClause = '';
        if (!empty($parsed['orderBy'])) {
            $orderClause = ' ORDER BY ' . implode(', ', $parsed['orderBy']);
        }

        // Build LIMIT and OFFSET
        $limitClause = isset($parsed['limit']) ? ' LIMIT {limit:UInt64}' : '';
        $offsetClause = isset($parsed['offset']) ? ' OFFSET {offset:UInt64}' : '';

        $sql = "
            SELECT {$selectColumns}
            FROM {$escapedTable}{$whereClause}{$orderClause}{$limitClause}{$offsetClause}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, $parsed['params']);
        return $this->parseResults($result);
    }

    /**
     * Count logs using Query objects.
     *
     * @param array<Query> $queries
     * @return int
     * @throws Exception
     */
    public function count(array $queries = []): int
    {
        $tableName = $this->getTableName();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        // Parse queries - we only need filters and params, not ordering/limit/offset
        $parsed = $this->parseQueries($queries);

        // Build WHERE clause
        $whereClause = '';
        $tenantFilter = $this->getTenantFilter();
        if (!empty($parsed['filters']) || $tenantFilter) {
            $conditions = $parsed['filters'];
            if ($tenantFilter) {
                $conditions[] = ltrim($tenantFilter, ' AND');
            }
            $whereClause = ' WHERE ' . implode(' AND ', $conditions);
        }

        // Remove limit and offset from params as they don't apply to count
        $params = $parsed['params'];
        unset($params['limit'], $params['offset']);

        $sql = "
            SELECT COUNT(*) as count
            FROM {$escapedTable}{$whereClause}
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, $params);
        $trimmed = trim($result);

        return $trimmed !== '' ? (int) $trimmed : 0;
    }

    /**
     * Parse Query objects into SQL components.
     *
     * @param array<Query> $queries
     * @return array{filters: array<string>, params: array<string, mixed>, orderBy?: array<string>, limit?: int, offset?: int}
     * @throws Exception
     */
    private function parseQueries(array $queries): array
    {
        $filters = [];
        $params = [];
        $orderBy = [];
        $limit = null;
        $offset = null;
        $paramCounter = 0;

        foreach ($queries as $query) {
            if (!$query instanceof Query) {
                /** @phpstan-ignore-next-line ternary.alwaysTrue - runtime validation despite type hint */
                $type = is_object($query) ? get_class($query) : gettype($query);
                throw new \InvalidArgumentException("Invalid query item: expected instance of Query, got {$type}");
            }

            $method = $query->getMethod();
            $attribute = $query->getAttribute();
            $values = $query->getValues();

            switch ($method) {
                case Query::TYPE_EQUAL:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "{$escapedAttr} = {{$paramName}:String}";
                    $params[$paramName] = $this->formatParamValue($values[0]);
                    break;

                case Query::TYPE_LESSER:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "{$escapedAttr} < {{$paramName}:String}";
                    $params[$paramName] = $this->formatParamValue($values[0]);
                    break;

                case Query::TYPE_GREATER:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "{$escapedAttr} > {{$paramName}:String}";
                    $params[$paramName] = $this->formatParamValue($values[0]);
                    break;

                case Query::TYPE_BETWEEN:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $paramName1 = 'param_' . $paramCounter++;
                    $paramName2 = 'param_' . $paramCounter++;
                    // Use DateTime64 type for time column, String for others
                    // This prevents type mismatch when comparing DateTime64 with timezone-suffixed strings
                    if ($attribute === 'time') {
                        $paramType = 'DateTime64(3)';
                        $filters[] = "{$escapedAttr} BETWEEN {{$paramName1}:{$paramType}} AND {{$paramName2}:{$paramType}}";
                        $params[$paramName1] = $this->formatDateTimeParam($values[0]);
                        $params[$paramName2] = $this->formatDateTimeParam($values[1]);
                    } else {
                        $filters[] = "{$escapedAttr} BETWEEN {{$paramName1}:String} AND {{$paramName2}:String}";
                        $params[$paramName1] = $this->formatParamValue($values[0]);
                        $params[$paramName2] = $this->formatParamValue($values[1]);
                    }
                    break;

                case Query::TYPE_IN:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $inParams = [];
                    foreach ($values as $value) {
                        $paramName = 'param_' . $paramCounter++;
                        $inParams[] = "{{$paramName}:String}";
                        $params[$paramName] = $this->formatParamValue($value);
                    }
                    $filters[] = "{$escapedAttr} IN (" . implode(', ', $inParams) . ")";
                    break;

                case Query::TYPE_ORDER_DESC:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $orderBy[] = "{$escapedAttr} DESC";
                    break;

                case Query::TYPE_ORDER_ASC:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $orderBy[] = "{$escapedAttr} ASC";
                    break;

                case Query::TYPE_LIMIT:
                    if (!\is_int($values[0])) {
                        throw new \Exception('Invalid limit value. Expected int');
                    }
                    $limit = $values[0];
                    $params['limit'] = $limit;
                    break;

                case Query::TYPE_OFFSET:
                    if (!\is_int($values[0])) {
                        throw new \Exception('Invalid offset value. Expected int');
                    }
                    $offset = $values[0];
                    $params['offset'] = $offset;
                    break;
            }
        }

        $result = [
            'filters' => $filters,
            'params' => $params,
        ];

        if (!empty($orderBy)) {
            $result['orderBy'] = $orderBy;
        }

        if ($limit !== null) {
            $result['limit'] = $limit;
        }

        if ($offset !== null) {
            $result['offset'] = $offset;
        }

        return $result;
    }

    /**
     * Create multiple audit log entries in batch.
     *
     * @param array<array<string, mixed>> $logs The logs to insert
     * @throws Exception
     */
    public function createBatch(array $logs): bool
    {
        if (empty($logs)) {
            return true;
        }

        $tableName = $this->getTableName();
        $escapedDatabaseAndTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        // Get all attribute column names
        $attributeColumns = $this->getColumnNames();

        // Build column list starting with id
        $columns = ['id'];

        // Determine which attribute columns are present in any log
        $presentColumns = [];
        foreach ($logs as $log) {
            foreach ($attributeColumns as $column) {
                if (isset($log[$column]) && !in_array($column, $presentColumns, true)) {
                    $presentColumns[] = $column;
                }
            }
        }

        // Add present columns in the order they're defined in attributes
        foreach ($attributeColumns as $column) {
            if (in_array($column, $presentColumns, true)) {
                $columns[] = $column;
            }
        }

        // Always include time column
        if (!in_array('time', $columns, true)) {
            $columns[] = 'time';
        }

        if ($this->sharedTables) {
            $columns[] = 'tenant';
        }

        $ids = [];
        $paramCounter = 0;
        $params = [];
        $valueClauses = [];

        foreach ($logs as $log) {
            /** @var array<string, mixed> $log */
            $id = uniqid('', true);
            $ids[] = $id;

            // Create parameter placeholders for this row
            $paramKeys = [];
            $paramValues = [];
            $placeholders = [];

            // Add id first
            $paramKey = 'id_' . $paramCounter;
            $paramKeys[] = $paramKey;
            $paramValues[] = $id;
            $params[$paramKey] = $id;
            $placeholders[] = '{' . $paramKey . ':String}';

            // Add all present columns in order
            foreach ($columns as $column) {
                if ($column === 'id') {
                    continue; // Already added
                }

                if ($column === 'tenant') {
                    continue; // Handle separately below
                }

                $paramKey = $column . '_' . $paramCounter;
                $paramKeys[] = $paramKey;

                // Get attribute metadata to determine nullability and requirements
                $attributeMeta = $this->getAttributeMetadata($column);
                $isRequired = $attributeMeta !== null && isset($attributeMeta['required']) && $attributeMeta['required'];
                $value = null;
                $placeholder = '';

                // Determine value based on column type
                if ($column === 'time') {
                    /** @var string|\DateTime|null $timeVal */
                    $timeVal = $log['time'] ?? null;

                    if ($timeVal === null && $isRequired) {
                        throw new Exception("Required attribute 'time' is missing in batch log entry");
                    }

                    $value = $this->formatDateTimeForClickHouse($timeVal);
                    $params[$paramKey] = $value;
                    // time is always non-nullable in ClickHouse
                    $placeholder = '{' . $paramKey . ':String}';
                } elseif ($column === 'data') {
                    /** @var array<string, mixed>|null $dataVal */
                    $dataVal = $log['data'] ?? null;

                    if ($dataVal === null && $isRequired) {
                        throw new Exception("Required attribute 'data' is missing in batch log entry");
                    }

                    $value = json_encode($dataVal ?? []);
                    $params[$paramKey] = $value;
                    // data is nullable in schema
                    $placeholder = $isRequired ? '{' . $paramKey . ':String}' : '{' . $paramKey . ':Nullable(String)}';
                } else {
                    // Regular attributes
                    $value = $log[$column] ?? null;

                    if ($value === null && $isRequired) {
                        throw new Exception("Required attribute '{$column}' is missing in batch log entry");
                    }

                    $params[$paramKey] = $value;
                    // Use metadata to determine if nullable
                    $placeholder = $isRequired ? '{' . $paramKey . ':String}' : '{' . $paramKey . ':Nullable(String)}';
                }

                $paramValues[] = $value;
                $placeholders[] = $placeholder;
            }

            if ($this->sharedTables) {
                $paramKey = 'tenant_' . $paramCounter;
                $params[$paramKey] = $this->tenant;
                $placeholders[] = '{' . $paramKey . ':Nullable(UInt64)}';
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
     * Escapes all column names to prevent SQL injection.
     *
     * @return string
     */
    private function getSelectColumns(): string
    {
        $columns = [
            $this->escapeIdentifier('id'),
            $this->escapeIdentifier('userId'),
            $this->escapeIdentifier('event'),
            $this->escapeIdentifier('resource'),
            $this->escapeIdentifier('userAgent'),
            $this->escapeIdentifier('ip'),
            $this->escapeIdentifier('location'),
            $this->escapeIdentifier('time'),
            $this->escapeIdentifier('data'),
        ];

        if ($this->sharedTables) {
            $columns[] = $this->escapeIdentifier('tenant');
        }

        return implode(', ', $columns);
    }

    /**
     * Build tenant filter clause based on current tenant context.
     * Escapes column name to prevent SQL injection.
     *
     * @return string
     */
    private function getTenantFilter(): string
    {
        if (!$this->sharedTables || $this->tenant === null) {
            return '';
        }

        $escapedTenant = $this->escapeIdentifier('tenant');
        return " AND {$escapedTenant} = {$this->tenant}";
    }

    /**
     * Build time WHERE clause and parameters with safe parameter placeholders.
     * Escapes column name to prevent SQL injection.
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

        $escapedTime = $this->escapeIdentifier('time');

        if ($afterStr !== null && $beforeStr !== null) {
            $conditions[] = "{$escapedTime} BETWEEN {after:String} AND {before:String}";
            $params['after'] = $afterStr;
            $params['before'] = $beforeStr;

            return ['clause' => ' AND ' . $conditions[0], 'params' => $params];
        }

        if ($afterStr !== null) {
            $conditions[] = "{$escapedTime} > {after:String}";
            $params['after'] = $afterStr;
        }

        if ($beforeStr !== null) {
            $conditions[] = "{$escapedTime} < {before:String}";
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
        $escapedUserId = $this->escapeIdentifier('userId');
        $escapedTime = $this->escapeIdentifier('time');

        $sql = "
            SELECT " . $this->getSelectColumns() . "
            FROM {$escapedTable}
            WHERE {$escapedUserId} = {userId:String}{$tenantFilter}{$time['clause']}
            ORDER BY {$escapedTime} {$order}
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
        $escapedUserId = $this->escapeIdentifier('userId');

        $sql = "
            SELECT count()
            FROM {$escapedTable}
            WHERE {$escapedUserId} = {userId:String}{$tenantFilter}{$time['clause']}
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
        $escapedResource = $this->escapeIdentifier('resource');
        $escapedTime = $this->escapeIdentifier('time');

        $sql = "
            SELECT " . $this->getSelectColumns() . "
            FROM {$escapedTable}
            WHERE {$escapedResource} = {resource:String}{$tenantFilter}{$time['clause']}
            ORDER BY {$escapedTime} {$order}
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
        $escapedResource = $this->escapeIdentifier('resource');

        $sql = "
            SELECT count()
            FROM {$escapedTable}
            WHERE {$escapedResource} = {resource:String}{$tenantFilter}{$time['clause']}
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
        $escapedUserId = $this->escapeIdentifier('userId');
        $escapedEvent = $this->escapeIdentifier('event');

        $sql = "
            SELECT count()
            FROM {$escapedTable}
            WHERE {$escapedUserId} = {userId:String} AND {$escapedEvent} IN ({$eventList['clause']}){$tenantFilter}{$time['clause']}
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
        $escapedResource = $this->escapeIdentifier('resource');
        $escapedEvent = $this->escapeIdentifier('event');

        $sql = "
            SELECT count()
            FROM {$escapedTable}
            WHERE {$escapedResource} = {resource:String} AND {$escapedEvent} IN ({$eventList['clause']}){$tenantFilter}{$time['clause']}
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
