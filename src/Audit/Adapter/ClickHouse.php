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
            $escapedAttributes = array_map(fn (string $attr) => $this->escapeIdentifier($attr), $attributes);
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
     * Format datetime for ClickHouse compatibility.
     * Converts datetime to 'YYYY-MM-DD HH:MM:SS.mmm' format without timezone suffix.
     * ClickHouse DateTime64(3) type expects this format as timezone is handled by column metadata.
     * Works with DateTime objects, strings, and other datetime representations.
     *
     * @param \DateTime|string|null $dateTime The datetime value to format
     * @return string The formatted datetime string in ClickHouse compatible format
     * @throws Exception If the datetime string cannot be parsed
     */
    private function formatDateTime(\DateTime|string|null $dateTime): string
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
        $logId = uniqid('', true);

        // Format time - use provided time or current time
        /** @var string|\DateTime|null $providedTime */
        $providedTime = $log['time'] ?? null;
        $formattedTime = $this->formatDateTime($providedTime);

        $tableName = $this->getTableName();

        // Extract additional attributes from the data array
        /** @var array<string, mixed> $logData */
        $logData = $log['data'] ?? [];

        // Build column list and placeholders dynamically from attributes
        $insertColumns = ['id', 'time'];
        $valuePlaceholders = ['{id:String}', '{time:String}'];
        $queryParams = [
            'id' => $logId,
            'time' => $formattedTime,
        ];

        // Get all column names from attributes
        $schemaColumns = $this->getColumnNames();

        // Separate data for the data column (non-schema attributes)
        $nonSchemaData = $logData;

        $resourceValue = $log['resource'] ?? null;
        if (!\is_string($resourceValue)) {
            $resourceValue = '';
        }
        $resource = $this->parseResource($resourceValue);

        foreach ($schemaColumns as $columnName) {
            if ($columnName === 'time') {
                // Skip time - already handled above
                continue;
            }

            // Get attribute metadata to determine if required and nullable
            $attributeMetadata = $this->getAttribute($columnName);
            $isRequiredAttribute = $attributeMetadata !== null && isset($attributeMetadata['required']) && $attributeMetadata['required'];
            $isNullableAttribute = $attributeMetadata !== null && (!isset($attributeMetadata['required']) || !$attributeMetadata['required']);

            // For 'data' column, we'll handle it separately at the end
            if ($columnName === 'data') {
                continue;
            }

            // Check if value exists in main log first, then in data array
            $attributeValue = null;
            $hasAttributeValue = false;

            if (isset($log[$columnName])) {
                // Value is in main log (e.g., userId, event, resource, etc.)
                $attributeValue = $log[$columnName];
                $hasAttributeValue = true;
            } elseif (isset($logData[$columnName])) {
                // Value is in data array (additional attributes)
                $attributeValue = $logData[$columnName];
                $hasAttributeValue = true;
                // Remove from non-schema data as it's now a dedicated column
                unset($nonSchemaData[$columnName]);
            } elseif (isset($resource[$columnName])) {
                // Value is in parsed resource (e.g., resourceType, resourceId, resourceParent)
                $attributeValue = $resource[$columnName];
                $hasAttributeValue = true;
            }

            // Validate required attributes
            if ($isRequiredAttribute && !$hasAttributeValue) {
                throw new \InvalidArgumentException("Required attribute '{$columnName}' is missing in log entry");
            }

            if ($hasAttributeValue) {
                $insertColumns[] = $columnName;
                $queryParams[$columnName] = $attributeValue;

                // Determine placeholder type based on attribute metadata
                if ($isNullableAttribute) {
                    $valuePlaceholders[] = '{' . $columnName . ':Nullable(String)}';
                } else {
                    $valuePlaceholders[] = '{' . $columnName . ':String}';
                }
            }
        }

        // Add the data column with remaining non-schema attributes
        $insertColumns[] = 'data';
        $queryParams['data'] = json_encode($nonSchemaData);
        $valuePlaceholders[] = '{data:Nullable(String)}';

        if ($this->sharedTables) {
            $insertColumns[] = 'tenant';
            $valuePlaceholders[] = '{tenant:Nullable(UInt64)}';
            $queryParams['tenant'] = $this->tenant;
        }

        $escapedDatabaseAndTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);
        $insertSql = "
            INSERT INTO {$escapedDatabaseAndTable}
            (" . implode(', ', $insertColumns) . ")
            VALUES (
                " . implode(", ", $valuePlaceholders) . "
            )
        ";

        $this->query($insertSql, $queryParams);

        // Retrieve the created log using getById to ensure consistency
        $createdLog = $this->getById($logId);
        if ($createdLog === null) {
            throw new Exception("Failed to retrieve created log with ID: {$logId}");
        }

        return $createdLog;
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
            /** @var string $attribute */

            $values = $query->getValues();
            $values = $query->getValues();

            switch ($method) {
                case Query::TYPE_EQUAL:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier((string) $attribute);
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "{$escapedAttr} = {{$paramName}:String}";
                    $params[$paramName] = $this->formatParamValue($values[0]);
                    break;

                case Query::TYPE_LESSER:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier((string) $attribute);
                    $paramName = 'param_' . $paramCounter++;
                    if ($attribute === 'time') {
                        $filters[] = "{$escapedAttr} < {{$paramName}:DateTime64(3)}";
                        /** @var \DateTime|string|null $val */
                        $val = $values[0];
                        $params[$paramName] = $this->formatDateTime($val);
                    } else {
                        $filters[] = "{$escapedAttr} < {{$paramName}:String}";
                        $params[$paramName] = $this->formatParamValue($values[0]);
                    }
                    break;

                case Query::TYPE_GREATER:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier((string) $attribute);
                    $paramName = 'param_' . $paramCounter++;
                    if ($attribute === 'time') {
                        $filters[] = "{$escapedAttr} > {{$paramName}:DateTime64(3)}";
                        /** @var \DateTime|string|null $val */
                        $val = $values[0];
                        $params[$paramName] = $this->formatDateTime($val);
                    } else {
                        $filters[] = "{$escapedAttr} > {{$paramName}:String}";
                        $params[$paramName] = $this->formatParamValue($values[0]);
                    }
                    break;

                case Query::TYPE_BETWEEN:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier((string) $attribute);
                    $paramName1 = 'param_' . $paramCounter++;
                    $paramName2 = 'param_' . $paramCounter++;
                    // Use DateTime64 type for time column, String for others
                    // This prevents type mismatch when comparing DateTime64 with timezone-suffixed strings
                    if ($attribute === 'time') {
                        $paramType = 'DateTime64(3)';
                        $filters[] = "{$escapedAttr} BETWEEN {{$paramName1}:{$paramType}} AND {{$paramName2}:{$paramType}}";
                        /** @var \DateTime|string|null $val1 */
                        $val1 = $values[0];
                        /** @var \DateTime|string|null $val2 */
                        $val2 = $values[1];
                        $params[$paramName1] = $this->formatDateTime($val1);
                        $params[$paramName2] = $this->formatDateTime($val2);
                    } else {
                        $filters[] = "{$escapedAttr} BETWEEN {{$paramName1}:String} AND {{$paramName2}:String}";
                        $params[$paramName1] = $this->formatParamValue($values[0]);
                        $params[$paramName2] = $this->formatParamValue($values[1]);
                    }
                    break;

                case Query::TYPE_IN:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier((string) $attribute);
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
        $schemaColumns = $this->getColumnNames();

        // Process each log to extract additional attributes from data
        $processedLogs = [];
        foreach ($logs as $log) {
            /** @var array<string, mixed> $logData */
            $logData = $log['data'] ?? [];

            // Separate data for non-schema attributes
            $nonSchemaData = $logData;
            $resourceValue = $log['resource'] ?? null;
            if (!\is_string($resourceValue)) {
                $resourceValue = '';
            }
            $resource = $this->parseResource($resourceValue);
            $processedLog = $log;

            // Extract schema attributes: check main log first, then data array
            foreach ($schemaColumns as $columnName) {
                if ($columnName === 'data' || $columnName === 'time') {
                    continue;
                }

                // If attribute not in main log, check data array
                if (!isset($processedLog[$columnName]) && isset($logData[$columnName])) {
                    $processedLog[$columnName] = $logData[$columnName];
                    unset($nonSchemaData[$columnName]);
                } elseif (!isset($processedLog[$columnName]) && isset($resource[$columnName])) {
                    // Check parsed resource for resourceType, resourceId, resourceParent
                    $processedLog[$columnName] = $resource[$columnName];
                } elseif (isset($processedLog[$columnName]) && isset($logData[$columnName])) {
                    // If in both, main log takes precedence, remove from data
                    unset($nonSchemaData[$columnName]);
                }
            }

            // Update data with remaining non-schema attributes
            $processedLog['data'] = $nonSchemaData;
            $processedLogs[] = $processedLog;
        }

        // Build column list starting with id and time
        $insertColumns = ['id', 'time'];

        // Determine which attribute columns are present in any log
        $presentColumns = [];
        foreach ($processedLogs as $processedLog) {
            foreach ($schemaColumns as $columnName) {
                if ($columnName === 'time') {
                    continue; // Already in insertColumns
                }
                if (isset($processedLog[$columnName]) && !in_array($columnName, $presentColumns, true)) {
                    $presentColumns[] = $columnName;
                }
            }
        }

        // Add present columns in the order they're defined in attributes
        foreach ($schemaColumns as $columnName) {
            if ($columnName === 'time') {
                continue; // Already added
            }
            if (in_array($columnName, $presentColumns, true)) {
                $insertColumns[] = $columnName;
            }
        }

        if ($this->sharedTables) {
            $insertColumns[] = 'tenant';
        }

        $paramCounter = 0;
        $queryParams = [];
        $valueClauses = [];

        foreach ($processedLogs as $processedLog) {
            $logId = uniqid('', true);
            $valuePlaceholders = [];

            // Add id
            $paramKey = 'id_' . $paramCounter;
            $queryParams[$paramKey] = $logId;
            $valuePlaceholders[] = '{' . $paramKey . ':String}';

            // Add time
            /** @var string|\DateTime|null $providedTime */
            $providedTime = $processedLog['time'] ?? null;
            $formattedTime = $this->formatDateTime($providedTime);
            $paramKey = 'time_' . $paramCounter;
            $queryParams[$paramKey] = $formattedTime;
            $valuePlaceholders[] = '{' . $paramKey . ':String}';

            // Add all other present columns
            foreach ($insertColumns as $columnName) {
                if ($columnName === 'id' || $columnName === 'time' || $columnName === 'tenant') {
                    continue; // Already handled
                }

                $paramKey = $columnName . '_' . $paramCounter;

                // Get attribute metadata to determine if required and nullable
                $attributeMetadata = $this->getAttribute($columnName);
                $isRequiredAttribute = $attributeMetadata !== null && isset($attributeMetadata['required']) && $attributeMetadata['required'];
                $isNullableAttribute = $attributeMetadata !== null && (!isset($attributeMetadata['required']) || !$attributeMetadata['required']);

                $attributeValue = null;
                $hasAttributeValue = false;

                if ($columnName === 'data') {
                    // Data column - encode as JSON
                    /** @var array<string, mixed> $dataValue */
                    $dataValue = $processedLog['data'];
                    $attributeValue = json_encode($dataValue);
                    $hasAttributeValue = true;
                } elseif (isset($processedLog[$columnName])) {
                    $attributeValue = $processedLog[$columnName];
                    $hasAttributeValue = true;
                }

                // Validate required attributes
                if ($isRequiredAttribute && !$hasAttributeValue) {
                    throw new \InvalidArgumentException("Required attribute '{$columnName}' is missing in batch log entry");
                }

                $queryParams[$paramKey] = $attributeValue;

                // Determine placeholder type based on attribute metadata
                if ($isNullableAttribute) {
                    $valuePlaceholders[] = '{' . $paramKey . ':Nullable(String)}';
                } else {
                    $valuePlaceholders[] = '{' . $paramKey . ':String}';
                }
            }

            if ($this->sharedTables) {
                $paramKey = 'tenant_' . $paramCounter;
                $queryParams[$paramKey] = $this->tenant;
                $valuePlaceholders[] = '{' . $paramKey . ':Nullable(UInt64)}';
            }

            $valueClauses[] = '(' . implode(', ', $valuePlaceholders) . ')';
            $paramCounter++;
        }

        $insertSql = "
            INSERT INTO {$escapedDatabaseAndTable}
            (" . implode(', ', $insertColumns) . ")
            VALUES " . implode(', ', $valueClauses);

        $this->query($insertSql, $queryParams);
        return true;
    }

    /**
     * Parse ClickHouse query result into Log objects.
     * Dynamically maps columns based on current attribute definitions.
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

        // Build the expected column order dynamically (matching getSelectColumns order)
        $selectColumns = ['id'];
        foreach ($this->getAttributes() as $attribute) {
            $id = $attribute['$id'];
            if ($id !== 'data') {
                $selectColumns[] = $id;
            }
        }
        $selectColumns[] = 'data';

        if ($this->sharedTables) {
            $selectColumns[] = 'tenant';
        }

        $expectedColumns = count($selectColumns);

        foreach ($lines as $line) {
            if (empty(trim($line))) {
                continue;
            }

            $columns = explode("\t", $line);
            if (count($columns) < $expectedColumns) {
                continue;
            }

            // Helper function to parse nullable string fields
            // ClickHouse TabSeparated format uses \N for NULL, but empty strings are also treated as null for nullable fields
            $parseNullableString = static function ($value): ?string {
                if ($value === '\\N' || $value === '') {
                    return null;
                }
                return $value;
            };

            // Build document dynamically by mapping columns to values
            $document = [];
            foreach ($selectColumns as $index => $columnName) {
                if (!isset($columns[$index])) {
                    continue;
                }

                $value = $columns[$index];

                if ($columnName === 'data') {
                    // Decode JSON data column
                    $document[$columnName] = json_decode($value, true) ?? [];
                } elseif ($columnName === 'tenant') {
                    // Parse tenant as integer or null
                    $document[$columnName] = ($value === '\\N' || $value === '') ? null : (int) $value;
                } elseif ($columnName === 'time') {
                    // Convert ClickHouse timestamp format back to ISO 8601
                    // ClickHouse: 2025-12-07 23:33:54.493
                    // ISO 8601:   2025-12-07T23:33:54.493+00:00
                    $parsedTime = $value;
                    if (strpos($parsedTime, 'T') === false) {
                        $parsedTime = str_replace(' ', 'T', $parsedTime) . '+00:00';
                    }
                    $document[$columnName] = $parsedTime;
                } else {
                    // Get attribute metadata to check if nullable
                    $col = $columnName;
                    /** @var string $col */
                    $attribute = $this->getAttribute($col);
                    if ($attribute && !$attribute['required']) {
                        // Nullable field - parse null values
                        $document[$columnName] = $parseNullableString($value);
                    } else {
                        // Required field - use value as-is
                        $document[$columnName] = $value;
                    }
                }
            }

            // Add special $id field if present
            if (isset($document['id'])) {
                $document['$id'] = $document['id'];
                unset($document['id']);
            }

            $documents[] = new Log($document);
        }

        return $documents;
    }

    /**
     * Get the SELECT column list for queries.
     * Dynamically builds the column list from attributes, excluding 'data' column.
     * Escapes all column names to prevent SQL injection.
     *
     * @return string
     */
    private function getSelectColumns(): string
    {
        $columns = [];

        // Add id column first (not part of attributes)
        $columns[] = $this->escapeIdentifier('id');

        // Dynamically add all attribute columns except 'data'
        foreach ($this->getAttributes() as $attribute) {
            $id = $attribute['$id'];
            /** @var string $id */
            if ($id !== 'data') {
                $columns[] = $this->escapeIdentifier($id);
            }
        }

        // Add data column at the end
        $columns[] = $this->escapeIdentifier('data');

        // Add tenant column if shared tables are enabled
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
    /** @phpstan-ignore-next-line */
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
    /** @phpstan-ignore-next-line */
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
     * Dynamically determines the ClickHouse type based on attribute metadata.
     * DateTime attributes use DateTime64(3), all others use String.
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

        // Dynamically determine type based on attribute metadata
        // DateTime attributes use DateTime64(3), all others use String
        $type = (isset($attribute['type']) && $attribute['type'] === Database::VAR_DATETIME)
            ? 'DateTime64(3)'
            : 'String';

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
        $queries = [
            Query::equal('userId', $userId),
        ];

        if ($after !== null && $before !== null) {
            $queries[] = Query::between('time', $after, $before);
        } elseif ($after !== null) {
            $queries[] = Query::greaterThan('time', $after);
        } elseif ($before !== null) {
            $queries[] = Query::lessThan('time', $before);
        }

        $queries[] = $ascending ? Query::orderAsc('time') : Query::orderDesc('time');
        $queries[] = Query::limit($limit);
        $queries[] = Query::offset($offset);

        return $this->find($queries);
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
        $queries = [
            Query::equal('userId', $userId),
        ];

        if ($after !== null && $before !== null) {
            $queries[] = Query::between('time', $after, $before);
        } elseif ($after !== null) {
            $queries[] = Query::greaterThan('time', $after);
        } elseif ($before !== null) {
            $queries[] = Query::lessThan('time', $before);
        }

        return count($this->find($queries));
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
        $queries = [
            Query::equal('resource', $resource),
        ];

        if ($after !== null && $before !== null) {
            $queries[] = Query::between('time', $after, $before);
        } elseif ($after !== null) {
            $queries[] = Query::greaterThan('time', $after);
        } elseif ($before !== null) {
            $queries[] = Query::lessThan('time', $before);
        }

        $queries[] = $ascending ? Query::orderAsc('time') : Query::orderDesc('time');
        $queries[] = Query::limit($limit);
        $queries[] = Query::offset($offset);

        return $this->find($queries);
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
        $queries = [
            Query::equal('resource', $resource),
        ];

        if ($after !== null && $before !== null) {
            $queries[] = Query::between('time', $after, $before);
        } elseif ($after !== null) {
            $queries[] = Query::greaterThan('time', $after);
        } elseif ($before !== null) {
            $queries[] = Query::lessThan('time', $before);
        }

        return count($this->find($queries));
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
        $queries = [
            Query::equal('userId', $userId),
            Query::in('event', $events),
        ];

        if ($after !== null && $before !== null) {
            $queries[] = Query::between('time', $after, $before);
        } elseif ($after !== null) {
            $queries[] = Query::greaterThan('time', $after);
        } elseif ($before !== null) {
            $queries[] = Query::lessThan('time', $before);
        }

        $queries[] = $ascending ? Query::orderAsc('time') : Query::orderDesc('time');
        $queries[] = Query::limit($limit);
        $queries[] = Query::offset($offset);

        return $this->find($queries);
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
        $queries = [
            Query::equal('userId', $userId),
            Query::in('event', $events),
        ];

        if ($after !== null && $before !== null) {
            $queries[] = Query::between('time', $after, $before);
        } elseif ($after !== null) {
            $queries[] = Query::greaterThan('time', $after);
        } elseif ($before !== null) {
            $queries[] = Query::lessThan('time', $before);
        }

        return count($this->find($queries));
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
        $queries = [
            Query::equal('resource', $resource),
            Query::in('event', $events),
        ];

        if ($after !== null && $before !== null) {
            $queries[] = Query::between('time', $after, $before);
        } elseif ($after !== null) {
            $queries[] = Query::greaterThan('time', $after);
        } elseif ($before !== null) {
            $queries[] = Query::lessThan('time', $before);
        }

        $queries[] = $ascending ? Query::orderAsc('time') : Query::orderDesc('time');
        $queries[] = Query::limit($limit);
        $queries[] = Query::offset($offset);

        return $this->find($queries);
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
        $queries = [
            Query::equal('resource', $resource),
            Query::in('event', $events),
        ];

        if ($after !== null && $before !== null) {
            $queries[] = Query::between('time', $after, $before);
        } elseif ($after !== null) {
            $queries[] = Query::greaterThan('time', $after);
        } elseif ($before !== null) {
            $queries[] = Query::lessThan('time', $before);
        }

        return count($this->find($queries));
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
