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

    /**
     * Filter methods that must be supplied at least one value. Empty `values`
     * arrays for these methods are rejected up front so they can't silently
     * compile into a "no filter applied" WHERE clause.
     *
     * @var list<string>
     */
    private const VALUE_REQUIRED_METHODS = [
        Query::TYPE_EQUAL,
        Query::TYPE_NOT_EQUAL,
        Query::TYPE_LESSER,
        Query::TYPE_LESSER_EQUAL,
        Query::TYPE_GREATER,
        Query::TYPE_GREATER_EQUAL,
        Query::TYPE_BETWEEN,
        Query::TYPE_NOT_BETWEEN,
        Query::TYPE_CONTAINS,
        Query::TYPE_NOT_CONTAINS,
        Query::TYPE_STARTS_WITH,
        Query::TYPE_NOT_STARTS_WITH,
        Query::TYPE_ENDS_WITH,
        Query::TYPE_NOT_ENDS_WITH,
        Query::TYPE_REGEX,
        Query::TYPE_SELECT,
    ];

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

    protected bool $asyncCleanup = false;

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
     * Set the table name for subsequent operations.
     *
     * @param string $table
     * @return self
     * @throws Exception
     */
    public function setTable(string $table): self
    {
        $this->validateIdentifier($table, 'Table');
        $this->table = $table;
        return $this;
    }

    /**
     * Get the table name (without namespace prefix).
     *
     * @return string
     */
    public function getTable(): string
    {
        return $this->table;
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
     * Set whether cleanup() should return after scheduling the DELETE mutation
     * rather than waiting for it to complete. When enabled, the DELETE is sent
     * with `SETTINGS lightweight_deletes_sync = 0` and the HTTP call returns
     * as soon as the mutation is queued.
     *
     * @param bool $asyncCleanup
     * @return self
     */
    public function setAsyncCleanup(bool $asyncCleanup): self
    {
        $this->asyncCleanup = $asyncCleanup;
        return $this;
    }

    /**
     * Get whether cleanup() runs asynchronously.
     *
     * @return bool
     */
    public function isAsyncCleanup(): bool
    {
        return $this->asyncCleanup;
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

        foreach ($parentAttributes as &$attribute) {
            if (($attribute['$id'] ?? null) === 'userId') {
                $attribute['$id'] = 'actorId';
                break;
            }
        }
        unset($attribute);

        return [
            ...$parentAttributes,
            [
                '$id' => 'actorType',
                'type' => Database::VAR_STRING,
                'size' => Database::LENGTH_KEY,
                'required' => true,
                'default' => null,
                'signed' => true,
                'array' => false,
                'filters' => [],
            ],
            [
                '$id' => 'actorInternalId',
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

        foreach ($parentIndexes as &$index) {
            if (($index['$id'] ?? null) === 'idx_userId_event') {
                $index['$id'] = 'idx_actorId_event';
                $index['attributes'] = ['actorId', 'event'];
                break;
            }
        }
        unset($index);

        return [
            ...$parentIndexes,
            [
                '$id' => '_key_actor_internal_and_event',
                'type' => Database::INDEX_KEY,
                'attributes' => ['actorInternalId', 'event'],
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
                '$id' => '_key_actor_internal_id',
                'type' => Database::INDEX_KEY,
                'attributes' => ['actorInternalId'],
                'lengths' => [],
                'orders' => [],
            ],
            [
                '$id' => '_key_actor_type',
                'type' => Database::INDEX_KEY,
                'attributes' => ['actorType'],
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
     * This unified method supports two modes of operation:
     *
     * 1. **Parameterized queries** (when $params is provided):
     *    Uses ClickHouse query parameters sent as POST multipart form data.
     *    Parameters are referenced in SQL using syntax: {paramName:Type}
     *    Example: SELECT * WHERE id = {id:String}
     *
     * 2. **JSON body queries** (when $jsonRows is provided):
     *    Uses JSONEachRow format for optimal INSERT performance.
     *    SQL is sent via URL query string, JSON data as POST body.
     *    Each row is a JSON object on a separate line.
     *
     * ClickHouse handles all parameter escaping and type conversion internally,
     * making both approaches fully injection-safe.
     *
     * @param string $sql The SQL query to execute
     * @param array<string, mixed> $params Key-value pairs for query parameters (for SELECT/UPDATE/DELETE)
     * @param array<int, array<string, mixed>>|null $jsonRows Array of rows for JSONEachRow INSERT operations
     * @return string Response body
     * @throws Exception
     */
    private function query(string $sql, array $params = [], ?array $jsonRows = null): string
    {
        $scheme = $this->secure ? 'https' : 'http';

        // Update the database header for each query (in case setDatabase was called)
        $this->client->addHeader('X-ClickHouse-Database', $this->database);

        try {
            if ($jsonRows !== null) {
                // JSON body mode for INSERT operations with JSONEachRow format
                $url = "{$scheme}://{$this->host}:{$this->port}/?query=" . urlencode($sql);

                // Build JSONEachRow body - each row on a separate line
                $jsonLines = [];
                foreach ($jsonRows as $row) {
                    try {
                        $encoded = json_encode($row, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
                    } catch (\JsonException $e) {
                        throw new Exception('Failed to encode row to JSON: ' . $e->getMessage());
                    }
                    $jsonLines[] = $encoded;
                }
                $body = implode("\n", $jsonLines);
            } else {
                // Parameterized query mode using multipart form data
                $url = "{$scheme}://{$this->host}:{$this->port}/";

                // Build multipart form data body with query and parameters
                $body = ['query' => $sql];
                foreach ($params as $key => $value) {
                    $body['param_' . $key] = $this->formatParamValue($value);
                }
            }

            $response = $this->client->fetch(
                url: $url,
                method: Client::METHOD_POST,
                body: $body
            );

            if ($response->getStatusCode() !== 200) {
                $responseBody = $response->getBody();
                $responseBody = is_string($responseBody) ? $responseBody : '';
                throw new Exception("ClickHouse query failed with HTTP {$response->getStatusCode()}: {$responseBody}");
            }

            $responseBody = $response->getBody();
            return is_string($responseBody) ? $responseBody : '';
        } catch (Exception $e) {
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
            try {
                return json_encode($value, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                throw new Exception('Failed to encode array parameter to JSON: ' . $e->getMessage());
            }
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
    /**
     * Translate legacy user* attribute names to actor* column names.
     *
     * @param string $attribute
     * @return string
     */
    private function translateAttribute(string $attribute): string
    {
        return match ($attribute) {
            'userId' => 'actorId',
            'userType' => 'actorType',
            'userInternalId' => 'actorInternalId',
            default => $attribute,
        };
    }

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
     * Create an audit log entry
     *
     * @param array<string, mixed> $log The log data
     * @throws Exception
     */
    public function create(array $log): Log
    {
        // Generate ID if not provided
        $logId = $log['id'] ?? uniqid('', true);
        if (!is_string($logId)) {
            throw new Exception('Log ID must be a string');
        }
        $log['id'] = $logId;

        // Use createBatch for the actual insertion
        $this->createBatch([$log]);

        // Retrieve the created log using getById to ensure consistency
        $createdLog = $this->getById($logId);
        if ($createdLog === null) {
            throw new Exception("Failed to retrieve created log with ID: {$logId}");
        }

        return $createdLog;
    }

    /**
     * Get a single log by its ID using JSON format for reliable parsing.
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
            FORMAT JSON
        ";

        $result = $this->query($sql, ['id' => $id]);
        $logs = $this->parseJsonResults($result);

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

        // Random ordering can't combine with anything that asks for a
        // specific row order: cursor pagination needs a stable anchor, and
        // mixing column-based ORDER BY with rand() would silently drop the
        // column order. Reject loudly in both cases so the caller fixes the
        // query rather than getting unexpected results.
        if (!empty($parsed['randomOrder']) && isset($parsed['cursor'])) {
            throw new Exception('Cursor pagination cannot be combined with orderRandom');
        }
        if (!empty($parsed['randomOrder']) && !empty($parsed['orderBy'])) {
            throw new Exception('orderRandom cannot be combined with orderAsc/orderDesc');
        }

        // Build SELECT clause — respect Query::select if provided, otherwise
        // fall back to the full column list.
        $selectColumns = $this->buildProjection($parsed['select'] ?? null);

        $filters = $parsed['filters'];
        $params = $parsed['params'];
        $orderAttributes = $parsed['orderAttributes'] ?? [];
        $cursorDirection = $parsed['cursorDirection'] ?? null;

        if (isset($parsed['cursor'])) {
            $orderAttributes = $this->resolveCursorOrder($orderAttributes);
            $cursorWhere = $this->buildCursorWhere($orderAttributes, $parsed['cursor'], $cursorDirection ?? 'after', $params);
            $filters[] = $cursorWhere['clause'];
            $params = $cursorWhere['params'];
        }

        // Build WHERE clause
        $whereClause = '';
        $tenantFilter = $this->getTenantFilter();
        if (!empty($filters) || $tenantFilter) {
            $conditions = $filters;
            if ($tenantFilter) {
                $conditions[] = ltrim($tenantFilter, ' AND');
            }
            $whereClause = ' WHERE ' . implode(' AND ', $conditions);
        }

        // Build ORDER BY clause. orderRandom is mutually exclusive with
        // cursor and column ordering (rejected at the top of find()); when
        // cursor is in play, rebuild from orderAttributes (always non-empty
        // after resolveCursorOrder, which appends an id tiebreaker),
        // flipping directions for `cursorBefore`.
        $orderClause = '';
        if (!empty($parsed['randomOrder'])) {
            $orderClause = ' ORDER BY rand()';
        } elseif (isset($parsed['cursor'])) {
            $orderSql = $this->buildOrderBySql($orderAttributes, flip: $cursorDirection === 'before');
            $orderClause = ' ORDER BY ' . implode(', ', $orderSql);
        } elseif (!empty($parsed['orderBy'])) {
            $orderClause = ' ORDER BY ' . implode(', ', $parsed['orderBy']);
        }

        // Build LIMIT and OFFSET
        $limitClause = isset($parsed['limit']) ? ' LIMIT {limit:UInt64}' : '';
        $offsetClause = isset($parsed['offset']) ? ' OFFSET {offset:UInt64}' : '';

        $sql = "
            SELECT {$selectColumns}
            FROM {$escapedTable}{$whereClause}{$orderClause}{$limitClause}{$offsetClause}
            FORMAT JSON
        ";

        $result = $this->query($sql, $params);
        $rows = $this->parseJsonResults($result);

        if ($cursorDirection === 'before') {
            $rows = array_reverse($rows);
        }

        return $rows;
    }

    /**
     * Build the SELECT projection list. When `$select` is null, returns the
     * full column list from `getSelectColumns()`; otherwise validates and
     * escapes each requested column.
     *
     * `id` is always projected so `parseJsonResults` can map it back to the
     * `$id` field on the `Log` model. When `sharedTables` is enabled, the
     * `tenant` column is also always projected — it's metadata callers expect
     * on every row and the full-projection path already includes it. Callers
     * requesting a slim projection don't have to remember either.
     *
     * @param  list<string>|null  $select
     * @throws Exception
     */
    private function buildProjection(?array $select): string
    {
        if ($select === null) {
            return $this->getSelectColumns();
        }

        // Forced columns are injected here, so they're validated defensively.
        // User-supplied columns in $select are already validated inside the
        // TYPE_SELECT branch of parseQueries() — no need to walk
        // getAttributes() a second time per column.
        $forced = ['id'];
        if ($this->sharedTables) {
            $forced[] = 'tenant';
        }

        $columns = [];
        $seen = [];
        foreach ($forced as $column) {
            if (isset($seen[$column])) {
                continue;
            }
            $this->validateAttributeName($column);
            $columns[] = $this->escapeIdentifier($column);
            $seen[$column] = true;
        }
        foreach ($select as $column) {
            if (isset($seen[$column])) {
                continue;
            }
            $columns[] = $this->escapeIdentifier($column);
            $seen[$column] = true;
        }

        return implode(', ', $columns);
    }

    /**
     * Count logs using Query objects.
     *
     * When $max is non-null the count is bounded at the database level via a
     * `LIMIT {max}` inside a subquery — ClickHouse stops scanning once the cap
     * is reached, keeping large counts cheap (e.g. for "5000+" UI badges).
     *
     * @param array<Query> $queries
     * @param int|null $max Optional upper bound (inclusive) for the count
     * @return int
     * @throws Exception
     */
    public function count(array $queries = [], ?int $max = null): int
    {
        $tableName = $this->getTableName();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        // Parse queries - we only need filters and params, not ordering/limit/offset/cursor
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

        if ($max !== null) {
            $params['max'] = $max;
            $sql = "
                SELECT COUNT(*) as count
                FROM (
                    SELECT 1 FROM {$escapedTable}{$whereClause} LIMIT {max:UInt64}
                ) sub
                FORMAT TabSeparated
            ";
        } else {
            $sql = "
                SELECT COUNT(*) as count
                FROM {$escapedTable}{$whereClause}
                FORMAT TabSeparated
            ";
        }

        $result = $this->query($sql, $params);
        $trimmed = trim($result);

        return $trimmed !== '' ? (int) $trimmed : 0;
    }

    /**
     * Parse Query objects into SQL components.
     *
     * @param array<Query> $queries
     * @return array{filters: array<string>, params: array<string, mixed>, orderBy?: array<string>, orderAttributes?: array<int, array{attribute: string, direction: string}>, randomOrder?: bool, limit?: int, offset?: int, cursor?: array<string, mixed>, cursorDirection?: string, select?: list<string>}
     * @throws Exception
     */
    private function parseQueries(array $queries): array
    {
        $filters = [];
        $params = [];
        $orderBy = [];
        $orderAttributes = [];
        $limit = null;
        $offset = null;
        $cursor = null;
        $cursorDirection = null;
        $select = null;
        $randomOrder = false;
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
            $attribute = $this->translateAttribute($attribute);
            $values = $query->getValues();

            // Reject empty values for filter methods that take values — mirrors
            // the validator in utopia-php/database (Validator/Query/Filter.php)
            // and prevents silently dropping the WHERE fragment, which would
            // otherwise turn `Query::contains('attr', [])` into a full-table
            // match instead of an empty result.
            if (\in_array($method, self::VALUE_REQUIRED_METHODS, true) && empty($values)) {
                throw new \Exception(\ucfirst($method) . ' queries require at least one value.');
            }

            switch ($method) {
                case Query::TYPE_EQUAL:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $chType = $this->getParamType($attribute);

                    if (count($values) > 1) {
                        $inParams = [];
                        foreach ($values as $value) {
                            $paramName = 'param_' . $paramCounter++;
                            $inParams[] = "{{$paramName}:{$chType}}";
                            $params[$paramName] = $this->formatTypedValue($chType, $value);
                        }
                        $filters[] = "{$escapedAttr} IN (" . implode(', ', $inParams) . ")";
                    } else {
                        $paramName = 'param_' . $paramCounter++;
                        $filters[] = "{$escapedAttr} = {{$paramName}:{$chType}}";
                        $params[$paramName] = $this->formatTypedValue($chType, $values[0] ?? null);
                    }
                    break;

                case Query::TYPE_NOT_EQUAL:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $chType = $this->getParamType($attribute);
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "{$escapedAttr} != {{$paramName}:{$chType}}";
                    $params[$paramName] = $this->formatTypedValue($chType, $values[0] ?? null);
                    break;

                case Query::TYPE_LESSER:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $chType = $this->getParamType($attribute);
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "{$escapedAttr} < {{$paramName}:{$chType}}";
                    $params[$paramName] = $this->formatTypedValue($chType, $values[0] ?? null);
                    break;

                case Query::TYPE_LESSER_EQUAL:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $chType = $this->getParamType($attribute);
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "{$escapedAttr} <= {{$paramName}:{$chType}}";
                    $params[$paramName] = $this->formatTypedValue($chType, $values[0] ?? null);
                    break;

                case Query::TYPE_GREATER:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $chType = $this->getParamType($attribute);
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "{$escapedAttr} > {{$paramName}:{$chType}}";
                    $params[$paramName] = $this->formatTypedValue($chType, $values[0] ?? null);
                    break;

                case Query::TYPE_GREATER_EQUAL:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $chType = $this->getParamType($attribute);
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "{$escapedAttr} >= {{$paramName}:{$chType}}";
                    $params[$paramName] = $this->formatTypedValue($chType, $values[0] ?? null);
                    break;

                case Query::TYPE_BETWEEN:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $chType = $this->getParamType($attribute);
                    $paramName1 = 'param_' . $paramCounter++;
                    $paramName2 = 'param_' . $paramCounter++;
                    $filters[] = "{$escapedAttr} BETWEEN {{$paramName1}:{$chType}} AND {{$paramName2}:{$chType}}";
                    $params[$paramName1] = $this->formatTypedValue($chType, $values[0] ?? null);
                    $params[$paramName2] = $this->formatTypedValue($chType, $values[1] ?? null);
                    break;

                case Query::TYPE_NOT_BETWEEN:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $chType = $this->getParamType($attribute);
                    $paramName1 = 'param_' . $paramCounter++;
                    $paramName2 = 'param_' . $paramCounter++;
                    $filters[] = "{$escapedAttr} NOT BETWEEN {{$paramName1}:{$chType}} AND {{$paramName2}:{$chType}}";
                    $params[$paramName1] = $this->formatTypedValue($chType, $values[0] ?? null);
                    $params[$paramName2] = $this->formatTypedValue($chType, $values[1] ?? null);
                    break;

                case Query::TYPE_CONTAINS:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $chType = $this->getParamType($attribute);
                    $inParams = [];
                    foreach ($values as $value) {
                        $paramName = 'param_' . $paramCounter++;
                        $inParams[] = "{{$paramName}:{$chType}}";
                        $params[$paramName] = $this->formatTypedValue($chType, $value);
                    }
                    if (!empty($inParams)) {
                        $filters[] = "{$escapedAttr} IN (" . implode(', ', $inParams) . ")";
                    }
                    break;

                case Query::TYPE_NOT_CONTAINS:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $chType = $this->getParamType($attribute);
                    $inParams = [];
                    foreach ($values as $value) {
                        $paramName = 'param_' . $paramCounter++;
                        $inParams[] = "{{$paramName}:{$chType}}";
                        $params[$paramName] = $this->formatTypedValue($chType, $value);
                    }
                    if (!empty($inParams)) {
                        $filters[] = "{$escapedAttr} NOT IN (" . implode(', ', $inParams) . ")";
                    }
                    break;

                case Query::TYPE_IS_NULL:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $filters[] = "{$escapedAttr} IS NULL";
                    break;

                case Query::TYPE_IS_NOT_NULL:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $filters[] = "{$escapedAttr} IS NOT NULL";
                    break;

                case Query::TYPE_STARTS_WITH:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $needle = $values[0] ?? null;
                    if (!is_string($needle)) {
                        throw new Exception("startsWith needle must be a string for attribute '{$attribute}'");
                    }
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "startsWith({$escapedAttr}, {{$paramName}:String})";
                    $params[$paramName] = $needle;
                    break;

                case Query::TYPE_NOT_STARTS_WITH:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $needle = $values[0] ?? null;
                    if (!is_string($needle)) {
                        throw new Exception("notStartsWith needle must be a string for attribute '{$attribute}'");
                    }
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "NOT startsWith({$escapedAttr}, {{$paramName}:String})";
                    $params[$paramName] = $needle;
                    break;

                case Query::TYPE_ENDS_WITH:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $needle = $values[0] ?? null;
                    if (!is_string($needle)) {
                        throw new Exception("endsWith needle must be a string for attribute '{$attribute}'");
                    }
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "endsWith({$escapedAttr}, {{$paramName}:String})";
                    $params[$paramName] = $needle;
                    break;

                case Query::TYPE_NOT_ENDS_WITH:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $needle = $values[0] ?? null;
                    if (!is_string($needle)) {
                        throw new Exception("notEndsWith needle must be a string for attribute '{$attribute}'");
                    }
                    $paramName = 'param_' . $paramCounter++;
                    $filters[] = "NOT endsWith({$escapedAttr}, {{$paramName}:String})";
                    $params[$paramName] = $needle;
                    break;

                case Query::TYPE_REGEX:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $pattern = $values[0] ?? null;
                    if (!is_string($pattern)) {
                        throw new Exception("regex pattern must be a string for attribute '{$attribute}'");
                    }
                    $paramName = 'param_' . $paramCounter++;
                    // ClickHouse's `match(haystack, pattern)` is the re2-style
                    // regex predicate. Pattern is bound as a parameter, never
                    // interpolated, so it can't escape into the SQL.
                    $filters[] = "match({$escapedAttr}, {{$paramName}:String})";
                    $params[$paramName] = $pattern;
                    break;

                case Query::TYPE_SELECT:
                    if (empty($values)) {
                        // VALUE_REQUIRED_METHODS already rejects empty values
                        // earlier, but the explicit check keeps this branch safe
                        // if the guard is ever bypassed.
                        break;
                    }
                    // Multiple Query::select(...) calls combine into a single
                    // projection. Duplicates are removed; column names are
                    // validated and escaped at SQL build time in find().
                    $select ??= [];
                    foreach ($values as $column) {
                        if (!is_string($column) || $column === '') {
                            throw new Exception('select columns must be non-empty strings');
                        }
                        $this->validateAttributeName($column);
                        if (!in_array($column, $select, true)) {
                            $select[] = $column;
                        }
                    }
                    break;

                case Query::TYPE_ORDER_DESC:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $orderBy[] = "{$escapedAttr} DESC";
                    $orderAttributes[] = ['attribute' => $attribute, 'direction' => 'DESC'];
                    break;

                case Query::TYPE_ORDER_ASC:
                    $this->validateAttributeName($attribute);
                    $escapedAttr = $this->escapeIdentifier($attribute);
                    $orderBy[] = "{$escapedAttr} ASC";
                    $orderAttributes[] = ['attribute' => $attribute, 'direction' => 'ASC'];
                    break;

                case Query::TYPE_ORDER_RANDOM:
                    // ClickHouse's rand() is the per-row PRNG used for random
                    // sampling. Single emission across the result set — repeated
                    // Query::orderRandom() calls collapse into one ORDER BY rand().
                    $randomOrder = true;
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

                case Query::TYPE_CURSOR_AFTER:
                case Query::TYPE_CURSOR_BEFORE:
                    if ($cursor !== null) {
                        // Keep the first cursor encountered (matches base groupByType semantics)
                        break;
                    }
                    $rawCursor = $values[0] ?? null;
                    if ($rawCursor === null) {
                        break; // no-op cursor
                    }
                    $cursor = $this->normalizeCursorRow($rawCursor);
                    $cursorDirection = $method === Query::TYPE_CURSOR_AFTER ? 'after' : 'before';
                    break;
            }
        }

        $result = [
            'filters' => $filters,
            'params' => $params,
        ];

        if (!empty($orderBy)) {
            $result['orderBy'] = $orderBy;
            $result['orderAttributes'] = $orderAttributes;
        }

        if ($randomOrder) {
            $result['randomOrder'] = true;
        }

        if ($limit !== null) {
            $result['limit'] = $limit;
        }

        if ($offset !== null) {
            $result['offset'] = $offset;
        }

        if ($cursor !== null && $cursorDirection !== null) {
            $result['cursor'] = $cursor;
            $result['cursorDirection'] = $cursorDirection;
        }

        if ($select !== null) {
            $result['select'] = $select;
        }

        return $result;
    }

    /**
     * Normalize a user-supplied cursor row into a column-keyed array.
     *
     * Accepts a `Log` (or any `ArrayObject`) or a plain associative array.
     * `Log` stores its identifier under `$id` (Appwrite convention) while the
     * underlying column is `id` — this remaps `$id` → `id` so cursor pagination
     * can match the SQL column.
     *
     * @param mixed $rawCursor
     * @return array<string, mixed>
     * @throws Exception
     */
    private function normalizeCursorRow(mixed $rawCursor): array
    {
        if ($rawCursor instanceof \ArrayObject) {
            /** @var array<string, mixed> $row */
            $row = $rawCursor->getArrayCopy();
        } elseif (is_array($rawCursor)) {
            /** @var array<string, mixed> $rawCursor */
            $row = $rawCursor;
        } else {
            throw new Exception(
                'Invalid cursor value: expected ArrayObject (Log) or associative array, got '
                . get_debug_type($rawCursor)
            );
        }

        if (!array_key_exists('id', $row) && array_key_exists('$id', $row)) {
            $row['id'] = $row['$id'];
            unset($row['$id']);
        }

        return $row;
    }

    /**
     * Resolve the ClickHouse parameter type for a column.
     *
     * Used by both filter binding and cursor keyset comparison so values are
     * bound with the column's actual SQL type — binding a numeric column as
     * `String` would compare values lexicographically (`"9" > "10"`) and
     * silently produce incorrect filter results or page boundaries. Add a
     * branch here when introducing a new non-String column type.
     *
     * @param string $attribute
     * @return string ClickHouse parameter type (e.g. 'String', 'DateTime64(3)', 'UInt64')
     */
    private function getParamType(string $attribute): string
    {
        return match (true) {
            $attribute === 'time' => 'DateTime64(3)',
            $attribute === 'tenant' && $this->sharedTables => 'UInt64',
            default => 'String',
        };
    }

    /**
     * Format a value for the given ClickHouse parameter type.
     *
     * Routes DateTime-typed columns through formatDateTime() and everything
     * else through formatParamValue(). Centralising this dispatch keeps
     * parseQueries and buildCursorWhere consistent across libraries.
     *
     * @param string $chType ClickHouse parameter type as returned by getParamType()
     * @param mixed $value
     * @return string
     * @throws Exception
     */
    private function formatTypedValue(string $chType, mixed $value): string
    {
        if ($chType === 'DateTime64(3)') {
            if ($value === null) {
                throw new Exception('DateTime parameter value cannot be null');
            }
            /** @var \DateTime|string $value */
            return $this->formatDateTime($value);
        }

        return $this->formatParamValue($value);
    }

    /**
     * Resolve the effective order attributes for cursor pagination.
     *
     * Auto-appends `id` as a tiebreaker when not already present so keyset
     * pagination is deterministic on non-unique columns (e.g. time).
     *
     * @param array<int, array{attribute: string, direction: string}> $orderAttributes
     * @return array<int, array{attribute: string, direction: string}>
     */
    private function resolveCursorOrder(array $orderAttributes): array
    {
        foreach ($orderAttributes as $entry) {
            if ($entry['attribute'] === 'id') {
                return $orderAttributes;
            }
        }

        $defaultDirection = 'DESC';
        if (!empty($orderAttributes)) {
            $last = $orderAttributes[count($orderAttributes) - 1];
            $defaultDirection = $last['direction'];
        }

        $orderAttributes[] = ['attribute' => 'id', 'direction' => $defaultDirection];

        return $orderAttributes;
    }

    /**
     * Build keyset-pagination WHERE fragments for cursor support.
     *
     * Produces a tuple-compare clause across the order attributes:
     *   (a > A) OR (a = A AND b > B) OR ...
     *
     * For cursor `before`, the comparison directions are flipped relative to
     * the requested ORDER BY (the caller is responsible for also flipping the
     * actual ORDER BY at SQL build time so the page comes back from the right
     * side, then reversing the rows post-fetch).
     *
     * @param array<int, array{attribute: string, direction: string}> $orderAttributes
     * @param array<string, mixed> $cursor
     * @param string $cursorDirection 'after' or 'before'
     * @param array<string, mixed> $params Existing params (mutated by adding cursor binds)
     * @return array{clause: string, params: array<string, mixed>}
     * @throws Exception
     */
    private function buildCursorWhere(array $orderAttributes, array $cursor, string $cursorDirection, array $params): array
    {
        $tuples = [];
        foreach ($orderAttributes as $i => $entry) {
            $attr = $entry['attribute'];
            $direction = $entry['direction'];

            if (!array_key_exists($attr, $cursor)) {
                throw new Exception("Cursor is missing required attribute '{$attr}'");
            }

            if ($cursorDirection === 'before') {
                $direction = $direction === 'DESC' ? 'ASC' : 'DESC';
            }

            $conditions = [];

            for ($j = 0; $j < $i; $j++) {
                $prev = $orderAttributes[$j];
                $prevAttr = $prev['attribute'];
                if (!array_key_exists($prevAttr, $cursor)) {
                    throw new Exception("Cursor is missing required attribute '{$prevAttr}'");
                }
                $prevValue = $cursor[$prevAttr];
                if ($prevValue === null) {
                    throw new Exception("Cursor value for '{$prevAttr}' cannot be null");
                }
                $prevEscaped = $this->escapeIdentifier($prevAttr);
                $prevType = $this->getParamType($prevAttr);
                $paramName = "cursor_eq_{$i}_{$j}";

                $conditions[] = "{$prevEscaped} = {{$paramName}:{$prevType}}";
                $params[$paramName] = $this->formatTypedValue($prevType, $prevValue);
            }

            $value = $cursor[$attr];
            if ($value === null) {
                throw new Exception("Cursor value for '{$attr}' cannot be null");
            }
            $escaped = $this->escapeIdentifier($attr);
            $chType = $this->getParamType($attr);
            $operator = $direction === 'DESC' ? '<' : '>';
            $paramName = "cursor_cmp_{$i}";

            $conditions[] = "{$escaped} {$operator} {{$paramName}:{$chType}}";
            $params[$paramName] = $this->formatTypedValue($chType, $value);

            $tuples[] = '(' . implode(' AND ', $conditions) . ')';
        }

        return [
            'clause' => '(' . implode(' OR ', $tuples) . ')',
            'params' => $params,
        ];
    }

    /**
     * Build the ORDER BY SQL fragment list, optionally flipping all directions.
     *
     * Used when cursor direction is `before` — we run the query in reverse to
     * grab the previous-page rows, then `array_reverse` the result.
     *
     * @param array<int, array{attribute: string, direction: string}> $orderAttributes
     * @param bool $flip Whether to flip ASC↔DESC
     * @return array<string>
     */
    private function buildOrderBySql(array $orderAttributes, bool $flip = false): array
    {
        $sql = [];
        foreach ($orderAttributes as $entry) {
            $direction = $entry['direction'];
            if ($flip) {
                $direction = $direction === 'DESC' ? 'ASC' : 'DESC';
            }
            $sql[] = $this->escapeIdentifier($entry['attribute']) . ' ' . $direction;
        }
        return $sql;
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

        // Build JSON rows for JSONEachRow format
        $rows = [];

        foreach ($logs as $log) {
            foreach (['userId' => 'actorId', 'userType' => 'actorType', 'userInternalId' => 'actorInternalId'] as $legacy => $current) {
                if (isset($log[$legacy]) && !isset($log[$current])) {
                    $log[$current] = $log[$legacy];
                }
                unset($log[$legacy]);
            }

            /** @var array<string, mixed> $logData */
            $logData = $log['data'] ?? [];

            foreach (['userId' => 'actorId', 'userType' => 'actorType', 'userInternalId' => 'actorInternalId'] as $legacy => $current) {
                if (\array_key_exists($legacy, $logData) && !\array_key_exists($current, $logData)) {
                    $logData[$current] = $logData[$legacy];
                }
                unset($logData[$legacy]);
            }
            $log['data'] = $logData;

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

            // Build JSON row - use provided id or generate one
            $logId = $log['id'] ?? uniqid('', true);

            /** @var string|\DateTime|null $providedTime */
            $providedTime = $processedLog['time'] ?? null;
            $formattedTime = $this->formatDateTime($providedTime);

            $row = [
                'id' => $logId,
                'time' => $formattedTime,
            ];

            // Add all other columns
            foreach ($schemaColumns as $columnName) {
                if ($columnName === 'time') {
                    continue; // Already handled
                }

                // Get attribute metadata to determine if required
                $attributeMetadata = $this->getAttribute($columnName);
                $isRequiredAttribute = $attributeMetadata !== null && isset($attributeMetadata['required']) && $attributeMetadata['required'];

                if ($columnName === 'data') {
                    // Data column - encode remaining non-schema data as JSON
                    try {
                        $encodedData = json_encode($nonSchemaData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
                    } catch (\JsonException $e) {
                        throw new Exception('Failed to encode data column to JSON: ' . $e->getMessage());
                    }
                    $row['data'] = $encodedData;
                } elseif (isset($processedLog[$columnName])) {
                    $row[$columnName] = $processedLog[$columnName];
                } elseif ($isRequiredAttribute) {
                    throw new \InvalidArgumentException("Required attribute '{$columnName}' is missing in batch log entry");
                }
            }

            if ($this->sharedTables) {
                $row['tenant'] = $log['$tenant'] ?? $this->tenant;
            }

            $rows[] = $row;
        }

        $insertSql = "INSERT INTO {$escapedDatabaseAndTable} FORMAT JSONEachRow";

        $this->query($insertSql, [], $rows);
        return true;
    }

    /**
     * Parse ClickHouse JSON format results into Log objects.
     * JSON format provides structured data with automatic type handling.
     *
     * @param string $result The JSON response from ClickHouse
     * @return array<int, Log>
     * @throws Exception If JSON parsing fails
     */
    private function parseJsonResults(string $result): array
    {
        if (empty(trim($result))) {
            return [];
        }

        /** @var array<string, mixed>|null $decoded */
        $decoded = json_decode($result, true);
        if ($decoded === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Failed to parse ClickHouse JSON response: ' . json_last_error_msg());
        }

        if (!is_array($decoded) || !isset($decoded['data']) || !is_array($decoded['data'])) {
            return [];
        }

        /** @var array<int, array<string, mixed>> $data */
        $data = $decoded['data'];
        $documents = [];

        foreach ($data as $row) {
            if (!is_array($row)) {
                continue;
            }

            $document = [];

            foreach ($row as $columnName => $value) {
                if ($columnName === 'data') {
                    // Decode JSON data column
                    if (is_string($value)) {
                        $document[$columnName] = json_decode($value, true) ?? [];
                    } else {
                        $document[$columnName] = $value ?? [];
                    }
                } elseif ($columnName === 'tenant') {
                    // Parse tenant as integer or null
                    if ($value === null || $value === '') {
                        $document[$columnName] = null;
                    } elseif (is_numeric($value)) {
                        $document[$columnName] = (int) $value;
                    } else {
                        $document[$columnName] = null;
                    }
                } elseif ($columnName === 'time') {
                    // Convert ClickHouse timestamp format back to ISO 8601
                    // ClickHouse JSON: "2025-12-07 23:33:54.493"
                    // ISO 8601:        "2025-12-07T23:33:54.493+00:00"
                    $parsedTime = is_string($value) ? $value : (is_scalar($value) ? (string) $value : '');
                    if (strpos($parsedTime, 'T') === false && $parsedTime !== '') {
                        $parsedTime = str_replace(' ', 'T', $parsedTime) . '+00:00';
                    }
                    $document[$columnName] = $parsedTime;
                } else {
                    // For other fields, handle null values
                    $document[$columnName] = $value;
                }
            }

            // Add special $id field if present
            if (isset($document['id'])) {
                $document['$id'] = $document['id'];
                unset($document['id']);
            }

            foreach (['actorId' => 'userId', 'actorType' => 'userType', 'actorInternalId' => 'userInternalId'] as $current => $legacy) {
                if (\array_key_exists($current, $document) && !\array_key_exists($legacy, $document)) {
                    $document[$legacy] = $document[$current];
                }
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
            Query::equal('actorId', $userId),
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
        ?int $max = null,
    ): int {
        $queries = [
            Query::equal('actorId', $userId),
        ];

        if ($after !== null && $before !== null) {
            $queries[] = Query::between('time', $after, $before);
        } elseif ($after !== null) {
            $queries[] = Query::greaterThan('time', $after);
        } elseif ($before !== null) {
            $queries[] = Query::lessThan('time', $before);
        }

        return $this->count($queries, $max);
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
        ?int $max = null,
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

        return $this->count($queries, $max);
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
            Query::equal('actorId', $userId),
            Query::contains('event', $events),
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
        ?int $max = null,
    ): int {
        $queries = [
            Query::equal('actorId', $userId),
            Query::contains('event', $events),
        ];

        if ($after !== null && $before !== null) {
            $queries[] = Query::between('time', $after, $before);
        } elseif ($after !== null) {
            $queries[] = Query::greaterThan('time', $after);
        } elseif ($before !== null) {
            $queries[] = Query::lessThan('time', $before);
        }

        return $this->count($queries, $max);
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
            Query::contains('event', $events),
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
        ?int $max = null,
    ): int {
        $queries = [
            Query::equal('resource', $resource),
            Query::contains('event', $events),
        ];

        if ($after !== null && $before !== null) {
            $queries[] = Query::between('time', $after, $before);
        } elseif ($after !== null) {
            $queries[] = Query::greaterThan('time', $after);
        } elseif ($before !== null) {
            $queries[] = Query::lessThan('time', $before);
        }

        return $this->count($queries, $max);
    }

    /**
     * Delete logs older than the specified datetime.
     *
     * @throws Exception
     */
    public function cleanup(\DateTime $datetime): bool
    {
        $tableName = $this->getTableName();
        $tenantFilter = $this->getTenantFilter();
        $escapedTable = $this->escapeIdentifier($this->database) . '.' . $this->escapeIdentifier($tableName);

        $datetimeString = $datetime->format('Y-m-d H:i:s.v');

        $settings = $this->asyncCleanup ? ' SETTINGS lightweight_deletes_sync = 0' : '';

        $sql = "
            DELETE FROM {$escapedTable}
            WHERE time < {datetime:String}{$tenantFilter}{$settings}
        ";

        $this->query($sql, ['datetime' => $datetimeString]);

        return true;
    }
}
