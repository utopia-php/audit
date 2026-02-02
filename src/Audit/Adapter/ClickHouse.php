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
 *
 * Features:
 * - HTTP compression support (gzip, lz4) for reduced bandwidth
 * - Configurable connection timeouts
 * - Connection health checking
 * - Parameterized queries for SQL injection prevention
 * - Multi-tenant support with shared tables
 */
class ClickHouse extends SQL
{
    /**
     * Default HTTP port for ClickHouse
     */
    private const DEFAULT_PORT = 8123;

    /**
     * Default table name for audit logs
     */
    private const DEFAULT_TABLE = 'audits';

    /**
     * Default database name
     */
    private const DEFAULT_DATABASE = 'default';

    /**
     * Default connection timeout in milliseconds
     */
    private const DEFAULT_TIMEOUT = 30_000;

    /**
     * Minimum allowed timeout in milliseconds
     */
    private const MIN_TIMEOUT = 1_000;

    /**
     * Maximum allowed timeout in milliseconds (10 minutes)
     */
    private const MAX_TIMEOUT = 600_000;

    /**
     * Compression type: No compression
     */
    public const COMPRESSION_NONE = 'none';

    /**
     * Compression type: gzip compression (best for HTTP)
     */
    public const COMPRESSION_GZIP = 'gzip';

    /**
     * Compression type: lz4 compression (fastest, ClickHouse native)
     */
    public const COMPRESSION_LZ4 = 'lz4';

    /**
     * Valid compression types
     */
    private const VALID_COMPRESSION_TYPES = [
        self::COMPRESSION_NONE,
        self::COMPRESSION_GZIP,
        self::COMPRESSION_LZ4,
    ];

    /**
     * Default maximum retry attempts
     */
    private const DEFAULT_MAX_RETRIES = 3;

    /**
     * Default retry delay in milliseconds
     */
    private const DEFAULT_RETRY_DELAY = 100;

    /**
     * Minimum retry delay in milliseconds
     */
    private const MIN_RETRY_DELAY = 10;

    /**
     * Maximum retry delay in milliseconds
     */
    private const MAX_RETRY_DELAY = 5000;

    /**
     * Maximum allowed retry attempts
     */
    private const MAX_RETRY_ATTEMPTS = 10;

    /**
     * HTTP status codes that are retryable
     */
    private const RETRYABLE_STATUS_CODES = [408, 429, 500, 502, 503, 504];

    private string $host;

    private int $port;

    private string $database = self::DEFAULT_DATABASE;

    private string $table = self::DEFAULT_TABLE;

    private string $username;

    private string $password;

    /**
     * @var bool Whether to use HTTPS for ClickHouse HTTP interface
     */
    private bool $secure = false;

    /**
     * @var string Compression type for HTTP requests/responses
     */
    private string $compression = self::COMPRESSION_NONE;

    /**
     * @var int Connection timeout in milliseconds
     */
    private int $timeout = self::DEFAULT_TIMEOUT;

    /**
     * @var int Maximum number of retry attempts for transient failures
     */
    private int $maxRetries = self::DEFAULT_MAX_RETRIES;

    /**
     * @var int Base delay between retries in milliseconds (doubles with each retry)
     */
    private int $retryDelay = self::DEFAULT_RETRY_DELAY;

    /**
     * @var bool Whether query logging is enabled
     */
    private bool $queryLoggingEnabled = false;

    /**
     * @var array<int, array{sql: string, params: array<string, mixed>, duration: float, timestamp: string, success: bool, error?: string, retries?: int}> Query log entries
     */
    private array $queryLog = [];

    /**
     * @var int Total number of queries executed
     */
    private int $queryCount = 0;

    /**
     * @var int Total number of failed queries
     */
    private int $failedQueryCount = 0;

    private Client $client;

    protected string $namespace = '';

    protected ?int $tenant = null;

    protected bool $sharedTables = false;

    /**
     * Create a new ClickHouse adapter instance.
     *
     * @param string $host ClickHouse host (hostname or IP address)
     * @param string $username ClickHouse username (default: 'default')
     * @param string $password ClickHouse password (default: '')
     * @param int $port ClickHouse HTTP port (default: 8123)
     * @param bool $secure Whether to use HTTPS (default: false)
     * @param string $compression Compression type: 'none', 'gzip', or 'lz4' (default: 'none')
     * @param int $timeout Connection timeout in milliseconds (default: 30000)
     * @throws Exception If validation fails
     */
    public function __construct(
        string $host,
        string $username = 'default',
        string $password = '',
        int $port = self::DEFAULT_PORT,
        bool $secure = false,
        string $compression = self::COMPRESSION_NONE,
        int $timeout = self::DEFAULT_TIMEOUT
    ) {
        $this->validateHost($host);
        $this->validatePort($port);
        $this->validateCompression($compression);
        $this->validateTimeout($timeout);

        $this->host = $host;
        $this->port = $port;
        $this->username = $username;
        $this->password = $password;
        $this->secure = $secure;
        $this->compression = $compression;
        $this->timeout = $timeout;

        $this->initializeClient();
    }

    /**
     * Initialize the HTTP client with current configuration.
     */
    private function initializeClient(): void
    {
        $this->client = new Client();
        $this->client->addHeader('X-ClickHouse-User', $this->username);
        $this->client->addHeader('X-ClickHouse-Key', $this->password);
        $this->client->setTimeout($this->timeout);

        // Request compressed responses from ClickHouse (safe for all requests)
        if ($this->compression !== self::COMPRESSION_NONE) {
            $this->client->addHeader('Accept-Encoding', $this->compression);
        }
        // Note: Content-Encoding is set per-request only when we actually compress the body
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
     * Validate compression parameter.
     *
     * @param string $compression
     * @throws Exception
     */
    private function validateCompression(string $compression): void
    {
        if (!in_array($compression, self::VALID_COMPRESSION_TYPES, true)) {
            $validTypes = implode(', ', self::VALID_COMPRESSION_TYPES);
            throw new Exception("Invalid compression type '{$compression}'. Valid types are: {$validTypes}");
        }
    }

    /**
     * Validate timeout parameter.
     *
     * @param int $timeout
     * @throws Exception
     */
    private function validateTimeout(int $timeout): void
    {
        if ($timeout < self::MIN_TIMEOUT || $timeout > self::MAX_TIMEOUT) {
            throw new Exception(
                "Timeout must be between " . self::MIN_TIMEOUT . " and " . self::MAX_TIMEOUT . " milliseconds"
            );
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
     *
     * @param bool $secure Whether to use HTTPS
     * @return self
     */
    public function setSecure(bool $secure): self
    {
        $this->secure = $secure;
        return $this;
    }

    /**
     * Set the compression type for HTTP responses.
     *
     * Compression can significantly reduce bandwidth for query results:
     * - 'none': No compression (default)
     * - 'gzip': Standard gzip compression, widely supported
     * - 'lz4': ClickHouse native compression, fastest decompression
     *
     * Note: This configures the Accept-Encoding header to request compressed
     * responses from ClickHouse. The server will compress query results before
     * sending them, reducing network transfer size.
     *
     * @param string $compression Compression type
     * @return self
     * @throws Exception If compression type is invalid
     */
    public function setCompression(string $compression): self
    {
        $this->validateCompression($compression);
        $this->compression = $compression;
        $this->initializeClient();
        return $this;
    }

    /**
     * Get the current compression type.
     *
     * @return string
     */
    public function getCompression(): string
    {
        return $this->compression;
    }

    /**
     * Set the connection timeout.
     *
     * @param int $timeout Timeout in milliseconds (1000-600000)
     * @return self
     * @throws Exception If timeout is out of range
     */
    public function setTimeout(int $timeout): self
    {
        $this->validateTimeout($timeout);
        $this->timeout = $timeout;
        $this->client->setTimeout($timeout);
        return $this;
    }

    /**
     * Get the current timeout.
     *
     * @return int Timeout in milliseconds
     */
    public function getTimeout(): int
    {
        return $this->timeout;
    }

    /**
     * Check if the ClickHouse server is reachable and responding.
     *
     * This method performs a lightweight ping query to verify:
     * - Network connectivity to the server
     * - Server is accepting HTTP connections
     * - Authentication credentials are valid
     *
     * @return bool True if server is healthy, false otherwise
     */
    public function ping(): bool
    {
        try {
            $result = $this->query('SELECT 1 FORMAT TabSeparated');
            return trim($result) === '1';
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Get server version information.
     *
     * @return string|null Server version string or null if unavailable
     */
    public function getServerVersion(): ?string
    {
        try {
            $result = $this->query('SELECT version() FORMAT TabSeparated');
            $version = trim($result);
            return $version !== '' ? $version : null;
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Get comprehensive health check information.
     *
     * Returns detailed status about the ClickHouse connection including:
     * - Connection health status
     * - Server version and uptime
     * - Response time measurement
     * - Configuration details
     *
     * @return array{healthy: bool, host: string, port: int, database: string, secure: bool, compression: string, version: string|null, uptime: int|null, responseTime: float, error?: string}
     */
    public function healthCheck(): array
    {
        $startTime = microtime(true);
        $healthy = false;
        $version = null;
        $uptime = null;
        $error = null;

        try {
            // Query version and uptime in a single request
            $result = $this->query("SELECT version() as version, uptime() as uptime FORMAT JSON");
            $decoded = json_decode($result, true);

            if (is_array($decoded) && isset($decoded['data'][0])) {
                $data = $decoded['data'][0];
                $version = $data['version'] ?? null;
                $uptime = isset($data['uptime']) ? (int) $data['uptime'] : null;
                $healthy = true;
            }
        } catch (Exception $e) {
            $error = $e->getMessage();
        }

        $responseTime = (microtime(true) - $startTime) * 1000; // Convert to milliseconds

        $result = [
            'healthy' => $healthy,
            'host' => $this->host,
            'port' => $this->port,
            'database' => $this->database,
            'secure' => $this->secure,
            'compression' => $this->compression,
            'version' => $version,
            'uptime' => $uptime,
            'responseTime' => round($responseTime, 2),
        ];

        if ($error !== null) {
            $result['error'] = $error;
        }

        return $result;
    }

    /**
     * Set the maximum number of retry attempts for transient failures.
     *
     * When a retryable error occurs (network timeout, server overload, etc.),
     * the adapter will retry the request up to this many times with exponential backoff.
     *
     * @param int $maxRetries Maximum retries (0-10, 0 disables retries)
     * @return self
     * @throws Exception If maxRetries is out of range
     */
    public function setMaxRetries(int $maxRetries): self
    {
        if ($maxRetries < 0 || $maxRetries > self::MAX_RETRY_ATTEMPTS) {
            throw new Exception("Max retries must be between 0 and " . self::MAX_RETRY_ATTEMPTS);
        }
        $this->maxRetries = $maxRetries;
        return $this;
    }

    /**
     * Get the maximum number of retry attempts.
     *
     * @return int
     */
    public function getMaxRetries(): int
    {
        return $this->maxRetries;
    }

    /**
     * Set the base delay between retry attempts.
     *
     * The actual delay uses exponential backoff: delay * 2^(attempt-1)
     * For example, with delay=100ms: 100ms, 200ms, 400ms, 800ms, etc.
     *
     * @param int $delayMs Base delay in milliseconds (10-5000)
     * @return self
     * @throws Exception If delay is out of range
     */
    public function setRetryDelay(int $delayMs): self
    {
        if ($delayMs < self::MIN_RETRY_DELAY || $delayMs > self::MAX_RETRY_DELAY) {
            throw new Exception(
                "Retry delay must be between " . self::MIN_RETRY_DELAY . " and " . self::MAX_RETRY_DELAY . " milliseconds"
            );
        }
        $this->retryDelay = $delayMs;
        return $this;
    }

    /**
     * Get the base retry delay.
     *
     * @return int Delay in milliseconds
     */
    public function getRetryDelay(): int
    {
        return $this->retryDelay;
    }

    /**
     * Enable or disable query logging.
     *
     * When enabled, all queries are logged with their SQL, parameters,
     * execution duration, and success/failure status. Useful for debugging
     * and performance monitoring.
     *
     * @param bool $enable Whether to enable query logging
     * @return self
     */
    public function enableQueryLogging(bool $enable = true): self
    {
        $this->queryLoggingEnabled = $enable;
        return $this;
    }

    /**
     * Check if query logging is enabled.
     *
     * @return bool
     */
    public function isQueryLoggingEnabled(): bool
    {
        return $this->queryLoggingEnabled;
    }

    /**
     * Get the query log.
     *
     * Each entry contains:
     * - sql: The SQL query
     * - params: Query parameters
     * - duration: Execution time in milliseconds
     * - timestamp: ISO 8601 timestamp
     * - success: Whether the query succeeded
     * - error: Error message (if failed)
     * - retries: Number of retry attempts (if any)
     *
     * @return array<int, array{sql: string, params: array<string, mixed>, duration: float, timestamp: string, success: bool, error?: string, retries?: int}>
     */
    public function getQueryLog(): array
    {
        return $this->queryLog;
    }

    /**
     * Clear the query log.
     *
     * @return self
     */
    public function clearQueryLog(): self
    {
        $this->queryLog = [];
        return $this;
    }

    /**
     * Get connection and query statistics.
     *
     * Returns operational metrics about the adapter's usage:
     * - Total queries executed
     * - Failed query count
     * - Configuration settings
     *
     * @return array{queryCount: int, failedQueryCount: int, successRate: float, host: string, port: int, database: string, secure: bool, compression: string, timeout: int, maxRetries: int, retryDelay: int, queryLoggingEnabled: bool, queryLogSize: int}
     */
    public function getStats(): array
    {
        $successRate = $this->queryCount > 0
            ? round(($this->queryCount - $this->failedQueryCount) / $this->queryCount * 100, 2)
            : 100.0;

        return [
            'queryCount' => $this->queryCount,
            'failedQueryCount' => $this->failedQueryCount,
            'successRate' => $successRate,
            'host' => $this->host,
            'port' => $this->port,
            'database' => $this->database,
            'secure' => $this->secure,
            'compression' => $this->compression,
            'timeout' => $this->timeout,
            'maxRetries' => $this->maxRetries,
            'retryDelay' => $this->retryDelay,
            'queryLoggingEnabled' => $this->queryLoggingEnabled,
            'queryLogSize' => count($this->queryLog),
        ];
    }

    /**
     * Reset query statistics.
     *
     * @return self
     */
    public function resetStats(): self
    {
        $this->queryCount = 0;
        $this->failedQueryCount = 0;
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
     * When compression is enabled:
     * - Response decompression is handled automatically via Accept-Encoding header
     * - This significantly reduces bandwidth for query results
     *
     * @param string $sql The SQL query to execute
     * @param array<string, mixed> $params Key-value pairs for query parameters (for SELECT/UPDATE/DELETE)
     * @param array<int, array<string, mixed>>|null $jsonRows Array of rows for JSONEachRow INSERT operations
     * @return string Response body
     * @throws Exception
     */
    private function query(string $sql, array $params = [], ?array $jsonRows = null): string
    {
        $startTime = microtime(true);
        $retryCount = 0;
        $lastException = null;

        $scheme = $this->secure ? 'https' : 'http';

        // Update the database header for each query (in case setDatabase was called)
        $this->client->addHeader('X-ClickHouse-Database', $this->database);

        // Prepare URL and body before retry loop
        if ($jsonRows !== null) {
            // JSON body mode for INSERT operations with JSONEachRow format
            $url = "{$scheme}://{$this->host}:{$this->port}/?query=" . urlencode($sql);

            // Build JSONEachRow body - each row on a separate line
            $jsonLines = [];
            foreach ($jsonRows as $row) {
                try {
                    $encoded = json_encode($row, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
                } catch (\JsonException $e) {
                    $this->logQuery($sql, $params, $startTime, false, $e->getMessage(), 0);
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

        // Retry loop with exponential backoff
        while (true) {
            try {
                $response = $this->client->fetch(
                    url: $url,
                    method: Client::METHOD_POST,
                    body: $body
                );

                $statusCode = $response->getStatusCode();
                $responseBody = $response->getBody();
                $responseBody = is_string($responseBody) ? $responseBody : '';

                // Decompress response if server sent compressed data
                $responseBody = $this->decompressResponse($response, $responseBody);

                if ($statusCode !== 200) {
                    // Check if this is a retryable error
                    if ($this->isRetryableError($statusCode, $responseBody) && $retryCount < $this->maxRetries) {
                        $retryCount++;
                        $this->sleepWithBackoff($retryCount);
                        continue;
                    }
                    $this->handleQueryError($statusCode, $responseBody, $sql);
                }

                // Success
                $this->logQuery($sql, $params, $startTime, true, null, $retryCount);
                return $responseBody;

            } catch (Exception $e) {
                $lastException = $e;

                // Check if this is a retryable network error
                if ($this->isRetryableException($e) && $retryCount < $this->maxRetries) {
                    $retryCount++;
                    $this->sleepWithBackoff($retryCount);
                    continue;
                }

                // Log the failed query
                $errorMessage = $e->getMessage();
                $this->logQuery($sql, $params, $startTime, false, $errorMessage, $retryCount);

                // Re-throw our own exceptions without wrapping
                if (strpos($errorMessage, 'ClickHouse') === 0) {
                    throw $e;
                }
                throw new Exception(
                    "ClickHouse query execution failed: {$errorMessage}",
                    0,
                    $e
                );
            }
        }
    }

    /**
     * Check if an HTTP status code indicates a retryable error.
     *
     * @param int $statusCode HTTP status code
     * @param string $responseBody Response body for additional checks
     * @return bool
     */
    private function isRetryableError(int $statusCode, string $responseBody): bool
    {
        // Common retryable status codes
        if (in_array($statusCode, self::RETRYABLE_STATUS_CODES, true)) {
            return true;
        }

        // Check response body for retryable patterns
        $retryablePatterns = [
            'too many simultaneous queries',
            'memory limit exceeded',
            'timeout',
            'connection reset',
        ];

        $lowerBody = strtolower($responseBody);
        foreach ($retryablePatterns as $pattern) {
            if (strpos($lowerBody, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an exception indicates a retryable network error.
     *
     * @param Exception $e The exception to check
     * @return bool
     */
    private function isRetryableException(Exception $e): bool
    {
        $message = strtolower($e->getMessage());
        $retryablePatterns = [
            'connection',
            'timeout',
            'refused',
            'reset',
            'broken pipe',
            'network',
            'temporary',
            'unavailable',
            'could not resolve',
        ];

        foreach ($retryablePatterns as $pattern) {
            if (strpos($message, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Sleep with exponential backoff before retry.
     *
     * @param int $attempt Current retry attempt (1-based)
     */
    private function sleepWithBackoff(int $attempt): void
    {
        // Exponential backoff: delay * 2^(attempt-1)
        // With jitter to avoid thundering herd
        $delay = $this->retryDelay * (2 ** ($attempt - 1));
        $jitter = rand(0, (int) ($delay * 0.1)); // 10% jitter
        $totalDelay = min($delay + $jitter, self::MAX_RETRY_DELAY);

        usleep((int) ($totalDelay * 1000)); // Convert ms to microseconds
    }

    /**
     * Log a query execution (if logging is enabled).
     *
     * @param string $sql The SQL query
     * @param array<string, mixed> $params Query parameters
     * @param float $startTime Start time from microtime(true)
     * @param bool $success Whether the query succeeded
     * @param string|null $error Error message if failed
     * @param int $retries Number of retry attempts
     */
    private function logQuery(string $sql, array $params, float $startTime, bool $success, ?string $error, int $retries): void
    {
        // Always track statistics
        $this->queryCount++;
        if (!$success) {
            $this->failedQueryCount++;
        }

        // Only log details if logging is enabled
        if (!$this->queryLoggingEnabled) {
            return;
        }

        $duration = (microtime(true) - $startTime) * 1000; // Convert to milliseconds

        $entry = [
            'sql' => $sql,
            'params' => $params,
            'duration' => round($duration, 2),
            'timestamp' => date('c'),
            'success' => $success,
        ];

        if ($error !== null) {
            $entry['error'] = $error;
        }

        if ($retries > 0) {
            $entry['retries'] = $retries;
        }

        $this->queryLog[] = $entry;
    }

    /**
     * Decompress response body if the server sent compressed data.
     *
     * Checks the Content-Encoding header and decompresses accordingly.
     *
     * @param \Utopia\Fetch\Response $response The HTTP response
     * @param string $body The response body
     * @return string Decompressed body (or original if not compressed)
     */
    private function decompressResponse(\Utopia\Fetch\Response $response, string $body): string
    {
        if (empty($body)) {
            return $body;
        }

        $headers = $response->getHeaders();
        $contentEncoding = '';

        // Find Content-Encoding header (case-insensitive)
        foreach ($headers as $name => $value) {
            if (strtolower($name) === 'content-encoding') {
                $contentEncoding = (string) $value;
                break;
            }
        }

        if (empty($contentEncoding)) {
            return $body;
        }

        $encoding = strtolower(trim($contentEncoding));

        if ($encoding === 'gzip' || $encoding === 'x-gzip') {
            $decompressed = @gzdecode($body);
            if ($decompressed !== false) {
                return $decompressed;
            }
            // If decompression fails, return original (might not actually be compressed)
            return $body;
        }

        if ($encoding === 'deflate') {
            $decompressed = @gzinflate($body);
            if ($decompressed !== false) {
                return $decompressed;
            }
            // Try with zlib header
            $decompressed = @gzuncompress($body);
            if ($decompressed !== false) {
                return $decompressed;
            }
            return $body;
        }

        // LZ4 decompression requires the lz4 extension
        if ($encoding === 'lz4') {
            if (function_exists('lz4_uncompress')) {
                /** @var string|false $decompressed */
                $decompressed = lz4_uncompress($body);
                if ($decompressed !== false) {
                    return $decompressed;
                }
            }
            return $body;
        }

        // Unknown encoding, return as-is
        return $body;
    }

    /**
     * Handle query error responses from ClickHouse.
     *
     * @param int $statusCode HTTP status code
     * @param string $responseBody Response body
     * @param string $sql The SQL query that failed
     * @throws Exception
     */
    private function handleQueryError(int $statusCode, string $responseBody, string $sql): void
    {
        // Extract meaningful error message from ClickHouse response
        $errorMessage = $this->parseClickHouseError($responseBody);

        $context = '';
        if ($statusCode === 401) {
            $context = ' (authentication failed - check username/password)';
        } elseif ($statusCode === 403) {
            $context = ' (access denied - check permissions)';
        } elseif ($statusCode === 404) {
            $context = ' (database or table not found)';
        }

        throw new Exception(
            "ClickHouse query failed with HTTP {$statusCode}{$context}: {$errorMessage}"
        );
    }

    /**
     * Parse ClickHouse error response to extract a meaningful error message.
     *
     * @param string $responseBody The raw response body
     * @return string Parsed error message
     */
    private function parseClickHouseError(string $responseBody): string
    {
        if (empty($responseBody)) {
            return 'Empty response from server';
        }

        // ClickHouse error format: Code: XXX. DB::Exception: Message
        if (preg_match('/Code:\s*(\d+).*?DB::Exception:\s*(.+?)(?:\s*\(|$)/s', $responseBody, $matches)) {
            return "Code {$matches[1]}: {$matches[2]}";
        }

        // Return the first line of the response as fallback
        // strtok() on a non-empty string will always return a string
        /** @var string $firstLine */
        $firstLine = strtok($responseBody, "\n");
        return $firstLine;
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
            FORMAT JSON
        ";

        $result = $this->query($sql, $parsed['params']);
        return $this->parseJsonResults($result);
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

        // Build JSON rows for JSONEachRow format
        $rows = [];

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
