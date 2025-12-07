<?php

namespace Utopia\Audit\Adapter;

use Exception;
use Utopia\Database\Document;
use Utopia\Fetch\Client;
use Utopia\Fetch\FetchException;

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
     * Execute a ClickHouse query via HTTP interface using Fetch Client.
     *
     * @throws Exception|FetchException
     */
    private function query(string $sql, array $params = []): string
    {
        $url = "http://{$this->host}:{$this->port}/";

        // Replace parameters in query
        foreach ($params as $key => $value) {
            if (is_string($value)) {
                $value = "'" . addslashes($value) . "'";
            } elseif (is_null($value)) {
                $value = 'NULL';
            } elseif (is_bool($value)) {
                $value = $value ? '1' : '0';
            } elseif (is_array($value)) {
                $value = "'" . addslashes(json_encode($value)) . "'";
            }
            $sql = str_replace(":{$key}", (string) $value, $sql);
        }

        // Build headers with authentication
        $headers = [
            'X-ClickHouse-User' => $this->username,
            'X-ClickHouse-Key' => $this->password,
            'X-ClickHouse-Database' => $this->database,
        ];

        try {
            $response = Client::fetch(
                url: $url,
                method: Client::METHOD_POST,
                headers: $headers,
                body: ['query' => $sql],
                timeout: 30
            );

            if ($response->getStatusCode() !== 200) {
                throw new Exception("ClickHouse query failed (HTTP {$response->getStatusCode()}): {$response->getBody()}");
            }

            return $response->getBody() ?: '';
        } catch (FetchException $e) {
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
        $columns = array_merge(
            ['id String'],
            $this->getAllColumnDefinitions()
        );

        // Build indexes from base adapter schema
        $indexes = [];
        foreach ($this->getIndexes() as $index) {
            $indexName = $index['$id'];
            $attributes = $index['attributes'];
            $attributeList = implode(', ', $attributes);
            $indexes[] = "INDEX {$indexName} ({$attributeList}) TYPE bloom_filter GRANULARITY 1";
        }

        // Create table with MergeTree engine for optimal performance
        $createTableSql = "
            CREATE TABLE IF NOT EXISTS {$this->database}.{$this->table} (
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
        $time = date('Y-m-d H:i:s.v');

        $insertSql = "
            INSERT INTO {$this->database}.{$this->table}
            (id, userId, event, resource, userAgent, ip, location, time, data)
            VALUES (
                :id,
                :userId,
                :event,
                :resource,
                :userAgent,
                :ip,
                :location,
                :time,
                :data
            )
        ";

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

        $this->query($insertSql, $params);

        return new Document([
            '$id' => $id,
            'userId' => $log['userId'] ?? null,
            'event' => $log['event'],
            'resource' => $log['resource'],
            'userAgent' => $log['userAgent'],
            'ip' => $log['ip'],
            'location' => $log['location'] ?? null,
            'time' => $time,
            'data' => $log['data'] ?? [],
        ]);
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
            $userId = isset($log['userId']) && $log['userId'] !== null
                ? "'" . addslashes($log['userId']) . "'"
                : 'NULL';
            $location = isset($log['location']) && $log['location'] !== null
                ? "'" . addslashes($log['location']) . "'"
                : 'NULL';

            $values[] = sprintf(
                "('%s', %s, '%s', '%s', '%s', '%s', %s, '%s', '%s')",
                $id,
                $userId,
                addslashes($log['event']),
                addslashes($log['resource']),
                addslashes($log['userAgent']),
                addslashes($log['ip']),
                $location,
                $log['timestamp'],
                addslashes(json_encode($log['data'] ?? []))
            );
        }

        $insertSql = "
            INSERT INTO {$this->database}.{$this->table}
            (id, userId, event, resource, userAgent, ip, location, time, data)
            VALUES " . implode(', ', $values);

        $this->query($insertSql);

        // Return documents
        $documents = [];
        foreach ($logs as $log) {
            $documents[] = new Document([
                '$id' => uniqid('audit_', true),
                'userId' => $log['userId'] ?? null,
                'event' => $log['event'],
                'resource' => $log['resource'],
                'userAgent' => $log['userAgent'],
                'ip' => $log['ip'],
                'location' => $log['location'] ?? null,
                'time' => $log['timestamp'],
                'data' => $log['data'] ?? [],
            ]);
        }

        return $documents;
    }

    /**
     * Parse ClickHouse query result into Documents.
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
            if (count($columns) < 9) {
                continue;
            }

            $data = [];
            try {
                $data = json_decode($columns[8], true) ?? [];
            } catch (\Exception $e) {
                $data = [];
            }

            $documents[] = new Document([
                '$id' => $columns[0],
                'userId' => $columns[1] === '\\N' ? null : $columns[1],
                'event' => $columns[2],
                'resource' => $columns[3],
                'userAgent' => $columns[4],
                'ip' => $columns[5],
                'location' => $columns[6] === '\\N' ? null : $columns[6],
                'time' => $columns[7],
                'data' => $data,
            ]);
        }

        return $documents;
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
            if (is_object($query) && method_exists($query, 'getMethod')) {
                if ($query->getMethod() === 'limit') {
                    $limit = $query->getValue();
                } elseif ($query->getMethod() === 'offset') {
                    $offset = $query->getValue();
                }
            }
        }

        $sql = "
            SELECT id, userId, event, resource, userAgent, ip, location, time, data
            FROM {$this->database}.{$this->table}
            WHERE userId = :userId
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
        $sql = "
            SELECT count() as count
            FROM {$this->database}.{$this->table}
            WHERE userId = :userId
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
            if (is_object($query) && method_exists($query, 'getMethod')) {
                if ($query->getMethod() === 'limit') {
                    $limit = $query->getValue();
                } elseif ($query->getMethod() === 'offset') {
                    $offset = $query->getValue();
                }
            }
        }

        $sql = "
            SELECT id, userId, event, resource, userAgent, ip, location, time, data
            FROM {$this->database}.{$this->table}
            WHERE resource = :resource
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
        $sql = "
            SELECT count() as count
            FROM {$this->database}.{$this->table}
            WHERE resource = :resource
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
            if (is_object($query) && method_exists($query, 'getMethod')) {
                if ($query->getMethod() === 'limit') {
                    $limit = $query->getValue();
                } elseif ($query->getMethod() === 'offset') {
                    $offset = $query->getValue();
                }
            }
        }

        $eventsList = implode("', '", array_map('addslashes', $events));

        $sql = "
            SELECT id, userId, event, resource, userAgent, ip, location, time, data
            FROM {$this->database}.{$this->table}
            WHERE userId = :userId AND event IN ('{$eventsList}')
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

        $sql = "
            SELECT count() as count
            FROM {$this->database}.{$this->table}
            WHERE userId = :userId AND event IN ('{$eventsList}')
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
            if (is_object($query) && method_exists($query, 'getMethod')) {
                if ($query->getMethod() === 'limit') {
                    $limit = $query->getValue();
                } elseif ($query->getMethod() === 'offset') {
                    $offset = $query->getValue();
                }
            }
        }

        $eventsList = implode("', '", array_map('addslashes', $events));

        $sql = "
            SELECT id, userId, event, resource, userAgent, ip, location, time, data
            FROM {$this->database}.{$this->table}
            WHERE resource = :resource AND event IN ('{$eventsList}')
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

        $sql = "
            SELECT count() as count
            FROM {$this->database}.{$this->table}
            WHERE resource = :resource AND event IN ('{$eventsList}')
            FORMAT TabSeparated
        ";

        $result = $this->query($sql, ['resource' => $resource]);

        return (int) trim($result);
    }

    /**
     * Delete logs older than the specified datetime.
     *
     * ClickHouse uses a different approach for deletions - we use ALTER TABLE DELETE.
     *
     * @throws Exception
     */
    public function cleanup(string $datetime): bool
    {
        $sql = "
            ALTER TABLE {$this->database}.{$this->table}
            DELETE WHERE time < :datetime
        ";

        $this->query($sql, ['datetime' => $datetime]);

        return true;
    }
}
