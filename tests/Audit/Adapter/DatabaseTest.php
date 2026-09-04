<?php

declare(strict_types=1);

namespace Utopia\Tests\Audit\Adapter;

use PDO;
use PHPUnit\Framework\TestCase;
use Utopia\Audit\Adapter;
use Utopia\Audit\Audit;
use Utopia\Audit\Log;
use Utopia\Audit\Query;
use Utopia\Cache\Adapter\None as NoCache;
use Utopia\Cache\Cache;
use Utopia\Database\Adapter\MariaDB;
use Utopia\Database\Attribute;
use Utopia\Database\Database;
use Utopia\Database\Index;
use Utopia\Query\Schema\ColumnType;
use Utopia\Query\Schema\IndexType;
use Utopia\Tests\Audit\AuditBase;

/**
 * Database Adapter Tests
 */
final class DatabaseTest extends TestCase
{
    use AuditBase;

    protected function initializeAudit(): void
    {
        $host = getenv('MARIADB_HOST') ?: '127.0.0.1';
        $port = getenv('MARIADB_PORT') ?: '13307';
        $username = 'root';
        $password = 'password';

        $attributes = MariaDB::getPdoAttributes();
        $attributes[PDO::ATTR_PERSISTENT] = false;
        $connection = new PDO("mysql:host={$host};port={$port};charset=utf8mb4", $username, $password, $attributes);
        $cache = new Cache(new NoCache());
        $database = new Database(new MariaDB($connection), $cache);
        $database->setDatabase('utopiaTests');
        $database->setNamespace('namespace');

        $adapter = new Adapter\Database($database);
        $this->audit = new Audit($adapter);
        if (! $database->exists('utopiaTests')) {
            $database->create();
            $this->audit->setup();
        }
    }

    public function testSchemaValueObjectsAndNullableLog(): void
    {
        $adapter = $this->audit->getAdapter();
        $this->assertInstanceOf(Adapter\Database::class, $adapter);

        $attributes = $adapter->getAttributes();
        $this->assertCount(7, $attributes);
        foreach ($attributes as $attribute) {
            $this->assertInstanceOf(Attribute::class, $attribute);
            $this->assertNull($attribute->default);
        }
        $this->assertSame('userId', $attributes[0]->key);
        $this->assertSame(ColumnType::String, $attributes[0]->type);
        $this->assertSame(Database::LENGTH_KEY, $attributes[0]->size);
        $this->assertFalse($attributes[0]->required);
        $this->assertTrue($attributes[1]->required);
        $this->assertSame(ColumnType::Datetime, $attributes[5]->type);
        $this->assertSame(['datetime'], $attributes[5]->filters);
        $this->assertSame(['json'], $attributes[6]->filters);

        $indexes = $adapter->getIndexes();
        $this->assertCount(4, $indexes);
        foreach ($indexes as $index) {
            $this->assertInstanceOf(Index::class, $index);
            $this->assertSame(IndexType::Key, $index->type);
        }
        $this->assertSame(['userId', 'event'], $indexes[1]->attributes);

        $log = $this->audit->log(null, 'schema.created', 'schema/defaults', 'test', '127.0.0.1');
        $stored = $this->audit->getLogById($log->getId());
        $this->assertInstanceOf(Log::class, $stored);
        $this->assertNull($stored->getUserId());
        $this->assertSame([], $stored->getAttribute('data'));
        $this->assertNotEmpty($stored->getAttribute('time'));
        $logs = $this->audit->find([
            Query::equal('resource', ['schema/defaults']),
            Query::containsString('event', ['created']),
        ]);
        $this->assertCount(1, $logs);
        $this->assertSame($log->getId(), $logs[0]->getId());
    }
}
