<?php

namespace Utopia\Tests\Audit\Adapter;

use PHPUnit\Framework\TestCase;
use Utopia\Query\Builder\ClickHouse as ClickHouseBuilder;
use Utopia\Query\Builder\ClickHouse\Format;
use Utopia\Query\Query;
use Utopia\Query\Schema\ClickHouse as ClickHouseSchema;
use Utopia\Query\Schema\ClickHouse\Engine as ClickHouseEngine;
use Utopia\Query\Schema\ClickHouse\IndexAlgorithm;
use Utopia\Query\Schema\ColumnType;

/**
 * Snapshot tests for the SQL emitted by the migrated ClickHouse adapter
 * paths. These pin the exact shape produced by `Schema\ClickHouse` and
 * `Builder\ClickHouse` for the audit DDL/INSERT/DELETE/SELECT surfaces so
 * a query-lib upgrade can't quietly change adapter SQL.
 */
class ClickHouseSqlSnapshotTest extends TestCase
{
    /**
     * @return array<string, string>
     */
    private function auditTypeMap(): array
    {
        return [
            'id' => 'String',
            'actorId' => 'String',
            'actorType' => 'String',
            'actorInternalId' => 'String',
            'event' => 'String',
            'resource' => 'String',
            'userAgent' => 'String',
            'ip' => 'String',
            'time' => 'DateTime64(3)',
            'data' => 'String',
            'tenant' => 'UInt64',
        ];
    }

    private function newAuditBuilder(): ClickHouseBuilder
    {
        return (new ClickHouseBuilder())
            ->useNamedBindings()
            ->withParamTypes($this->auditTypeMap());
    }

    public function testSetupCreateTableSnapshot(): void
    {
        $schema = new ClickHouseSchema();
        $table = $schema->table('default.audits');
        $table->string('id')->primary();
        $table->string('actorId')->nullable();
        $table->string('actorType');
        $table->string('actorInternalId')->nullable();
        $table->string('event');
        $table->string('resource')->nullable();
        $table->string('userAgent');
        $table->string('ip');
        $table->datetime('time', precision: 3);
        $table->addColumn('data', ColumnType::String)->nullable();

        $table->index(
            columns: ['event'],
            name: 'idx_event',
            algorithm: IndexAlgorithm::BloomFilter,
            granularity: 1,
        );
        $table->index(
            columns: ['actorId', 'event'],
            name: 'idx_actorId_event',
            algorithm: IndexAlgorithm::BloomFilter,
            granularity: 1,
        );
        $table->index(
            columns: ['actorType'],
            name: '_key_actor_type',
            algorithm: IndexAlgorithm::BloomFilter,
            granularity: 1,
        );

        $table->engine(ClickHouseEngine::MergeTree);
        $table->orderBy(['time', 'id']);
        $table->partitionBy('toYYYYMM(time)');
        $table->settings(['index_granularity' => '8192']);

        $sql = $table->createIfNotExists()->query;

        $this->assertStringContainsString('CREATE TABLE IF NOT EXISTS `default`.`audits`', $sql);
        $this->assertStringContainsString('`id` String', $sql);
        $this->assertStringContainsString('`actorId` Nullable(String)', $sql);
        $this->assertStringContainsString('`actorType` String', $sql);
        $this->assertStringContainsString('`actorInternalId` Nullable(String)', $sql);
        $this->assertStringContainsString('`event` String', $sql);
        $this->assertStringContainsString('`time` DateTime64(3)', $sql);
        $this->assertStringNotContainsString('`location`', $sql);
        $this->assertStringNotContainsString('`userId`', $sql);
        $this->assertStringContainsString('INDEX `idx_event` `event` TYPE bloom_filter GRANULARITY 1', $sql);
        $this->assertStringContainsString('INDEX `idx_actorId_event` (`actorId`, `event`) TYPE bloom_filter GRANULARITY 1', $sql);
        $this->assertStringContainsString('INDEX `_key_actor_type` `actorType` TYPE bloom_filter GRANULARITY 1', $sql);
        $this->assertStringContainsString('ENGINE = MergeTree()', $sql);
        $this->assertStringContainsString('PARTITION BY toYYYYMM(time)', $sql);
        $this->assertStringContainsString('ORDER BY (`time`, `id`)', $sql);
        $this->assertStringContainsString('SETTINGS index_granularity = 8192', $sql);
    }

    public function testBulkInsertJsonEachRowSnapshot(): void
    {
        $columns = ['id', 'time', 'actorId', 'actorType', 'event', 'data'];
        $rows = [
            [
                'id' => 'log-1',
                'time' => '2025-01-02 03:04:05.678',
                'actorId' => 'u1',
                'actorType' => 'users',
                'event' => 'users.create',
                'data' => '{"foo":"bar"}',
            ],
            [
                'id' => 'log-2',
                'time' => '2025-01-02 03:04:06.000',
                'actorId' => 'u2',
                'actorType' => 'users',
                'event' => 'users.delete',
                'data' => '{"foo":"baz"}',
            ],
        ];

        $statement = (new ClickHouseBuilder())
            ->into('default.audits')
            ->bulkInsert(Format::JSONEachRow, $rows, $columns);

        $this->assertEquals(
            'INSERT INTO `default`.`audits` (`id`, `time`, `actorId`, `actorType`, `event`, `data`) FORMAT JSONEachRow',
            $statement->query,
        );
        $this->assertSame('JSONEachRow', $statement->format);
        $this->assertSame($columns, $statement->columns);
        $this->assertSame(
            '{"id":"log-1","time":"2025-01-02 03:04:05.678","actorId":"u1","actorType":"users","event":"users.create","data":"{\"foo\":\"bar\"}"}' . "\n"
            . '{"id":"log-2","time":"2025-01-02 03:04:06.000","actorId":"u2","actorType":"users","event":"users.delete","data":"{\"foo\":\"baz\"}"}',
            $statement->body,
        );
    }

    public function testAsyncCleanupDeleteEmitsSettingsClause(): void
    {
        $sql = (new ClickHouseBuilder())
            ->into('default.audits')
            ->whereRaw('`time` < {datetime:DateTime64(3)}')
            ->settings(['lightweight_deletes_sync' => '0'])
            ->delete()
            ->query;

        $this->assertEquals(
            'DELETE FROM `default`.`audits` WHERE `time` < {datetime:DateTime64(3)} SETTINGS lightweight_deletes_sync=0',
            $sql,
        );
    }

    public function testSyncCleanupDeleteOmitsSettingsClause(): void
    {
        $sql = (new ClickHouseBuilder())
            ->into('default.audits')
            ->whereRaw('`time` < {datetime:DateTime64(3)}')
            ->delete()
            ->query;

        $this->assertEquals(
            'DELETE FROM `default`.`audits` WHERE `time` < {datetime:DateTime64(3)}',
            $sql,
        );
    }

    public function testFindEmitsTypedNamedBindings(): void
    {
        $statement = $this->newAuditBuilder()
            ->from('default.audits')
            ->selectRaw('`id`, `event`, `time`')
            ->filter([
                Query::equal('actorId', ['u1']),
                Query::between('time', '2025-01-01 00:00:00.000', '2025-12-31 00:00:00.000'),
            ])
            ->sortDesc('time')
            ->limit(25)
            ->build();

        $expectedSql = 'SELECT `id`, `event`, `time` FROM `default`.`audits` '
            . 'WHERE `actorId` IN ({param0:String}) '
            . 'AND `time` BETWEEN {param1:DateTime64(3)} AND {param2:DateTime64(3)} '
            . 'ORDER BY `time` DESC '
            . 'LIMIT {param3:Int64}';

        $this->assertEquals($expectedSql, $statement->query);
        $this->assertSame(
            [
                'param0' => 'u1',
                'param1' => '2025-01-01 00:00:00.000',
                'param2' => '2025-12-31 00:00:00.000',
                'param3' => 25,
            ],
            $statement->namedBindings,
        );
    }

    public function testNotContainsMultiValueEmitsTypedNotIn(): void
    {
        $statement = $this->newAuditBuilder()
            ->from('default.audits')
            ->selectRaw('`id`, `event`, `time`')
            ->filter([
                Query::notEqual('event', ['users.delete', 'projects.delete']),
            ])
            ->limit(25)
            ->build();

        $expectedSql = 'SELECT `id`, `event`, `time` FROM `default`.`audits` '
            . 'WHERE `event` NOT IN ({param0:String}, {param1:String}) '
            . 'LIMIT {param2:Int64}';

        $this->assertEquals($expectedSql, $statement->query);
        $this->assertSame(
            [
                'param0' => 'users.delete',
                'param1' => 'projects.delete',
                'param2' => 25,
            ],
            $statement->namedBindings,
        );
    }

    public function testFindCursorRawFragmentMergesWithTypedBindings(): void
    {
        $cursorClause = '((`time` < {cursor_cmp_0:DateTime64(3)}) '
            . 'OR (`time` = {cursor_eq_1_0:DateTime64(3)} AND `id` < {cursor_cmp_1:String}))';

        $statement = $this->newAuditBuilder()
            ->from('default.audits')
            ->selectRaw('`id`, `event`, `time`')
            ->filter([Query::equal('actorId', ['u1'])])
            ->whereRaw($cursorClause)
            ->sortDesc('time')
            ->sortDesc('id')
            ->limit(25)
            ->build();

        $expectedSql = 'SELECT `id`, `event`, `time` FROM `default`.`audits` '
            . 'WHERE `actorId` IN ({param0:String}) '
            . 'AND ' . $cursorClause . ' '
            . 'ORDER BY `time` DESC, `id` DESC '
            . 'LIMIT {param1:Int64}';

        $this->assertEquals($expectedSql, $statement->query);
        $this->assertSame(
            [
                'param0' => 'u1',
                'param1' => 25,
            ],
            $statement->namedBindings,
        );
    }

    public function testCountWithMaxWrapsInnerSelect(): void
    {
        $inner = $this->newAuditBuilder()
            ->from('default.audits')
            ->selectRaw('1')
            ->filter([Query::equal('actorId', ['u1'])])
            ->limit(5000)
            ->build();

        $sql = 'SELECT COUNT(*) AS count FROM (' . $inner->query . ') sub FORMAT TabSeparated';

        $this->assertEquals(
            'SELECT COUNT(*) AS count FROM ('
            . 'SELECT 1 FROM `default`.`audits` WHERE `actorId` IN ({param0:String}) LIMIT {param1:Int64}'
            . ') sub FORMAT TabSeparated',
            $sql,
        );
        $this->assertSame(
            ['param0' => 'u1', 'param1' => 5000],
            $inner->namedBindings,
        );
    }
}
