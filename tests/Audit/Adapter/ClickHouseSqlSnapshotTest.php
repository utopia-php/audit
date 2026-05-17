<?php

namespace Utopia\Tests\Audit\Adapter;

use PHPUnit\Framework\TestCase;
use Utopia\Query\Builder\ClickHouse as ClickHouseBuilder;
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
    public function testSetupCreateTableSnapshot(): void
    {
        $schema = new ClickHouseSchema();
        $table = $schema->table('default.audits');
        $table->string('id')->primary();
        $table->string('userId')->nullable();
        $table->string('event');
        $table->string('resource')->nullable();
        $table->string('userAgent');
        $table->string('ip');
        $table->string('location')->nullable();
        $table->datetime('time', precision: 3);
        $table->addColumn('data', ColumnType::String)->nullable();

        $table->index(
            columns: ['event'],
            name: 'idx_event',
            algorithm: IndexAlgorithm::BloomFilter,
            granularity: 1,
        );
        $table->index(
            columns: ['userId', 'event'],
            name: 'idx_userId_event',
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
        $this->assertStringContainsString('`userId` Nullable(String)', $sql);
        $this->assertStringContainsString('`event` String', $sql);
        $this->assertStringContainsString('`time` DateTime64(3)', $sql);
        $this->assertStringContainsString('INDEX `idx_event` `event` TYPE bloom_filter GRANULARITY 1', $sql);
        $this->assertStringContainsString('INDEX `idx_userId_event` (`userId`, `event`) TYPE bloom_filter GRANULARITY 1', $sql);
        $this->assertStringContainsString('ENGINE = MergeTree()', $sql);
        $this->assertStringContainsString('PARTITION BY toYYYYMM(time)', $sql);
        $this->assertStringContainsString('ORDER BY (`time`, `id`)', $sql);
        $this->assertStringContainsString('SETTINGS index_granularity = 8192', $sql);
    }

    public function testInsertFormatJsonEachRowSnapshot(): void
    {
        $columns = ['id', 'time', 'userId', 'event', 'data'];
        $sql = (new ClickHouseBuilder())
            ->into('default.audits')
            ->insertFormat('JSONEachRow', $columns)
            ->insert()
            ->query;

        $this->assertEquals(
            'INSERT INTO `default`.`audits` (`id`, `time`, `userId`, `event`, `data`) FORMAT JSONEachRow',
            $sql,
        );
    }

    public function testAsyncCleanupDeleteEmitsSettingsClause(): void
    {
        $sql = (new ClickHouseBuilder())
            ->into('default.audits')
            ->whereRaw('`time` < {datetime:DateTime64(3)}')
            ->settings(['mutations_sync' => '0'])
            ->delete()
            ->query;

        $this->assertEquals(
            'ALTER TABLE `default`.`audits` DELETE WHERE `time` < {datetime:DateTime64(3)} SETTINGS mutations_sync=0',
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
            'ALTER TABLE `default`.`audits` DELETE WHERE `time` < {datetime:DateTime64(3)}',
            $sql,
        );
    }

    public function testFindSelectWithCursorAndOrderRaw(): void
    {
        $builder = (new ClickHouseBuilder())
            ->from('default.audits')
            ->selectRaw('`id`, `event`, `time`')
            ->whereRaw('`userId` = {param_0:String}')
            ->whereRaw('(`time` < {cursor_cmp_0:DateTime64(3)}) OR (`time` = {cursor_eq_1_0:DateTime64(3)} AND `id` < {cursor_cmp_1:String})')
            ->orderByRaw('`time` DESC')
            ->orderByRaw('`id` DESC');

        $sql = $builder->build()->query . ' LIMIT {limit:UInt64} FORMAT JSON';

        $expected = 'SELECT `id`, `event`, `time` FROM `default`.`audits` '
            . 'WHERE `userId` = {param_0:String} AND '
            . '(`time` < {cursor_cmp_0:DateTime64(3)}) OR (`time` = {cursor_eq_1_0:DateTime64(3)} AND `id` < {cursor_cmp_1:String}) '
            . 'ORDER BY `time` DESC, `id` DESC '
            . 'LIMIT {limit:UInt64} FORMAT JSON';

        $this->assertEquals($expected, $sql);
    }
}
