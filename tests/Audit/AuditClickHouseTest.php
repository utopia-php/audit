<?php

namespace Utopia\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\Audit\Adapter\ClickHouse;
use Utopia\Audit\Audit;

/**
 * ClickHouse Adapter Tests
 *
 * Tests the Audit library using the ClickHouse adapter
 */
class AuditClickHouseTest extends TestCase
{
    use AuditBase;

    protected function initializeAudit(): void
    {
        $clickHouse = new ClickHouse(
            host: 'clickhouse',
            database: 'default',
            username: 'default',
            password: '',
            port: 8123,
            table: 'audit_logs'
        );

        $this->audit = new Audit($clickHouse);
        $this->audit->setup();
    }
}
