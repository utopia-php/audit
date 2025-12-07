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
            username: 'default',
            password: 'clickhouse',
            port: 8123
        );

        $clickHouse->setDatabase('default');

        $this->audit = new Audit($clickHouse);
        $this->audit->setup();
    }
}
