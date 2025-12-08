<?php

namespace Utopia\Tests\Audit\Adapter;

use PHPUnit\Framework\TestCase;
use Utopia\Audit\Adapter\ClickHouse;
use Utopia\Audit\Audit;
use Utopia\Tests\Audit\AuditBase;

/**
 * ClickHouse Adapter Tests
 */
class ClickHouseTest extends TestCase
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
