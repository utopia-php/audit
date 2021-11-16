<?php
/**
 * Utopia PHP Framework
 *
 * @package Abuse
 * @subpackage Tests
 *
 * @link https://github.com/utopia-php/framework
 * @author Eldad Fux <eldad@appwrite.io>
 * @version 1.0 RC4
 * @license The MIT License (MIT) <http://www.opensource.org/licenses/mit-license.php>
 */

namespace Utopia\Tests;

use PDO;
use Utopia\Audit\Audit;
use PHPUnit\Framework\TestCase;
use Utopia\Cache\Cache;
use Utopia\Cache\Adapter\None as NoCache;
use Utopia\Database\Adapter\MariaDB;
use Utopia\Database\Database;

class AuditTest extends TestCase
{
    /**
     * @var Audit
     */
    protected $audit = null;
    protected $initialized = false;

    public function setUp(): void
    {
        $dbHost = 'mariadb';
        $dbUser = 'root';
        $dbPort = '3306';
        $dbUser = 'root';
        $dbPass = 'password';

        $pdo = new PDO("mysql:host={$dbHost};port={$dbPort};charset=utf8mb4", $dbUser, $dbPass, array(
            PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8mb4',
            PDO::ATTR_TIMEOUT => 3, // Seconds
            PDO::ATTR_PERSISTENT => true
        ));

        // Connection settings
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);   // Return arrays
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);        // Handle all errors with exceptions 

        $cache = new Cache(new NoCache());

        $database = new Database(new MariaDB($pdo),$cache);
        $database->setNamespace('namespace');

        $this->audit = new Audit($database);
        if(!$database->exists()) {
            $database->create();
            $this->audit->setup();
        }
    }

    public function tearDown(): void
    {
        $this->audit->cleanup(time());
        $this->audit = null;
    }

    public function testLog()
    {
        $userId = 'userId';
        $userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36';
        $ip = '127.0.0.1';
        $location = 'US';
        $data = ['key1' => 'value1','key2' => 'value2'];
        $this->assertEquals($this->audit->log($userId, 'update', 'database/document/1', $userAgent, $ip, $location, $data), true);
        $this->assertEquals($this->audit->log($userId, 'update', 'database/document/2', $userAgent, $ip, $location, $data), true);
        $this->assertEquals($this->audit->log($userId, 'delete', 'database/document/2', $userAgent, $ip, $location, $data), true);
    }

    public function testGetLogsByUser()
    {
        $logs = $this->audit->getLogsByUser('userId');
        $this->assertEquals(3, \count($logs));

        $logsCount = $this->audit->getLogsByUserCount('userId');
        $this->assertEquals(3, $logsCount);

        $logs1 = $this->audit->getLogsByUser('userId', 1, 1);
        $this->assertEquals(1, \count($logs1));
        $this->assertEquals($logs1[0]->getId(), $logs[1]->getId());

        $logs2 = $this->audit->getLogsByUser('userId', 1, 0, $logs[0]);
        $this->assertEquals(1, \count($logs2));
        $this->assertEquals($logs2[0]->getId(), $logs[1]->getId());
    }

    public function testGetLogsByUserAndEvents()
    {
        $logs1 = $this->audit->getLogsByUserAndEvents('userId', ['update']);
        $logs2 = $this->audit->getLogsByUserAndEvents('userId', ['update', 'delete']);

        $this->assertEquals(2, \count($logs1));
        $this->assertEquals(3, \count($logs2));

        $logsCount1 = $this->audit->getLogsByUserAndEventsCount('userId', ['update']);
        $logsCount2 = $this->audit->getLogsByUserAndEventsCount('userId', ['update', 'delete']);

        $this->assertEquals(2, $logsCount1);
        $this->assertEquals(3, $logsCount2);

        $logs3 = $this->audit->getLogsByUserAndEvents('userId', ['update', 'delete'], 1, 1);

        $this->assertEquals(1, \count($logs3));
        $this->assertEquals($logs3[0]->getId(), $logs2[1]->getId());

        $logs4 = $this->audit->getLogsByUserAndEvents('userId', ['update', 'delete'], 1, 0, $logs2[0]);

        $this->assertEquals(1, \count($logs4));
        $this->assertEquals($logs4[0]->getId(), $logs2[1]->getId());
    }

    public function testGetLogsByResourceAndEvents()
    {
        $logs1 = $this->audit->getLogsByResourceAndEvents('database/document/1', ['update']);
        $logs2 = $this->audit->getLogsByResourceAndEvents('database/document/2', ['update', 'delete']);

        $this->assertEquals(1, \count($logs1));
        $this->assertEquals(2, \count($logs2));

        $logsCount1 = $this->audit->getLogsByResourceAndEventsCount('database/document/1', ['update']);
        $logsCount2 = $this->audit->getLogsByResourceAndEventsCount('database/document/2', ['update', 'delete']);

        $this->assertEquals(1, $logsCount1);
        $this->assertEquals(2, $logsCount2);

        $logs3 = $this->audit->getLogsByResourceAndEvents('database/document/2', ['update', 'delete'], 1, 1);

        $this->assertEquals(1, \count($logs3));
        $this->assertEquals($logs3[0]->getId(), $logs2[1]->getId());

        $logs4 = $this->audit->getLogsByResourceAndEvents('database/document/2', ['update', 'delete'], 1, 0, $logs2[0]);

        $this->assertEquals(1, \count($logs4));
        $this->assertEquals($logs4[0]->getId(), $logs2[1]->getId());
    }

    public function testGetLogsByResource()
    {
        $logs1 = $this->audit->getLogsByResource('database/document/1');
        $logs2 = $this->audit->getLogsByResource('database/document/2');

        $this->assertEquals(1, \count($logs1));
        $this->assertEquals(2, \count($logs2));

        $logsCount1 = $this->audit->getLogsByResourceCount('database/document/1');
        $logsCount2 = $this->audit->getLogsByResourceCount('database/document/2');

        $this->assertEquals(1, $logsCount1);
        $this->assertEquals(2, $logsCount2);

        $logs3 = $this->audit->getLogsByResource('database/document/2', 1, 1);
        $this->assertEquals(1, \count($logs3));
        $this->assertEquals($logs3[0]->getId(), $logs2[1]->getId());

        $logs4 = $this->audit->getLogsByResource('database/document/2', 1, 0, $logs2[0]);
        $this->assertEquals(1, \count($logs4));
        $this->assertEquals($logs4[0]->getId(), $logs2[1]->getId());
    }

    public function testCleanup() {
        sleep(3);
        // First delete all the logs
        $status = $this->audit->cleanup(time());
        $this->assertEquals($status, true);

        // Check that all logs have been deleted 
        $logs = $this->audit->getLogsByUser('userId');
        $this->assertEquals(0, \count($logs));

        // Add three sample logs 
        $userId = 'userId';
        $userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36';
        $ip = '127.0.0.1';
        $location = 'US';
        $data = ['key1' => 'value1','key2' => 'value2'];

        $this->assertEquals($this->audit->log($userId, 'update', 'database/document/1', $userAgent, $ip, $location, $data), true);
        sleep(5);
        $this->assertEquals($this->audit->log($userId, 'update', 'database/document/2', $userAgent, $ip, $location, $data), true);
        sleep(5);
        $this->assertEquals($this->audit->log($userId, 'delete', 'database/document/2', $userAgent, $ip, $location, $data), true);
        sleep(5);

        // DELETE logs older than 10 seconds and check that status is true
        $status = $this->audit->cleanup(time()-10);
        $this->assertEquals($status, true);

        // Check if 1 log has been deleted
        $logs = $this->audit->getLogsByUser('userId');
        $this->assertEquals(2, \count($logs));
    }
}
