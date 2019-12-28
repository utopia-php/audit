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
use Utopia\Audit\Adapters\MySQL;
use PHPUnit\Framework\TestCase;

class AuditTest extends TestCase
{
    /**
     * @var Audit
     */
    protected $audit = null;

    public function setUp()
    {
        $dbHost = '127.0.0.1';
        $dbUser = 'travis';
        $dbPass = '';
        $dbName = 'audit';

        $pdo = new PDO("mysql:host={$dbHost};dbname={$dbName}", $dbUser, $dbPass, array(
            PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8',
            PDO::ATTR_TIMEOUT => 5 // Seconds
        ));

        // Connection settings
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);   // Return arrays
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);        // Handle all errors with exceptions

        $adapter = new MySQL($pdo);

        $adapter
            ->setNamespace('namespace') // DB table namespace
        ;

        $userId = 'userId';
        $userType = 'userType';
        $userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36';
        $ip = '127.0.0.1';
        $location = 'US';

        $this->audit = new Audit($adapter, $userId, $userType, $userAgent, $ip, $location);
    }

    public function tearDown()
    {
        $this->audit = null;
    }

    public function testLog()
    {
        var_dump($this->audit->log('update', 'document/document-1', ['key1' => 'value1','key2' => 'value2']));
        $this->assertEquals($this->audit->log('update', 'document/document-1', ['key1' => 'value1','key2' => 'value2']), true);
    }
}
