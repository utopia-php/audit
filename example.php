<?php

/**
 * Utopia Audit Example
 *
 * This example demonstrates how to use the Utopia Audit library
 * with the Database adapter to log user actions.
 */

require_once __DIR__ . '/vendor/autoload.php';

use PDO;
use Utopia\Audit\Audit;
use Utopia\Cache\Cache;
use Utopia\Cache\Adapter\None as NoCache;
use Utopia\Database\Adapter\MySQL;
use Utopia\Database\Database;
use Utopia\Database\DateTime;

// Database configuration
$dbHost = '127.0.0.1';
$dbUser = 'root';
$dbPass = 'password';
$dbPort = '3306';

try {
    // Create PDO instance
    $pdo = new PDO("mysql:host={$dbHost};port={$dbPort};charset=utf8mb4", $dbUser, $dbPass, [
        PDO::ATTR_TIMEOUT => 3,
        PDO::ATTR_PERSISTENT => true,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => true,
        PDO::ATTR_STRINGIFY_FETCHES => true,
    ]);

    // Create cache instance
    $cache = new Cache(new NoCache());

    // Create database instance
    $database = new Database(new MySQL($pdo), $cache);
    $database->setDatabase('auditExample');
    $database->setNamespace('example');

    // Create database if it doesn't exist
    if (!$database->exists('auditExample')) {
        $database->create();
    }

    // Method 1: Create Audit instance using the Database adapter (recommended)
    $audit = Audit::withDatabase($database);

    // Setup the audit collection (creates tables/collections and indexes)
    $audit->setup();

    echo "✓ Audit instance created and setup completed\n\n";

    // Example 1: Log a single event
    echo "Example 1: Logging a single event\n";
    $document = $audit->log(
        userId: 'user-123',
        event: 'document.create',
        resource: 'database/collection/document-456',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        ip: '192.168.1.100',
        location: 'US',
        data: [
            'documentId' => 'document-456',
            'collectionId' => 'collection-789',
            'action' => 'created new document'
        ]
    );
    echo "✓ Created log with ID: {$document->getId()}\n\n";

    // Example 2: Log multiple events in batch
    echo "Example 2: Batch logging multiple events\n";
    $batchEvents = [
        [
            'userId' => 'user-123',
            'event' => 'document.update',
            'resource' => 'database/collection/document-456',
            'userAgent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'ip' => '192.168.1.100',
            'location' => 'US',
            'data' => ['field' => 'title', 'oldValue' => 'Old Title', 'newValue' => 'New Title'],
            'timestamp' => DateTime::now()
        ],
        [
            'userId' => 'user-456',
            'event' => 'user.login',
            'resource' => 'auth/session/session-789',
            'userAgent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'ip' => '192.168.1.101',
            'location' => 'UK',
            'data' => ['sessionId' => 'session-789', 'method' => 'email'],
            'timestamp' => DateTime::now()
        ],
    ];

    $documents = $audit->logBatch($batchEvents);
    echo "✓ Created " . count($documents) . " logs in batch\n\n";

    // Example 3: Retrieve logs by user
    echo "Example 3: Retrieving logs by user\n";
    $userLogs = $audit->getLogsByUser('user-123');
    echo "✓ Found " . count($userLogs) . " logs for user-123\n";
    foreach ($userLogs as $log) {
        echo "  - Event: {$log->getAttribute('event')}, Resource: {$log->getAttribute('resource')}\n";
    }
    echo "\n";

    // Example 4: Retrieve logs by user and specific events
    echo "Example 4: Retrieving logs by user and events\n";
    $eventLogs = $audit->getLogsByUserAndEvents('user-123', ['document.create', 'document.update']);
    echo "✓ Found " . count($eventLogs) . " document events for user-123\n\n";

    // Example 5: Retrieve logs by resource
    echo "Example 5: Retrieving logs by resource\n";
    $resourceLogs = $audit->getLogsByResource('database/collection/document-456');
    echo "✓ Found " . count($resourceLogs) . " logs for resource\n\n";

    // Example 6: Count logs
    echo "Example 6: Counting logs\n";
    $userLogsCount = $audit->countLogsByUser('user-123');
    echo "✓ Total logs for user-123: {$userLogsCount}\n\n";

    // Example 7: Using with custom adapter (alternative method)
    echo "Example 7: Using custom adapter\n";
    $customAdapter = new \Utopia\Audit\Adapter\Database($database);
    $auditWithAdapter = Audit::withAdapter($customAdapter);
    echo "✓ Audit created with custom adapter: {$customAdapter->getName()}\n\n";

    // Example 8: Cleanup old logs
    echo "Example 8: Cleanup old logs (commented out to preserve examples)\n";
    // $oldDate = DateTime::addSeconds(new \DateTime(), -3600); // Logs older than 1 hour
    // $audit->cleanup($oldDate);
    echo "✓ Cleanup example available (currently commented out)\n\n";

    echo "All examples completed successfully!\n";
} catch (\Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    echo "Trace: " . $e->getTraceAsString() . "\n";
    exit(1);
}
