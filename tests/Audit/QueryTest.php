<?php

declare(strict_types=1);

namespace Utopia\Tests\Audit;

use PHPUnit\Framework\TestCase;
use Utopia\Audit\Query;

final class QueryTest extends TestCase
{
    /**
     * Test Query class static factory methods
     */
    public function test_query_static_factory_methods(): void
    {
        // Test equal
        $query = Query::equal('userId', '123');
        $this->assertSame(Query::TYPE_EQUAL, $query->getMethod()->value);
        $this->assertSame('userId', $query->getAttribute());
        $this->assertSame(['123'], $query->getValues());

        // Test lessThan
        $query = Query::lessThan('time', '2024-01-01');
        $this->assertSame(Query::TYPE_LESSER, $query->getMethod()->value);
        $this->assertSame('time', $query->getAttribute());
        $this->assertSame(['2024-01-01'], $query->getValues());

        // Test greaterThan
        $query = Query::greaterThan('time', '2023-01-01');
        $this->assertSame(Query::TYPE_GREATER, $query->getMethod()->value);
        $this->assertSame('time', $query->getAttribute());
        $this->assertSame(['2023-01-01'], $query->getValues());

        // Test between
        $query = Query::between('time', '2023-01-01', '2024-01-01');
        $this->assertSame(Query::TYPE_BETWEEN, $query->getMethod()->value);
        $this->assertSame('time', $query->getAttribute());
        $this->assertSame(['2023-01-01', '2024-01-01'], $query->getValues());

        $query = Query::contains('event', ['create', 'update', 'delete']);
        $this->assertSame(Query::TYPE_CONTAINS, $query->getMethod()->value);
        $this->assertSame('event', $query->getAttribute());
        $this->assertSame(['create', 'update', 'delete'], $query->getValues());

        // Test orderDesc
        $query = Query::orderDesc('time');
        $this->assertSame(Query::TYPE_ORDER_DESC, $query->getMethod()->value);
        $this->assertSame('time', $query->getAttribute());
        $this->assertSame([], $query->getValues());

        // Test orderAsc
        $query = Query::orderAsc('userId');
        $this->assertSame(Query::TYPE_ORDER_ASC, $query->getMethod()->value);
        $this->assertSame('userId', $query->getAttribute());
        $this->assertSame([], $query->getValues());

        // Test limit
        $query = Query::limit(10);
        $this->assertSame(Query::TYPE_LIMIT, $query->getMethod()->value);
        $this->assertSame('', $query->getAttribute());
        $this->assertSame([10], $query->getValues());

        // Test offset
        $query = Query::offset(5);
        $this->assertSame(Query::TYPE_OFFSET, $query->getMethod()->value);
        $this->assertSame('', $query->getAttribute());
        $this->assertSame([5], $query->getValues());
    }

    /**
     * Test Query parse and toString methods
     */
    public function test_query_parse_and_to_string(): void
    {
        // Test parsing equal query
        $json = '{"method":"equal","attribute":"userId","values":["123"]}';
        $query = Query::parse($json);
        $this->assertSame(Query::TYPE_EQUAL, $query->getMethod()->value);
        $this->assertSame('userId', $query->getAttribute());
        $this->assertSame(['123'], $query->getValues());

        // Test toString
        $query = Query::equal('event', 'create');
        $json = $query->toString();
        $this->assertJson($json);

        $parsed = Query::parse($json);
        $this->assertSame(Query::TYPE_EQUAL, $parsed->getMethod()->value);
        $this->assertSame('event', $parsed->getAttribute());
        $this->assertSame(['create'], $parsed->getValues());

        // Test toArray
        $array = $query->toArray();
        $this->assertArrayHasKey('method', $array);
        $this->assertArrayHasKey('attribute', $array);
        $this->assertArrayHasKey('values', $array);
        $this->assertEquals(Query::TYPE_EQUAL, $array['method']);
        $this->assertEquals('event', $array['attribute']);
        $this->assertEquals(['create'], $array['values']);
    }

    /**
     * Test Query parseQueries method
     */
    public function test_query_parse_queries(): void
    {
        $queries = [
            '{"method":"equal","attribute":"userId","values":["123"]}',
            '{"method":"greaterThan","attribute":"time","values":["2023-01-01"]}',
            '{"method":"limit","values":[10]}',
        ];

        $parsed = Query::parseQueries($queries);

        $this->assertCount(3, $parsed);
        $this->assertInstanceOf(Query::class, $parsed[0]);
        $this->assertInstanceOf(Query::class, $parsed[1]);
        $this->assertInstanceOf(Query::class, $parsed[2]);

        $this->assertSame(Query::TYPE_EQUAL, $parsed[0]->getMethod()->value);
        $this->assertSame(Query::TYPE_GREATER, $parsed[1]->getMethod()->value);
        $this->assertSame(Query::TYPE_LIMIT, $parsed[2]->getMethod()->value);
    }

    /**
     * Test Query getValue method
     */
    public function test_get_value(): void
    {
        $query = Query::equal('userId', '123');
        $this->assertEquals('123', $query->getValue());

        $query = Query::limit(10);
        $this->assertEquals(10, $query->getValue());

        // Test with default value
        $query = Query::orderAsc('time');
        $this->assertNull($query->getValue());
        $this->assertEquals('default', $query->getValue('default'));
    }

    /**
     * Test Query with empty attribute
     */
    public function test_query_with_empty_attribute(): void
    {
        $query = Query::limit(25);
        $this->assertSame('', $query->getAttribute());
        $this->assertSame([25], $query->getValues());

        $query = Query::offset(10);
        $this->assertSame('', $query->getAttribute());
        $this->assertSame([10], $query->getValues());
    }

    /**
     * Test Query parse with invalid JSON
     */
    public function test_query_parse_invalid_json(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid query');

        Query::parse('{"method":"equal","attribute":"userId"'); // Invalid JSON
    }

    /**
     * Test Query parse with non-array value
     */
    public function test_query_parse_non_array(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid query. Must be an array');

        Query::parse('"string"');
    }

    /**
     * Test Query parse with invalid method type
     */
    public function test_query_parse_invalid_method_type(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid query method. Must be a string');

        Query::parse('{"method":["array"],"attribute":"test","values":[]}');
    }

    /**
     * Test Query parse with invalid attribute type
     */
    public function test_query_parse_invalid_attribute_type(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid query attribute. Must be a string');

        Query::parse('{"method":"equal","attribute":123,"values":[]}');
    }

    /**
     * Test Query parse with invalid values type
     */
    public function test_query_parse_invalid_values_type(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid query values. Must be an array');

        Query::parse('{"method":"equal","attribute":"test","values":"string"}');
    }

    /**
     * Test Query toString with complex values
     */
    public function test_query_to_string_with_complex_values(): void
    {
        $query = Query::between('time', '2023-01-01', '2024-12-31');
        $json = $query->toString();
        $this->assertJson($json);

        $parsed = Query::parse($json);
        $this->assertSame(Query::TYPE_BETWEEN, $parsed->getMethod()->value);
        $this->assertSame('time', $parsed->getAttribute());
        $this->assertSame(['2023-01-01', '2024-12-31'], $parsed->getValues());
    }
}
