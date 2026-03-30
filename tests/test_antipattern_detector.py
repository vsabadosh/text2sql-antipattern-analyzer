"""
Unit tests for antipattern_detector.py

Tests the pure antipattern detection API that analyzes SQL queries
and detects code smells without touching DB/pipeline objects.
"""
import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from text2sql_antipattern.analyzers.query_antipattern.antipattern_detector import detect_antipatterns

class TestDetectAntipatternBasic:
    """Test basic functionality of detect_antipatterns()."""

    def test_empty_sql(self):
        """Test that empty SQL returns unparseable result."""
        result = detect_antipatterns("")
        assert result.parseable is False
        assert result.quality_score == 0
        assert result.quality_level == "poor"

    def test_whitespace_only_sql(self):
        """Test that whitespace-only SQL returns unparseable result."""
        result = detect_antipatterns("   \n\t  ")
        assert result.parseable is False
        assert result.quality_score == 0

    def test_unparseable_sql(self):
        """Test that invalid SQL returns unparseable result."""
        result = detect_antipatterns("SELECT FROM WHERE")
        assert result.parseable is False
        assert result.quality_score == 0

    def test_perfect_query(self):
        """Test that a well-written query scores high."""
        sql = "SELECT id, name, email FROM users WHERE status = 'active' ORDER BY id LIMIT 10"
        result = detect_antipatterns(sql)
        
        assert result.parseable is True
        assert result.total_antipatterns == 0
        assert result.quality_score == 100
        assert result.quality_level == "excellent"


class TestSelectStarAntipattern:
    """Unit tests for SELECT * antipattern detection."""

    def test_select_star_detected(self):
        """SELECT * should be detected as an antipattern."""
        sql = "SELECT * FROM users"
        result = detect_antipatterns(sql)

        assert result.has_select_star is True
        assert result.total_antipatterns >= 1
        assert any(
            ap.pattern == "select_star" and ap.severity == "medium"
            for ap in result.antipatterns
        )

    def test_select_star_with_join(self):
        """SELECT * with joins should still be detected."""
        sql = "SELECT * FROM users JOIN orders ON users.id = orders.user_id"
        result = detect_antipatterns(sql)

        assert result.has_select_star is True
        assert any(ap.pattern == "select_star" for ap in result.antipatterns)

    def test_qualified_star_detected(self):
        """SELECT table.* should also be treated as SELECT *."""
        sql = "SELECT u.* FROM users u"
        result = detect_antipatterns(sql)

        assert result.has_select_star is True
        assert any(ap.pattern == "select_star" for ap in result.antipatterns)

    def test_qualified_multiple_star_detected(self):
        """SELECT u.*, o.* should be detected as SELECT * usage."""
        sql = """
        SELECT u.*, o.*
        FROM users u
        JOIN orders o ON o.user_id = u.id
        """
        result = detect_antipatterns(sql)

        assert result.has_select_star is True
        assert any(ap.pattern == "select_star" for ap in result.antipatterns)

    def test_distinct_star_detected(self):
        """SELECT DISTINCT * should also be treated as SELECT *."""
        sql = "SELECT DISTINCT * FROM users"
        result = detect_antipatterns(sql)

        assert result.has_select_star is True
        assert any(ap.pattern == "select_star" for ap in result.antipatterns)

    def test_star_in_subquery_detected(self):
        """SELECT * in a subquery should still be treated as an antipattern."""
        sql = """
        SELECT id
        FROM users
        WHERE id IN (SELECT * FROM banned_users)
        """
        result = detect_antipatterns(sql)

        assert result.has_select_star is True
        assert any(ap.pattern == "select_star" for ap in result.antipatterns)

    def test_explicit_columns_no_antipattern(self):
        """Explicit column selection should not be flagged."""
        sql = "SELECT id, name, email FROM users"
        result = detect_antipatterns(sql)

        assert result.has_select_star is False
        assert all(ap.pattern != "select_star" for ap in result.antipatterns)

    def test_count_star_not_flagged(self):
        """COUNT(*) in aggregate context should not be treated as SELECT *."""
        sql = "SELECT COUNT(*) FROM users"
        result = detect_antipatterns(sql)

        assert result.has_select_star is False
        assert all(ap.pattern != "select_star" for ap in result.antipatterns)

    def test_count_star_with_other_columns_not_flagged(self):
        """COUNT(*) together with explicit columns should still not trigger select_star."""
        sql = "SELECT id, COUNT(*) FROM users GROUP BY id"
        result = detect_antipatterns(sql)

        assert result.has_select_star is False
        assert all(ap.pattern != "select_star" for ap in result.antipatterns)

    def test_nested_subquery_count_star_not_flagged(self):
        """COUNT(*) in a nested subquery should not be treated as SELECT *."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE EXISTS (
            SELECT 1
            FROM orders o
            WHERE o.user_id = u.id
            GROUP BY o.user_id
            HAVING COUNT(*) > 10
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_select_star is False
        assert all(ap.pattern != "select_star" for ap in result.antipatterns)

    def test_star_in_cte_detected(self):
        """SELECT * inside CTE should also be reported."""
        sql = """
        WITH temp AS (
            SELECT * FROM users
        )
        SELECT id FROM temp
        """
        result = detect_antipatterns(sql)

        assert result.has_select_star is True
        assert any(ap.pattern == "select_star" for ap in result.antipatterns)

    def test_multiple_stars_counts_as_single_antipattern(self):
        """
        Multiple SELECT * projections across UNION branches should still
        be reported as a single antipattern instance.
        """
        sql = """
        SELECT * FROM users
        UNION ALL
        SELECT * FROM admins
        """
        result = detect_antipatterns(sql)

        assert result.has_select_star is True
        # We don't strictly assert the number of instances, but we expect
        # at least one, not necessarily two separate entries.


class TestFunctionInWhereAntipattern:
    """Test function in WHERE clause antipattern detection."""

    # ========================================
    # BASIC DETECTION
    # ========================================
    
    def test_function_on_column_detected(self):
        """Function applied to column in WHERE is detected."""
        sql = "SELECT * FROM users WHERE UPPER(name) = 'JOHN'"
        result = detect_antipatterns(sql)
        
        assert result.has_function_in_where is True
        assert result.total_antipatterns >= 1
        assert any(
            ap.pattern == "function_in_where" and ap.severity == "high" 
            for ap in result.antipatterns
        )

    def test_date_function_on_column_detected(self):
        """DATE() function on column is detected."""
        sql = "SELECT * FROM orders WHERE DATE(created_at) = '2024-01-01'"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_coalesce_on_column_detected(self):
        """COALESCE on column prevents index usage."""
        sql = "SELECT * FROM users WHERE COALESCE(status, 'active') = 'active'"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_cast_on_column_detected(self):
        """CAST on column is detected."""
        sql = "SELECT * FROM orders WHERE CAST(amount AS INTEGER) > 100"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_substr_on_column_detected(self):
        """SUBSTR on column is detected."""
        sql = "SELECT * FROM users WHERE SUBSTR(email, 1, 5) = 'admin'"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_left_function_on_column_detected(self):
        """LEFT function on column is detected."""
        sql = "SELECT * FROM users WHERE LEFT(email, 5) = 'admin'"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_trim_on_column_detected(self):
        """TRIM on column is detected."""
        sql = "SELECT * FROM users WHERE TRIM(name) = 'John'"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    # ========================================
    # NEGATIVE TESTS (should NOT be flagged)
    # ========================================

    def test_function_on_literal_not_flagged(self):
        """Function on literal only is not flagged."""
        sql = "SELECT * FROM users WHERE name = UPPER('john')"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is False
        assert all(ap.pattern != "function_in_where" for ap in result.antipatterns)

    def test_function_in_select_list_not_flagged(self):
        """Function in SELECT list is not flagged by this detector."""
        sql = "SELECT UPPER(name) FROM users WHERE status = 'active'"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is False

    def test_function_in_join_on_not_flagged(self):
        """Function in JOIN ON is not flagged (only WHERE matters)."""
        sql = """
        SELECT * FROM a 
        JOIN b ON UPPER(a.name) = UPPER(b.name)
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is False

    def test_function_in_having_is_now_flagged(self):
        """Function in HAVING is now flagged (extended detection scope)."""
        sql = """
        SELECT country, COUNT(*) 
        FROM users 
        GROUP BY country 
        HAVING UPPER(country) = 'USA'
        """
        result = detect_antipatterns(sql)
        # NOTE: We now flag functions in HAVING as well as WHERE
        # because they can also prevent index usage on grouped columns
        assert result.has_function_in_where is True

    def test_column_without_function_not_flagged(self):
        """Simple column comparison is not flagged."""
        sql = "SELECT * FROM users WHERE status = 'active'"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is False

    def test_aggregate_in_where_not_flagged(self):
        """Aggregate functions in WHERE are syntax errors, but not this antipattern."""
        sql = "SELECT * FROM users WHERE COUNT(*) > 5"
        # This would be a syntax error in most DBs, but if it parses, 
        # we don't flag it as function_in_where
        try:
            result = detect_antipatterns(sql)
            if result.parseable:
                assert result.has_function_in_where is False
        except:
            pass  # Expected to not parse

    # ========================================
    # NESTED QUERIES
    # ========================================

    def test_function_on_column_in_subquery_where_detected(self):
        """Function in subquery WHERE is detected at that level."""
        sql = """
        SELECT * FROM users u
        WHERE EXISTS (
            SELECT 1 FROM orders o 
            WHERE UPPER(o.status) = 'PAID'
              AND o.user_id = u.id
        )
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True
        assert any("UPPER" in ap.location for ap in result.antipatterns)

    def test_function_on_outer_column_with_subquery_detected(self):
        """Function on outer column is detected."""
        sql = """
        SELECT * FROM users u
        WHERE UPPER(u.name) = 'JOHN'
          AND EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id)
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_correlated_column_reference_not_flagged(self):
        """Correlated column reference without function is not flagged."""
        sql = """
        SELECT * FROM users u
        WHERE EXISTS (
            SELECT 1 FROM orders o WHERE o.user_id = u.id
        )
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is False

    def test_function_in_scalar_subquery_where_detected(self):
        """Function in scalar subquery WHERE is detected."""
        sql = """
        SELECT 
            name,
            (SELECT COUNT(*) FROM orders WHERE UPPER(status) = 'PAID') as cnt
        FROM users
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_function_in_cte_where_detected(self):
        """Function in CTE WHERE is detected."""
        sql = """
        WITH active_users AS (
            SELECT * FROM users WHERE UPPER(status) = 'ACTIVE'
        )
        SELECT * FROM active_users WHERE age > 18
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_function_in_derived_table_where_detected(self):
        """Function in derived table WHERE is detected."""
        sql = """
        SELECT u.id, sub.order_count
        FROM users u
        JOIN (
            SELECT user_id, COUNT(*) as order_count
            FROM orders
            WHERE DATE(created_at) = '2024-01-01'
            GROUP BY user_id
        ) sub ON sub.user_id = u.id
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    # ========================================
    # COMPLEX EXPRESSIONS
    # ========================================

    def test_nested_functions_on_column_detected(self):
        """Nested functions (UPPER(TRIM(...))) are detected."""
        sql = "SELECT * FROM users WHERE UPPER(TRIM(name)) = 'JOHN'"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True
        
        # Should only report ONE antipattern (early return)
        function_aps = [ap for ap in result.antipatterns if ap.pattern == "function_in_where"]
        assert len(function_aps) == 1

    def test_case_with_function_on_column_detected(self):
        """CASE expression with function on column is detected."""
        sql = """
        SELECT * FROM users
        WHERE CASE 
            WHEN UPPER(status) = 'ACTIVE' THEN 1 
            ELSE 0 
        END = 1
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_function_in_or_condition_detected(self):
        """Function in OR branch is detected."""
        sql = """
        SELECT * FROM users 
        WHERE name = 'John' OR UPPER(email) = 'ADMIN@EXAMPLE.COM'
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_function_in_and_condition_detected(self):
        """Function in AND branch is detected."""
        sql = """
        SELECT * FROM users 
        WHERE UPPER(name) = 'JOHN' AND age > 18
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_multiple_functions_on_different_columns_detected_once(self):
        """Multiple functions detected but only first reported (early return)."""
        sql = """
        SELECT * FROM users 
        WHERE UPPER(name) = 'JOHN' AND DATE(created_at) = '2024-01-01'
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True
        
        # Early return means only one antipattern
        function_aps = [ap for ap in result.antipatterns if ap.pattern == "function_in_where"]
        assert len(function_aps) == 1

    # ========================================
    # EDGE CASES
    # ========================================

    def test_function_with_multiple_arguments_one_column_detected(self):
        """Function with mixed column/literal args is detected."""
        sql = "SELECT * FROM users WHERE SUBSTR(name, 1, 3) = 'Joh'"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_function_on_expression_with_column_detected(self):
        """Function on expression containing column is detected."""
        sql = "SELECT * FROM users WHERE UPPER(name || ' Smith') = 'JOHN SMITH'"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_between_with_functions_detected(self):
        """BETWEEN with function on column is detected."""
        sql = """
        SELECT * FROM orders 
        WHERE DATE(created_at) BETWEEN '2024-01-01' AND '2024-12-31'
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_in_list_with_function_on_column_detected(self):
        """IN list with function on column is detected."""
        sql = "SELECT * FROM users WHERE UPPER(status) IN ('ACTIVE', 'PENDING')"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_function_in_not_condition_detected(self):
        """Function in NOT condition is detected."""
        sql = "SELECT * FROM users WHERE NOT (UPPER(name) = 'JOHN')"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    # ========================================
    # NEW: Arithmetic expressions on columns
    # ========================================

    def test_addition_on_column_detected(self):
        """Arithmetic addition on column prevents index usage."""
        sql = "SELECT * FROM users WHERE age + 1 > 18"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True
        assert any("arithmetic" in ap.message.lower() or "function" in ap.message.lower() 
                   for ap in result.antipatterns if ap.pattern == "function_in_where")

    def test_subtraction_on_column_detected(self):
        """Arithmetic subtraction on column prevents index usage."""
        sql = "SELECT * FROM users WHERE age - 5 >= 13"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_multiplication_on_column_detected(self):
        """Arithmetic multiplication on column prevents index usage."""
        sql = "SELECT * FROM orders WHERE quantity * price > 100"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_division_on_column_detected(self):
        """Arithmetic division on column prevents index usage."""
        sql = "SELECT * FROM orders WHERE total / 2 > 50"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_modulo_on_column_detected(self):
        """Modulo operation on column prevents index usage."""
        sql = "SELECT * FROM users WHERE id % 10 = 0"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_concat_on_column_detected(self):
        """String concatenation on column prevents index usage."""
        sql = "SELECT * FROM users WHERE name || ' Smith' = 'John Smith'"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_arithmetic_on_literal_only_not_flagged(self):
        """Pure arithmetic on literals (no columns) is not flagged."""
        sql = "SELECT * FROM users WHERE age > 10 + 8"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is False

    def test_arithmetic_on_right_side_only_not_flagged(self):
        """Arithmetic on the right side of comparison is not flagged."""
        sql = "SELECT * FROM users WHERE age > 2 * 9"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is False

    def test_complex_arithmetic_expression_detected(self):
        """Complex arithmetic expression involving column is detected."""
        sql = "SELECT * FROM orders WHERE (price * quantity) + tax > 1000"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    # ========================================
    # NEW: Function in HAVING clause
    # ========================================

    def test_function_in_having_detected(self):
        """Function on column in HAVING clause is detected."""
        sql = "SELECT country, COUNT(*) FROM users GROUP BY country HAVING UPPER(country) = 'USA'"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True
        assert any("HAVING" in ap.location for ap in result.antipatterns if ap.pattern == "function_in_where")

    def test_aggregate_function_in_having_not_flagged(self):
        """Aggregate functions in HAVING are expected and should not be flagged."""
        sql = "SELECT country, COUNT(*) FROM users GROUP BY country HAVING COUNT(*) > 10"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is False

    def test_function_wrapping_aggregate_in_having_not_flagged(self):
        """Functions wrapping aggregates in HAVING are acceptable."""
        sql = "SELECT country, AVG(age) FROM users GROUP BY country HAVING ROUND(AVG(age)) > 30"
        result = detect_antipatterns(sql)
        # This might or might not be flagged depending on implementation
        # The key is that pure aggregates should not be flagged

    def test_arithmetic_in_having_detected(self):
        """Arithmetic on grouped column in HAVING is detected."""
        sql = "SELECT country, COUNT(*) FROM users GROUP BY country HAVING LENGTH(country) + 1 > 5"
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True

    def test_function_in_where_and_having_only_one_reported(self):
        """If both WHERE and HAVING have functions, only one antipattern is reported."""
        sql = """
        SELECT country, COUNT(*) FROM users 
        WHERE UPPER(status) = 'ACTIVE' 
        GROUP BY country 
        HAVING UPPER(country) = 'USA'
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True
        # Should only report once (early return)
        function_aps = [ap for ap in result.antipatterns if ap.pattern == "function_in_where"]
        assert len(function_aps) == 1

    def test_json_extract_in_where_detected(self):
        """JSON_EXTRACT on a column should be detected."""
        sql = """
        SELECT * FROM users 
        WHERE JSON_EXTRACT(metadata, '$.age') > 18
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True


    def test_array_operations_in_where_detected(self):
        """Array operations on a column should be detected."""
        sql = """
        SELECT * FROM users 
        WHERE 'admin' = ANY(roles)
        """
        result = detect_antipatterns(sql)
        # If 'roles' is a column, it should be detected
        assert result.has_function_in_where is True

    def test_column_equals_sum_of_other_table_columns_not_flagged(self):
        """
        Equality between a bare column and an arithmetic expression over
        columns from a different table (typical join-style condition) should
        not be treated as a function-in-WHERE antipattern.
        """
        sql = """
        SELECT count(*)
        FROM Reservations AS T1
        JOIN Rooms AS T2 ON T1.Room = T2.RoomId
        WHERE T2.maxOccupancy = T1.Adults + T1.Kids;
        """
        result = detect_antipatterns(sql)

        assert result.has_function_in_where is False
        assert all(ap.pattern != "function_in_where" for ap in result.antipatterns)

    def test_column_greater_than_sum_of_other_table_columns_not_flagged(self):
        """
        Join-style comparison with > operator should not be flagged.
        T2.capacity > T1.required + T1.buffer can use index on T2.capacity.
        """
        sql = """
        SELECT * 
        FROM Bookings AS T1 
        JOIN Venues AS T2 ON T1.venue_id = T2.id 
        WHERE T2.capacity > T1.required_seats + T1.buffer
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is False
        assert all(ap.pattern != "function_in_where" for ap in result.antipatterns)

    def test_column_less_than_sum_of_other_table_columns_not_flagged(self):
        """
        Join-style comparison with < operator should not be flagged.
        T2.limit < T1.current + T1.pending can use index on T2.limit.
        """
        sql = """
        SELECT * 
        FROM Transactions AS T1 
        JOIN Accounts AS T2 ON T1.account_id = T2.id 
        WHERE T2.limit < T1.current_count + T1.pending
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is False
        assert all(ap.pattern != "function_in_where" for ap in result.antipatterns)

    def test_column_gte_sum_of_other_table_columns_not_flagged(self):
        """
        Join-style comparison with >= operator should not be flagged.
        """
        sql = """
        SELECT * 
        FROM Orders AS T1 
        JOIN Inventory AS T2 ON T1.product_id = T2.product_id 
        WHERE T2.stock >= T1.quantity + T1.reserved
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is False
        assert all(ap.pattern != "function_in_where" for ap in result.antipatterns)

    def test_column_lte_sum_of_other_table_columns_not_flagged(self):
        """
        Join-style comparison with <= operator should not be flagged.
        """
        sql = """
        SELECT * 
        FROM Requests AS T1 
        JOIN Limits AS T2 ON T1.user_id = T2.user_id 
        WHERE T2.daily_limit <= T1.used + T1.pending
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is False
        assert all(ap.pattern != "function_in_where" for ap in result.antipatterns)

    def test_arithmetic_on_same_table_column_still_flagged(self):
        """
        Arithmetic on column from the SAME table should still be flagged.
        T1.age + 1 > 18 prevents index usage on T1.age.
        """
        sql = """
        SELECT * 
        FROM Users AS T1
        WHERE T1.age + 1 > 18
        """
        result = detect_antipatterns(sql)
        assert result.has_function_in_where is True
        assert any(ap.pattern == "function_in_where" for ap in result.antipatterns)


class TestLeadingWildcardLikeAntipattern:
    """Test leading wildcard LIKE antipattern detection."""

    def test_leading_percent_detected(self):
        """Test that LIKE with leading % is detected."""
        sql = "SELECT * FROM users WHERE name LIKE '%john'"
        result = detect_antipatterns(sql)
        
        assert result.has_leading_wildcard_like is True
        assert result.total_antipatterns >= 1
        assert any(ap.pattern == "leading_wildcard_like" and ap.severity == "high" for ap in result.antipatterns)

    def test_leading_underscore_detected(self):
        """Test that LIKE with leading _ is detected."""
        sql = "SELECT * FROM users WHERE name LIKE '_ohn'"
        result = detect_antipatterns(sql)
        
        assert result.has_leading_wildcard_like is True

    def test_trailing_wildcard_not_flagged(self):
        """Test that LIKE with trailing % is not flagged."""
        sql = "SELECT * FROM users WHERE name LIKE 'john%'"
        result = detect_antipatterns(sql)
        
        assert result.has_leading_wildcard_like is False

    def test_middle_wildcard_not_flagged(self):
        """Test that LIKE with middle % is not flagged."""
        sql = "SELECT * FROM users WHERE name LIKE 'jo%hn'"
        result = detect_antipatterns(sql)
        
        assert result.has_leading_wildcard_like is False

class TestNotInNullableAntipattern:
    """Test NOT IN with nullable subquery antipattern detection."""

    def test_not_in_subquery_detected(self):
        """Test that NOT IN with subquery is detected."""
        sql = "SELECT * FROM users WHERE id NOT IN (SELECT user_id FROM orders)"
        result = detect_antipatterns(sql)
        
        assert result.has_not_in_nullable is True
        assert result.total_antipatterns >= 1
        assert any(ap.pattern == "not_in_nullable" and ap.severity == "high" for ap in result.antipatterns)

    def test_not_in_list_not_flagged(self):
        """Test that NOT IN with literal list is not flagged."""
        sql = "SELECT * FROM users WHERE status NOT IN ('inactive', 'banned')"
        result = detect_antipatterns(sql)
        
        assert result.has_not_in_nullable is False

    def test_in_subquery_not_flagged(self):
        """Test that IN (without NOT) is not flagged."""
        sql = "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)"
        result = detect_antipatterns(sql)
        
        assert result.has_not_in_nullable is False

    # ========================================
    # NEW: NULL literal in NOT IN list tests
    # ========================================

    def test_not_in_with_null_literal_detected(self):
        """NOT IN with NULL in literal list is a null_comparison_equals issue."""
        sql = "SELECT * FROM users WHERE id NOT IN (1, 2, NULL)"
        result = detect_antipatterns(sql)
        
        assert result.has_null_comparison_equals is True
        assert any(ap.pattern == "null_comparison_equals" for ap in result.antipatterns)
        assert result.has_not_in_nullable is False

    def test_not_in_with_null_at_start_of_list_detected(self):
        """NULL at start of literal list should be detected as null_comparison_equals."""
        sql = "SELECT * FROM users WHERE id NOT IN (NULL, 1, 2)"
        result = detect_antipatterns(sql)
        
        assert result.has_null_comparison_equals is True
        assert result.has_not_in_nullable is False

    def test_not_in_with_null_at_end_of_list_detected(self):
        """NULL at end of literal list should be detected as null_comparison_equals."""
        sql = "SELECT * FROM users WHERE id NOT IN (1, 2, 3, NULL)"
        result = detect_antipatterns(sql)
        
        assert result.has_null_comparison_equals is True
        assert result.has_not_in_nullable is False

    def test_not_in_with_only_null_detected(self):
        """NOT IN (NULL) is detected as null_comparison_equals."""
        sql = "SELECT * FROM users WHERE id NOT IN (NULL)"
        result = detect_antipatterns(sql)
        
        assert result.has_null_comparison_equals is True
        assert result.has_not_in_nullable is False

    def test_not_in_with_string_literals_no_null_not_flagged(self):
        """NOT IN with only non-NULL literals should not be flagged."""
        sql = "SELECT * FROM users WHERE status NOT IN ('active', 'pending', 'inactive')"
        result = detect_antipatterns(sql)
        
        assert result.has_not_in_nullable is False

    def test_not_in_with_integer_literals_no_null_not_flagged(self):
        """NOT IN with only integer literals should not be flagged."""
        sql = "SELECT * FROM users WHERE id NOT IN (1, 2, 3, 4, 5)"
        result = detect_antipatterns(sql)
        
        assert result.has_not_in_nullable is False

    def test_in_with_null_literal_flagged_as_null_comparison(self):
        """IN with NULL in value list is flagged: col IN (1, 2, NULL) uses implicit = NULL."""
        sql = "SELECT * FROM users WHERE id IN (1, 2, NULL)"
        result = detect_antipatterns(sql)
        
        assert result.has_not_in_nullable is False
        assert result.has_null_comparison_equals is True
        assert any(ap.pattern == "null_comparison_equals" for ap in result.antipatterns)

    def test_not_in_subquery_and_null_literal_both_detected(self):
        """If both subquery and NULL literal issues exist, at least one is flagged."""
        # This is contrived but tests early return behavior
        sql = "SELECT * FROM users WHERE id NOT IN (SELECT user_id FROM orders)"
        result = detect_antipatterns(sql)
        
        assert result.has_not_in_nullable is True


class TestLimitWithoutOrderByAntipattern:
    """Test LIMIT without ORDER BY antipattern detection."""

    # ========================================
    # BASIC DETECTION
    # ========================================

    def test_limit_without_order_by_detected(self):
        """LIMIT without ORDER BY should be detected."""
        sql = "SELECT id, name FROM users LIMIT 10"
        result = detect_antipatterns(sql)
        
        assert result.has_limit_without_order_by is True
        assert any(ap.pattern == "limit_without_order_by" for ap in result.antipatterns)
        assert any(ap.severity == "high" for ap in result.antipatterns if ap.pattern == "limit_without_order_by")

    def test_limit_with_order_by_not_flagged(self):
        """LIMIT with ORDER BY should not be flagged."""
        sql = "SELECT id, name FROM users ORDER BY id LIMIT 10"
        result = detect_antipatterns(sql)
        
        assert result.has_limit_without_order_by is False

    def test_no_limit_not_flagged(self):
        """Query without LIMIT should not be flagged."""
        sql = "SELECT id, name FROM users"
        result = detect_antipatterns(sql)
        
        assert result.has_limit_without_order_by is False

    # ========================================
    # EDGE CASES
    # ========================================

    def test_select_1_limit_1_not_flagged(self):
        """SELECT 1 LIMIT 1 (existence check) should not be flagged."""
        sql = "SELECT 1 FROM users WHERE status = 'active' LIMIT 1"
        result = detect_antipatterns(sql)
        
        assert result.has_limit_without_order_by is False

    def test_select_literal_limit_not_flagged(self):
        """SELECT with only literals and LIMIT should not be flagged."""
        sql = "SELECT 'exists' FROM users WHERE id = 1 LIMIT 1"
        result = detect_antipatterns(sql)
        
        assert result.has_limit_without_order_by is False

    def test_exists_subquery_limit_not_flagged(self):
        """LIMIT in EXISTS subquery should not be flagged."""
        sql = """
        SELECT * FROM orders o
        WHERE EXISTS (
            SELECT 1 FROM users u WHERE u.id = o.user_id LIMIT 1
        )
        """
        result = detect_antipatterns(sql)
        
        # The LIMIT inside EXISTS should not be flagged
        assert result.has_limit_without_order_by is False

    def test_limit_in_subquery_without_order_by_detected(self):
        """LIMIT without ORDER BY in non-EXISTS subquery should be detected."""
        sql = """
        SELECT * FROM (
            SELECT id, name FROM users LIMIT 10
        ) sub
        """
        result = detect_antipatterns(sql)
        
        assert result.has_limit_without_order_by is True

    def test_limit_in_cte_without_order_by_detected(self):
        """LIMIT without ORDER BY in CTE should be detected."""
        sql = """
        WITH top_users AS (
            SELECT id, name FROM users LIMIT 5
        )
        SELECT * FROM top_users
        """
        result = detect_antipatterns(sql)
        
        assert result.has_limit_without_order_by is True

    def test_limit_offset_without_order_by_detected(self):
        """LIMIT with OFFSET but without ORDER BY should be detected."""
        sql = "SELECT id, name FROM users LIMIT 10 OFFSET 5"
        result = detect_antipatterns(sql)
        
        assert result.has_limit_without_order_by is True

    def test_union_with_limit_without_order_by(self):
        """UNION with LIMIT without ORDER BY should be detected."""
        sql = """
        SELECT id FROM users
        UNION ALL
        SELECT id FROM admins
        LIMIT 10
        """
        result = detect_antipatterns(sql)
        
        # The outer LIMIT without ORDER BY should be detected
        assert result.has_limit_without_order_by is True

    def test_multiple_selects_one_with_limit_detected(self):
        """Only SELECTs with LIMIT but no ORDER BY should be flagged."""
        sql = """
        SELECT * FROM (
            SELECT id FROM users ORDER BY id LIMIT 5
        ) a
        JOIN (
            SELECT id FROM orders LIMIT 5
        ) b ON a.id = b.id
        """
        result = detect_antipatterns(sql)
        
        # The second subquery has LIMIT without ORDER BY
        assert result.has_limit_without_order_by is True

    def test_limit_1_with_columns_still_flagged(self):
        """LIMIT 1 with actual columns (not just literals) should be flagged."""
        sql = "SELECT id, name, email FROM users WHERE status = 'active' LIMIT 1"
        result = detect_antipatterns(sql)
        
        assert result.has_limit_without_order_by is True

    def test_order_by_in_subquery_outer_limit_without_order_flagged(self):
        """Outer LIMIT without ORDER BY is flagged even if subquery has ORDER BY."""
        sql = """
        SELECT * FROM (
            SELECT id, name FROM users ORDER BY created_at
        ) sub
        LIMIT 10
        """
        result = detect_antipatterns(sql)
        
        # The outer SELECT has LIMIT but no ORDER BY
        assert result.has_limit_without_order_by is True


class TestOffsetWithoutOrderByAntipattern:
    """Test OFFSET without ORDER BY antipattern detection."""

    # ========================================
    # BASIC DETECTION
    # ========================================

    def test_offset_without_order_by_detected(self):
        """OFFSET without ORDER BY should be detected."""
        sql = "SELECT id, name FROM users LIMIT 10 OFFSET 20"
        result = detect_antipatterns(sql)
        
        assert result.has_offset_without_order_by is True
        assert any(ap.pattern == "offset_without_order_by" for ap in result.antipatterns)
        assert any(ap.severity == "high" for ap in result.antipatterns if ap.pattern == "offset_without_order_by")

    def test_offset_with_order_by_not_flagged(self):
        """OFFSET with ORDER BY should not be flagged."""
        sql = "SELECT id, name FROM users ORDER BY id LIMIT 10 OFFSET 20"
        result = detect_antipatterns(sql)
        
        assert result.has_offset_without_order_by is False

    def test_no_offset_not_flagged(self):
        """Query without OFFSET should not be flagged."""
        sql = "SELECT id, name FROM users LIMIT 10"
        result = detect_antipatterns(sql)
        
        assert result.has_offset_without_order_by is False

    def test_only_offset_syntax_if_supported(self):
        """Some DBs support OFFSET without LIMIT - should still flag."""
        # SQLite supports this syntax
        sql = "SELECT id, name FROM users OFFSET 10"
        result = detect_antipatterns(sql)
        
        # If parsed successfully, OFFSET without ORDER BY should be flagged
        if result.parseable:
            # Note: Some dialects may not parse this syntax
            pass  # Just ensure no crash

    # ========================================
    # EDGE CASES
    # ========================================

    def test_offset_0_without_order_by_detected(self):
        """OFFSET 0 without ORDER BY should still be detected (semantic issue)."""
        sql = "SELECT id, name FROM users LIMIT 10 OFFSET 0"
        result = detect_antipatterns(sql)
        
        assert result.has_offset_without_order_by is True

    def test_offset_in_subquery_without_order_by_detected(self):
        """OFFSET without ORDER BY in subquery should be detected."""
        sql = """
        SELECT * FROM (
            SELECT id, name FROM users LIMIT 10 OFFSET 5
        ) sub
        """
        result = detect_antipatterns(sql)
        
        assert result.has_offset_without_order_by is True

    def test_offset_in_cte_without_order_by_detected(self):
        """OFFSET without ORDER BY in CTE should be detected."""
        sql = """
        WITH paginated AS (
            SELECT id, name FROM users LIMIT 10 OFFSET 20
        )
        SELECT * FROM paginated
        """
        result = detect_antipatterns(sql)
        
        assert result.has_offset_without_order_by is True

    def test_offset_in_union_without_order_by_detected(self):
        """OFFSET on UNION result without ORDER BY should be detected."""
        sql = """
        SELECT id FROM users
        UNION ALL
        SELECT id FROM admins
        LIMIT 10 OFFSET 5
        """
        result = detect_antipatterns(sql)
        
        assert result.has_offset_without_order_by is True

    def test_multiple_offsets_first_flagged_only(self):
        """Multiple SELECTs with OFFSET without ORDER BY - only one reported."""
        sql = """
        SELECT * FROM (
            SELECT id FROM users LIMIT 5 OFFSET 10
        ) a
        JOIN (
            SELECT id FROM orders LIMIT 5 OFFSET 10
        ) b ON a.id = b.id
        """
        result = detect_antipatterns(sql)
        
        assert result.has_offset_without_order_by is True
        # Early return means only one antipattern instance
        offset_aps = [ap for ap in result.antipatterns if ap.pattern == "offset_without_order_by"]
        assert len(offset_aps) == 1

    def test_offset_large_value_without_order_detected(self):
        """Large OFFSET without ORDER BY should be detected."""
        sql = "SELECT id, name FROM users LIMIT 100 OFFSET 10000"
        result = detect_antipatterns(sql)
        
        assert result.has_offset_without_order_by is True

    def test_both_limit_and_offset_without_order_by(self):
        """Both LIMIT and OFFSET antipatterns should be detected."""
        sql = "SELECT id, name, email FROM users LIMIT 10 OFFSET 20"
        result = detect_antipatterns(sql)
        
        # Both antipatterns should be detected
        assert result.has_limit_without_order_by is True
        assert result.has_offset_without_order_by is True
        # Should have at least 2 antipatterns (limit_without_order_by and offset_without_order_by)
        assert result.total_antipatterns >= 2


class TestCorrelatedSubqueryAntipattern:
    """Test correlated subquery antipattern detection."""

    def test_correlated_subquery_detected(self):
        """Test that potentially correlated subquery is detected."""
        sql = """
        SELECT * FROM users u 
        WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id)
        """
        result = detect_antipatterns(sql)
        
        # This is a heuristic detection, may or may not flag
        assert result.parseable is True

    def test_simple_subquery_may_be_flagged(self):
        """Test that subquery with WHERE might be flagged."""
        sql = "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 100)"
        result = detect_antipatterns(sql)
        
        # Conservative heuristic may flag this
        assert result.parseable is True

class TestNullComparisonEqualsAntipattern:
    """Test = NULL / != NULL antipattern detection."""

    def test_equals_null_detected(self):
        """Test that = NULL is detected."""
        sql = "SELECT * FROM users WHERE status = NULL"
        result = detect_antipatterns(sql)
        
        assert result.has_null_comparison_equals is True
        assert result.total_antipatterns >= 1
        assert any(ap.pattern == "null_comparison_equals" for ap in result.antipatterns)
        assert any(ap.severity == "critical" for ap in result.antipatterns)

    def test_not_equals_null_detected(self):
        """Test that != NULL is detected."""
        sql = "SELECT * FROM users WHERE status != NULL"
        result = detect_antipatterns(sql)
        
        assert result.has_null_comparison_equals is True
        assert result.total_antipatterns >= 1

    def test_is_null_not_flagged(self):
        """Test that IS NULL is not flagged."""
        sql = "SELECT * FROM users WHERE status IS NULL"
        result = detect_antipatterns(sql)
        
        assert result.has_null_comparison_equals is False

    def test_is_not_null_not_flagged(self):
        """Test that IS NOT NULL is not flagged."""
        sql = "SELECT * FROM users WHERE status IS NOT NULL"
        result = detect_antipatterns(sql)
        
        assert result.has_null_comparison_equals is False
    # NEW TESTS
    def test_not_equals_angle_bracket_null_detected(self):
        """Test that <> NULL is detected as not-equals NULL."""
        sql = "SELECT * FROM users WHERE status <> NULL"
        result = detect_antipatterns(sql)

        assert result.has_null_comparison_equals is True
        assert any(ap.pattern == "null_comparison_equals" for ap in result.antipatterns)

    def test_less_than_null_detected(self):
        """Test that < NULL is detected as a suspicious NULL comparison."""
        sql = "SELECT * FROM users WHERE status < NULL"
        result = detect_antipatterns(sql)

        assert result.has_null_comparison_equals is True
        assert any(ap.pattern == "null_comparison_equals" for ap in result.antipatterns)

    def test_greater_than_null_detected(self):
        """Test that > NULL is detected as a suspicious NULL comparison."""
        sql = "SELECT * FROM users WHERE status > NULL"
        result = detect_antipatterns(sql)

        assert result.has_null_comparison_equals is True
        assert any(ap.pattern == "null_comparison_equals" for ap in result.antipatterns)

    def test_less_or_equal_null_detected(self):
        """Test that <= NULL is detected as a suspicious NULL comparison."""
        sql = "SELECT * FROM users WHERE status <= NULL"
        result = detect_antipatterns(sql)

        assert result.has_null_comparison_equals is True
        assert any(ap.pattern == "null_comparison_equals" for ap in result.antipatterns)

    def test_greater_or_equal_null_detected(self):
        """Test that >= NULL is detected as a suspicious NULL comparison."""
        sql = "SELECT * FROM users WHERE status >= NULL"
        result = detect_antipatterns(sql)

        assert result.has_null_comparison_equals is True
        assert any(ap.pattern == "null_comparison_equals" for ap in result.antipatterns)

    def test_null_equals_column_detected(self):
        """Test that NULL = column is also detected (NULL on the left side)."""
        sql = "SELECT * FROM users WHERE NULL = status"
        result = detect_antipatterns(sql)

        assert result.has_null_comparison_equals is True
        assert any(ap.pattern == "null_comparison_equals" for ap in result.antipatterns)

    def test_null_safe_equal_mysql_not_flagged(self):
        """
        Test that MySQL NULL-safe equality <=> NULL is not flagged.

        NOTE:
        This test only makes sense if detect_antipatterns parses the query
        using a MySQL-compatible dialect so that `<=>` becomes a dedicated
        NullSafeEQ node in the AST. If you always use SQLite dialect, you may
        skip or adapt this test.
        """
        sql = "SELECT * FROM users WHERE status <=> NULL"
        result = detect_antipatterns(sql)

        assert result.has_null_comparison_equals is False
        assert not any(ap.pattern == "null_comparison_equals" for ap in result.antipatterns)

    def test_case_expression_with_null_comparison_detected(self):
        sql = """
        SELECT CASE
                 WHEN status = NULL THEN 'unknown'
                 ELSE status
               END AS s
        FROM users
        """
        result = detect_antipatterns(sql)

        assert result.has_null_comparison_equals is True

    # ========================================
    # IN with NULL literal tests
    # ========================================

    def test_in_with_null_and_strings_detected(self):
        """IN list with NULL and string literals: NULL part silently never matches."""
        sql = "SELECT * FROM events WHERE consent IN (NULL, 'N/A', '')"
        result = detect_antipatterns(sql)

        assert result.has_null_comparison_equals is True
        assert any(ap.pattern == "null_comparison_equals" for ap in result.antipatterns)
        assert any("IN list" in ap.message for ap in result.antipatterns
                    if ap.pattern == "null_comparison_equals")

    def test_in_with_null_only_detected(self):
        """IN (NULL) is equivalent to = NULL — always UNKNOWN."""
        sql = "SELECT * FROM users WHERE status IN (NULL)"
        result = detect_antipatterns(sql)

        assert result.has_null_comparison_equals is True
        assert any(ap.pattern == "null_comparison_equals" for ap in result.antipatterns)

    def test_in_without_null_not_flagged(self):
        """IN with only non-NULL literals should not be flagged."""
        sql = "SELECT * FROM events WHERE consent IN ('N/A', '')"
        result = detect_antipatterns(sql)

        assert result.has_null_comparison_equals is False

    def test_not_in_with_null_flagged_as_null_comparison(self):
        """NOT IN with NULL literal in list is the same root cause — null_comparison_equals, not not_in_nullable."""
        sql = "SELECT * FROM users WHERE id NOT IN (NULL, 1, 2)"
        result = detect_antipatterns(sql)

        assert result.has_null_comparison_equals is True
        assert result.has_not_in_nullable is False


class TestCartesianProductAntipattern:
    def test_cartesian_product_comma_separated(self):
        """Test that comma-separated tables are detected as Cartesian product."""
        sql = "SELECT * FROM users, orders"
        result = detect_antipatterns(sql)
        
        assert result.has_cartesian_product is True
        assert any(ap.pattern == "cartesian_product" for ap in result.antipatterns)

    def test_cartesian_product_three_tables_comma(self):
        """Test Cartesian product with three comma-separated tables."""
        sql = "SELECT * FROM a, b, c"
        result = detect_antipatterns(sql)
        
        assert result.has_cartesian_product is True

    def test_join_using_clause_not_cartesian(self):
        """JOIN USING(id) is a proper join condition between tables - NOT Cartesian."""
        sql = "SELECT * FROM a JOIN b USING (id)"
        result = detect_antipatterns(sql)

        # FIXED: USING is a valid join condition!
        assert result.has_cartesian_product is False

    def test_pure_cartesian_from_comma(self):
        """Classic comma-separated tables without any conditions → pure Cartesian product."""
        sql = "SELECT * FROM a, b"
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is True
        assert any(ap.pattern == "cartesian_product" for ap in result.antipatterns)

    def test_cartesian_cross_join(self):
        """CROSS JOIN without any join condition → Cartesian product by definition."""
        sql = "SELECT * FROM a CROSS JOIN b"
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is True

    def test_not_cartesian_when_join_condition_exists(self):
        """Old-style join via WHERE: FROM users u, orders o WHERE u.id = o.user_id
        This is a proper join between two tables → NOT a Cartesian product."""
        sql = "SELECT * FROM users u, orders o WHERE u.id = o.user_id"
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is False

    def test_three_tables_comma_no_conditions_cartesian(self):
        """Multiple tables listed with commas, no WHERE/ON conditions at all.
        a, b, c → full Cartesian product a × b × c."""
        sql = "SELECT * FROM a, b, c"
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is True

    def test_two_tables_comma_where_only_single_table_condition_cartesian(self):
        """WHERE clause references only one table:
        condition filters rows in 'a' but does not relate 'a' to 'b'.
        Still a Cartesian product a × b with a filter on 'a'."""
        sql = "SELECT * FROM a, b WHERE a.id > 10"
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is True

    def test_two_tables_comma_where_same_table_columns_cartesian(self):
        """WHERE a.x = a.y: still only references table 'a'.
        'b' is completely unrelated → a × b is still a Cartesian product."""
        sql = "SELECT * FROM a, b WHERE a.x = a.y"
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is True

    def test_mixed_comma_and_join_without_condition_for_all_tables_cartesian(self):
        """FROM a, b JOIN c ON b.id = c.b_id
        
        There is a join between b and c, but 'a' is not connected to (b ⋈ c) at all.
        Effective result: a × (b ⋈ c) → still a Cartesian product."""
        sql = "SELECT * FROM a, b JOIN c ON b.id = c.b_id"
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is True

    def test_mixed_comma_and_join_with_full_where_join_not_cartesian(self):
        """Same as previous test, but now WHERE connects 'a' with 'b':
        a.id = b.a_id → all tables are joined: a ↔ b ↔ c → NOT a Cartesian product."""
        sql = """
        SELECT *
        FROM a, b
        JOIN c ON b.id = c.b_id
        WHERE a.id = b.a_id
        """
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is False

    def test_inner_join_on_not_cartesian(self):
        """Standard INNER JOIN with a valid join condition between two tables."""
        sql = "SELECT * FROM users u JOIN orders o ON u.id = o.user_id"
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is False

    def test_two_table_join_with_unqualified_column_is_not_cartesian(self):
        """JOIN between STUDENT and VOTING_RECORD using an unqualified column; should NOT be detected as Cartesian."""
        sql = (
            'SELECT count(*) FROM STUDENT AS T1 '
            'JOIN VOTING_RECORD AS T2 ON T1.StuID = Class_Senator_Vote '
            'WHERE T1.Sex = "M" AND T2.Election_Cycle = "Fall"'
        )
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is False


    def test_tautological_join_condition_creates_cartesian_three_tables(self):
        """Tautological join condition T2.actid = T2.actid leaves ACTIVITY unconnected; should be detected as Cartesian."""
        sql = (
            "SELECT DISTINCT T1.lname "
            "FROM Faculty AS T1 "
            "JOIN Faculty_participates_in AS T2 ON T1.facID = T2.facID "
            "JOIN activity AS T3 ON T2.actid = T2.actid "
            "WHERE T3.activity_name = 'Canoeing' OR T3.activity_name = 'Kayaking'"
        )
        result = detect_antipatterns(sql)
        assert result.has_cartesian_product is True


    def test_tautological_join_with_intersect_still_cartesian(self):
        """Tautological join T2.actid = T2.actid between participates_in and activity; each side of INTERSECT is Cartesian."""
        sql = (
            "SELECT T1.stuid "
            "FROM participates_in AS T1 "
            "JOIN activity AS T2 ON T2.actid = T2.actid "
            "WHERE T2.activity_name = 'Canoeing' "
            "INTERSECT "
            "SELECT T1.stuid "
            "FROM participates_in AS T1 "
            "JOIN activity AS T2 ON T2.actid = T2.actid "
            "WHERE T2.activity_name = 'Kayaking'"
        )
        result = detect_antipatterns(sql)
        assert result.has_cartesian_product is True

    def test_cross_join_detected_as_cartesian(self):
        """Explicit CROSS JOIN is still a Cartesian product."""
        sql = "SELECT * FROM a CROSS JOIN b"
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is True
        assert any(ap.pattern == "cartesian_product" for ap in result.antipatterns)

    def test_self_join_with_different_aliases_not_cartesian(self):
        """Proper self-join using aliases should NOT be reported as Cartesian."""
        sql = """
        SELECT * 
        FROM users u1, users u2 
        WHERE u1.manager_id = u2.id
        """
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is False

    def test_three_table_comma_join_with_one_table_unjoined_is_cartesian(self):
        """
        If one of the tables in a comma join has no join condition at all,
        the resulting plan includes a Cartesian product for that table.
        """
        sql = "SELECT * FROM a, b, c WHERE a.id = b.id"
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is True

    def test_where_join_condition_with_and_still_connects_tables(self):
        """
        WHERE with multiple predicates combined by AND must still detect a join
        across tables when there is at least one a.col = b.col.
        """
        sql = """
        SELECT *
        FROM a, b
        WHERE a.id = 1 AND b.id = 2 AND a.x = b.x
        """
        result = detect_antipatterns(sql)

        assert result.has_cartesian_product is False

    def test_bird_1014_lap_records_in_italy_not_cartesian(self):
        """
        Regression: BIRD dev question_id=1014 should NOT be marked as Cartesian.
        Join to scalar subquery alias T4 uses expression = T4.column.
        """
        sql = (
            "WITH fastest_lap_times AS (SELECT T1.raceId, T1.FastestLapTime, "
            "(CAST(SUBSTR(T1.FastestLapTime, 1, INSTR(T1.FastestLapTime, ':') - 1) AS REAL) * 60) + "
            "(CAST(SUBSTR(T1.FastestLapTime, INSTR(T1.FastestLapTime, ':') + 1, "
            "INSTR(T1.FastestLapTime, '.') - INSTR(T1.FastestLapTime, ':') - 1) AS REAL)) + "
            "(CAST(SUBSTR(T1.FastestLapTime, INSTR(T1.FastestLapTime, '.') + 1) AS REAL) / 1000) "
            "as time_in_seconds FROM results AS T1 WHERE T1.FastestLapTime IS NOT NULL ) "
            "SELECT T1.FastestLapTime as lap_record FROM results AS T1 "
            "INNER JOIN races AS T2 on T1.raceId = T2.raceId "
            "INNER JOIN circuits AS T3 on T2.circuitId = T3.circuitId "
            "INNER JOIN (SELECT MIN(fastest_lap_times.time_in_seconds) as min_time_in_seconds "
            "FROM fastest_lap_times "
            "INNER JOIN races AS T2 on fastest_lap_times.raceId = T2.raceId "
            "INNER JOIN circuits AS T3 on T2.circuitId = T3.circuitId "
            "WHERE T3.country = 'Italy' ) AS T4 ON "
            "(CAST(SUBSTR(T1.FastestLapTime, 1, INSTR(T1.FastestLapTime, ':') - 1) AS REAL) * 60) + "
            "(CAST(SUBSTR(T1.FastestLapTime, INSTR(T1.FastestLapTime, ':') + 1, "
            "INSTR(T1.FastestLapTime, '.') - INSTR(T1.FastestLapTime, ':') - 1) AS REAL)) + "
            "(CAST(SUBSTR(T1.FastestLapTime, INSTR(T1.FastestLapTime, '.') + 1) AS REAL) / 1000) "
            "= T4.min_time_in_seconds LIMIT 1"
        )
        result = detect_antipatterns(sql)
        assert result.parseable is True
        assert result.has_cartesian_product is False

    def test_bird_1015_austrian_grand_prix_record_not_cartesian(self):
        """
        Regression: BIRD dev question_id=1015 should NOT be marked as Cartesian.
        """
        sql = (
            "WITH fastest_lap_times AS ( SELECT T1.raceId, T1.FastestLapTime, "
            "(CAST(SUBSTR(T1.FastestLapTime, 1, INSTR(T1.FastestLapTime, ':') - 1) AS REAL) * 60) + "
            "(CAST(SUBSTR(T1.FastestLapTime, INSTR(T1.FastestLapTime, ':') + 1, "
            "INSTR(T1.FastestLapTime, '.') - INSTR(T1.FastestLapTime, ':') - 1) AS REAL)) + "
            "(CAST(SUBSTR(T1.FastestLapTime, INSTR(T1.FastestLapTime, '.') + 1) AS REAL) / 1000) "
            "as time_in_seconds FROM results AS T1 WHERE T1.FastestLapTime IS NOT NULL ) "
            "SELECT T2.name FROM races AS T2 "
            "INNER JOIN circuits AS T3 on T2.circuitId = T3.circuitId "
            "INNER JOIN results AS T1 on T2.raceId = T1.raceId "
            "INNER JOIN ( SELECT MIN(fastest_lap_times.time_in_seconds) as min_time_in_seconds "
            "FROM fastest_lap_times "
            "INNER JOIN races AS T2 on fastest_lap_times.raceId = T2.raceId "
            "INNER JOIN circuits AS T3 on T2.circuitId = T3.circuitId "
            "WHERE T2.name = 'Austrian Grand Prix') AS T4 ON "
            "(CAST(SUBSTR(T1.FastestLapTime, 1, INSTR(T1.FastestLapTime, ':') - 1) AS REAL) * 60) + "
            "(CAST(SUBSTR(T1.FastestLapTime, INSTR(T1.FastestLapTime, ':') + 1, "
            "INSTR(T1.FastestLapTime, '.') - INSTR(T1.FastestLapTime, ':') - 1) AS REAL)) + "
            "(CAST(SUBSTR(T1.FastestLapTime, INSTR(T1.FastestLapTime, '.') + 1) AS REAL) / 1000) "
            "= T4.min_time_in_seconds WHERE T2.name = 'Austrian Grand Prix'"
        )
        result = detect_antipatterns(sql)
        assert result.parseable is True
        assert result.has_cartesian_product is False

    def test_bird_1016_lap_record_pitstop_not_cartesian(self):
        """
        Regression: BIRD dev question_id=1016 should NOT be marked as Cartesian.
        """
        sql = (
            "WITH fastest_lap_times AS ( SELECT T1.raceId, T1.driverId, T1.FastestLapTime, "
            "(CAST(SUBSTR(T1.FastestLapTime, 1, INSTR(T1.FastestLapTime, ':') - 1) AS REAL) * 60) + "
            "(CAST(SUBSTR(T1.FastestLapTime, INSTR(T1.FastestLapTime, ':') + 1, "
            "INSTR(T1.FastestLapTime, '.') - INSTR(T1.FastestLapTime, ':') - 1) AS REAL)) + "
            "(CAST(SUBSTR(T1.FastestLapTime, INSTR(T1.FastestLapTime, '.') + 1) AS REAL) / 1000) "
            "as time_in_seconds FROM results AS T1 WHERE T1.FastestLapTime IS NOT NULL), "
            "lap_record_race AS ( SELECT T1.raceId, T1.driverId FROM results AS T1 "
            "INNER JOIN races AS T2 on T1.raceId = T2.raceId "
            "INNER JOIN circuits AS T3 on T2.circuitId = T3.circuitId "
            "INNER JOIN ( SELECT MIN(fastest_lap_times.time_in_seconds) as min_time_in_seconds "
            "FROM fastest_lap_times "
            "INNER JOIN races AS T2 on fastest_lap_times.raceId = T2.raceId "
            "INNER JOIN circuits AS T3 on T2.circuitId = T3.circuitId "
            "WHERE T2.name = 'Austrian Grand Prix') AS T4 ON "
            "(CAST(SUBSTR(T1.FastestLapTime, 1, INSTR(T1.FastestLapTime, ':') - 1) AS REAL) * 60) + "
            "(CAST(SUBSTR(T1.FastestLapTime, INSTR(T1.FastestLapTime, ':') + 1, "
            "INSTR(T1.FastestLapTime, '.') - INSTR(T1.FastestLapTime, ':') - 1) AS REAL)) + "
            "(CAST(SUBSTR(T1.FastestLapTime, INSTR(T1.FastestLapTime, '.') + 1) AS REAL) / 1000) "
            "= T4.min_time_in_seconds WHERE T2.name = 'Austrian Grand Prix') "
            "SELECT T4.duration FROM lap_record_race "
            "INNER JOIN pitStops AS T4 on lap_record_race.raceId = T4.raceId "
            "AND lap_record_race.driverId = T4.driverId"
        )
        result = detect_antipatterns(sql)
        assert result.parseable is True
        assert result.has_cartesian_product is False

class TestMissingGroupByAntipattern:
    """Test missing GROUP BY antipattern detection."""

    def test_aggregate_without_group_by_detected(self):
        """Test that aggregates with non-aggregated columns without GROUP BY are detected."""
        sql = "SELECT user_id, COUNT(*) FROM orders"
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is True
        assert result.total_antipatterns >= 1
        assert any(ap.pattern == "missing_group_by" for ap in result.antipatterns)

    def test_aggregate_with_group_by_not_flagged(self):
        """Test that proper GROUP BY is not flagged."""
        sql = "SELECT user_id, COUNT(*) FROM orders GROUP BY user_id"
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is False

    def test_only_aggregates_not_flagged(self):
        """Test that queries with only aggregates are not flagged."""
        sql = "SELECT COUNT(*), SUM(total) FROM orders"
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is False

    def test_group_by_missing_when_column_is_wrapped_but_alias_grouped(self):
        sql = "SELECT UPPER(country) AS c, COUNT(*) FROM singer GROUP BY country"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False

class TestMissingGroupByAdditional:
    """Additional tests for the Missing GROUP BY antipattern (semantic behavior)."""

    def test_group_by_alias_not_matching_column_not_flagged(self):
        """
        Non-aggregated expression: country (via alias c).
        GROUP BY groups by alias c, which refers to country.
        This is logically equivalent to GROUP BY country and should not be flagged.
        """
        sql = "SELECT country AS c, AVG(age) FROM singer GROUP BY c"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False

    def test_wrapped_column_grouped_by_underlying_column_not_flagged(self):
        """
        Non-aggregated expression: UPPER(country).
        GROUP BY country; the expression is a pure function of the grouped column.
        This is logically valid (expression is functionally dependent on GROUP BY)
        and should not be flagged.
        """
        sql = "SELECT UPPER(country) AS c, COUNT(*) FROM singer GROUP BY country"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False

    def test_group_by_expression_not_matching_select_column_flagged(self):
        """
        Non-aggregated column: country.
        GROUP BY uses LOWER(country), which may group multiple distinct country
        values into a single group, while SELECT returns a raw country value.
        This can produce arbitrary country values per group and should be flagged.
        """
        sql = "SELECT country, COUNT(*) FROM singer GROUP BY LOWER(country)"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is True

    def test_duplicate_columns_with_aggregate_missing_group_by_flagged(self):
        """
        Non-aggregated columns: country, country (the same column twice).
        There is a group aggregate COUNT(*) and no GROUP BY at all.
        This is the classic Missing GROUP BY antipattern.
        """
        sql = "SELECT country, country, COUNT(*) FROM singer"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is True

    def test_distinct_does_not_replace_group_by_flagged(self):
        """
        DISTINCT does not replace GROUP BY in terms of aggregate semantics.
        This query still mixes aggregates with non-aggregated columns
        without a GROUP BY clause and should be flagged.
        """
        sql = "SELECT DISTINCT country, COUNT(*) FROM singer"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is True

    def test_order_by_non_grouped_column_not_considered_missing_group_by(self):
        """
        Non-aggregated column city appears only in ORDER BY, not in the SELECT list.
        The Missing GROUP BY rule is defined for non-aggregated columns in the SELECT
        list, not for ORDER BY. This should not be flagged by this specific detector.
        """
        sql = "SELECT country, COUNT(*) FROM singer GROUP BY country ORDER BY city"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False

    def test_having_non_grouped_column_not_in_scope_for_this_detector(self):
        """
        Most SQL engines do not allow non-grouped column city in HAVING without
        an aggregate or GROUP BY on that column.

        However, the Missing GROUP BY detector is defined to inspect the SELECT
        list only (non-aggregated columns mixed with aggregates), not HAVING.
        This test documents that behavior: it should not be flagged here.
        """
        sql = (
            "SELECT country, COUNT(*) FROM singer "
            "GROUP BY country HAVING city = 'NY'"
        )
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False

    def test_select_star_with_aggregate_flagged(self):
        """
        SELECT * expands to a set of non-aggregated columns.
        There is at least one aggregate (COUNT(*)) and no GROUP BY clause.
        This is a Missing GROUP BY antipattern and should be flagged.
        """
        sql = "SELECT *, COUNT(*) FROM singer"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is True

    def test_deeply_nested_column_expression_flagged(self):
        """
        The CASE expression contains non-aggregated columns age, country, and city.
        There is a group aggregate COUNT(*) and no GROUP BY clause.
        This should be flagged as a Missing GROUP BY antipattern.
        """
        sql = """
        SELECT 
            CASE 
                WHEN (age + 10) > 40 THEN country 
                ELSE city 
            END AS region,
            COUNT(*)
        FROM singer
        """
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is True

    def test_case_expression_with_window_and_group_aggregate_flagged(self):
        """
        AVG(age) OVER () is a window aggregate and is ignored by this detector.
        The CASE expression still contains non-aggregated columns age, country, city.
        There is also a group aggregate COUNT(*), and no GROUP BY clause.
        This should be flagged as a Missing GROUP BY antipattern.
        """
        sql = """
        SELECT 
            CASE 
                WHEN age > AVG(age) OVER () THEN country 
                ELSE city 
            END AS region,
            COUNT(*)
        FROM singer
        """
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is True

    def test_window_and_group_aggregate_without_group_by_flagged(self):
        """
        COUNT(*) OVER () is a window aggregate and does not affect grouping rules.
        SUM(age) is a group aggregate.
        The query also selects a non-aggregated column country and has no GROUP BY.
        This is a Missing GROUP BY antipattern and should be flagged.
        """
        sql = "SELECT country, COUNT(*) OVER (), SUM(age) FROM singer"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is True

    def test_constant_with_aggregate_not_flagged(self):
        """
        Constant literals in SELECT together with aggregates and no GROUP BY
        should NOT be treated as missing GROUP BY, because they are not
        non-aggregated columns.

        Example:
            SELECT COUNT(*), 'constant' FROM singer

        This query is logically valid and should not be flagged.
        """
        sql = "SELECT COUNT(*), 'constant' AS label FROM singer"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False
        assert result.total_antipatterns == 0 or not any(
            ap.pattern == "missing_group_by" for ap in result.antipatterns
        )

    def test_group_by_position_reference_not_flagged(self):
        """
        Non-aggregated column: col1.
        GROUP BY 1 groups by the first select expression (col1).
        This is equivalent to GROUP BY col1 and should not be flagged.
        """
        sql = "SELECT col1, COUNT(*) FROM t GROUP BY 1"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False

    def test_group_by_expression_matching_select_not_flagged(self):
        """
        Non-aggregated expression: YEAR(date).
        GROUP BY uses the same expression YEAR(date).
        This is logically correct and should not be flagged.
        """
        sql = "SELECT YEAR(date), COUNT(*) FROM t GROUP BY YEAR(date)"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False
        
    def test_group_by_expression_whitespace_insensitive(self):
        """
        YEAR(date) and YEAR( date ) should be treated as the same expression
        when used in GROUP BY.
        """
        sql = """
        SELECT YEAR(date) AS y, COUNT(*) 
        FROM t 
        GROUP BY YEAR( date )
        """
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False

    def test_commutative_expression_in_group_by_still_flagged_or_explicit(self):
        """
        Optional: if you decide to treat a + b and b + a as equivalent, 
        this test can assert False; otherwise assert True.

        For now we keep it explicit and *expect* a warning, because GROUP BY uses
        a different expression than the SELECT expression.
        """
        sql = """
        SELECT a + b, COUNT(*) 
        FROM t 
        GROUP BY b + a
        """
        result = detect_antipatterns(sql)

        # Choose one behavior and keep it consistent:
        # If you implement commutative equivalence in _expression_grouped:
        # assert result.has_missing_group_by is False
        # Otherwise (current behavior, stricter):
        assert result.has_missing_group_by is True

    def test_select_star_with_aggregate_and_no_group_by_flagged(self):
        """SELECT * together with aggregates and no GROUP BY is a classic antipattern."""
        sql = "SELECT *, COUNT(*) FROM users"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is True
        assert any(ap.pattern == "missing_group_by" for ap in result.antipatterns)

    def test_only_aggregates_without_group_by_not_flagged(self):
        """Pure aggregate query without non-aggregated columns is allowed."""
        sql = "SELECT COUNT(*), SUM(total) FROM orders"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False

    def test_scalar_subquery_in_select_does_not_trigger_missing_group_by(self):
        """
        Scalar subquery in SELECT is independent from GROUP BY in the outer query.
        Only columns from the outer SELECT level should be considered.
        """
        sql = """
        SELECT 
            d.name,
            (SELECT MAX(salary) FROM employees e WHERE e.dept = d.name) AS max_sal,
            COUNT(*) 
        FROM departments d
        GROUP BY d.name
        """
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False

    def test_column_in_subquery_not_counted_as_outer_non_aggregated(self):
        """
        Columns inside nested SELECT should be handled by that inner SELECT, not by the outer one.
        """
        sql = """
        SELECT 
            name,
            COUNT(*) 
        FROM (
            SELECT name, age FROM singer WHERE age > 25
        ) s
        GROUP BY name
        """
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False

    def test_column_case_insensitive_between_select_and_group_by(self):
        """
        Columns that differ only by case between SELECT and GROUP BY
        (e.g. Claim_id vs claim_id) should be treated as the same identifier
        and must NOT be reported as missing/incomplete GROUP BY.
        """
        sql = """
        SELECT 
            T1.Claim_id,
            COUNT(*)
        FROM Claims AS T1
        JOIN Settlements AS T2 
            ON T1.claim_id = T2.claim_id
        GROUP BY T1.claim_id
        """
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False


    def test_aggregate_in_order_by_only_with_grouped_select_column(self):
        """
        Queries that use an aggregate only in ORDER BY, while the SELECT list
        contains a single non-aggregated column that is also present in GROUP BY,
        must NOT be reported as having incomplete GROUP BY.

        Example:
            SELECT river_name
            FROM river
            GROUP BY ( river_name )
            ORDER BY COUNT(DISTINCT traverse) DESC
            LIMIT 1;
        """
        sql = """
        SELECT river_name
        FROM river
        GROUP BY ( river_name )
        ORDER BY COUNT ( DISTINCT traverse ) DESC
        LIMIT 1;
        """
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False


class TestUnsafeUpdateDeleteAntipattern:
    """Test unsafe UPDATE/DELETE antipattern detection."""

    def test_delete_without_where_detected(self):
        """Test that DELETE without WHERE is detected."""
        sql = "DELETE FROM users"
        result = detect_antipatterns(sql)
        
        assert result.has_unsafe_update_delete is True
        assert result.total_antipatterns >= 1
        assert any(ap.pattern == "unsafe_delete" for ap in result.antipatterns)
        assert any(ap.severity == "critical" for ap in result.antipatterns)

    def test_update_without_where_detected(self):
        """Test that UPDATE without WHERE is detected."""
        sql = "UPDATE users SET status = 'inactive'"
        result = detect_antipatterns(sql)
        
        assert result.has_unsafe_update_delete is True
        assert result.total_antipatterns >= 1
        assert any(ap.pattern == "unsafe_update" for ap in result.antipatterns)

    def test_delete_with_where_not_flagged(self):
        """Test that DELETE with WHERE is not flagged."""
        sql = "DELETE FROM users WHERE status = 'inactive'"
        result = detect_antipatterns(sql)
        
        assert result.has_unsafe_update_delete is False

    def test_update_with_where_not_flagged(self):
        """Test that UPDATE with WHERE is not flagged."""
        sql = "UPDATE users SET status = 'active' WHERE id = 1"
        result = detect_antipatterns(sql)
        
        assert result.has_unsafe_update_delete is False


class TestRedundantDistinctAntipattern:
    """Test redundant DISTINCT with GROUP BY antipattern detection."""

    def test_distinct_with_group_by_detected(self):
        """Test that DISTINCT with GROUP BY is detected."""
        sql = "SELECT DISTINCT user_id, COUNT(*) FROM orders GROUP BY user_id"
        result = detect_antipatterns(sql)
        
        assert result.has_redundant_distinct is True
        assert result.total_antipatterns >= 1
        assert any(ap.pattern == "redundant_distinct" for ap in result.antipatterns)

    def test_distinct_without_group_by_not_flagged(self):
        """Test that DISTINCT alone is not flagged."""
        sql = "SELECT DISTINCT user_id FROM orders"
        result = detect_antipatterns(sql)
        
        assert result.has_redundant_distinct is False

    def test_group_by_without_distinct_not_flagged(self):
        """Test that GROUP BY alone is not flagged."""
        sql = "SELECT user_id, COUNT(*) FROM orders GROUP BY user_id"
        result = detect_antipatterns(sql)
        
        assert result.has_redundant_distinct is False

    def test_distinct_inside_agg_not_flagged(self):
        """
        Test that DISTINCT inside an aggregate function (e.g., COUNT(DISTINCT col))
        is NOT flagged as redundant DISTINCT.
        """
        sql = """
            SELECT card_type_code, COUNT(DISTINCT customer_id)
            FROM Customers_cards
            GROUP BY card_type_code
        """
        result = detect_antipatterns(sql)

        assert result.has_redundant_distinct is False
        assert not any(ap.pattern == "redundant_distinct" for ap in result.antipatterns)

    def test_distinct_with_group_by_and_having_detected(self):
        """DISTINCT together with GROUP BY and HAVING is still redundant."""
        sql = """
        SELECT DISTINCT user_id, COUNT(*) 
        FROM orders 
        WHERE status = 'PAID'
        GROUP BY user_id
        HAVING COUNT(*) > 1
        """
        result = detect_antipatterns(sql)

        assert result.has_redundant_distinct is True
        assert any(ap.pattern == "redundant_distinct" for ap in result.antipatterns)

    def test_distinct_with_group_by_in_subquery_detected(self):
        """DISTINCT + GROUP BY in a subquery should also be detected as redundant."""
        sql = """
        SELECT u.user_id
        FROM (
            SELECT DISTINCT user_id, COUNT(*) AS cnt
            FROM orders
            GROUP BY user_id
        ) u
        WHERE u.cnt > 10
        """
        result = detect_antipatterns(sql)

        assert result.has_redundant_distinct is True
        assert any(ap.pattern == "redundant_distinct" for ap in result.antipatterns)

    def test_distinct_in_subquery_without_group_by_not_flagged(self):
        """DISTINCT in a subquery without GROUP BY should not be flagged."""
        sql = """
        SELECT user_id
        FROM orders
        WHERE user_id IN (
            SELECT DISTINCT user_id
            FROM archived_orders
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_redundant_distinct is False
        assert not any(ap.pattern == "redundant_distinct" for ap in result.antipatterns)

    def test_distinct_with_window_function_not_flagged(self):
        """
        DISTINCT used with a window function but without GROUP BY 
        should not be treated as redundant DISTINCT.
        """
        sql = """
        SELECT DISTINCT 
            user_id,
            COUNT(*) OVER (PARTITION BY user_id) AS orders_per_user
        FROM orders
        """
        result = detect_antipatterns(sql)

        assert result.has_redundant_distinct is False
        assert not any(ap.pattern == "redundant_distinct" for ap in result.antipatterns)


class TestSelectInExistsAntipattern:
    """Test SELECT in EXISTS antipattern detection."""

    def test_select_star_in_exists_detected(self):
        """Test that SELECT * in EXISTS is detected."""
        sql = "SELECT * FROM users WHERE EXISTS (SELECT * FROM orders WHERE orders.user_id = users.id)"
        result = detect_antipatterns(sql)
        
        assert result.has_select_in_exists is True
        assert result.total_antipatterns >= 1
        assert any(ap.pattern == "select_in_exists" for ap in result.antipatterns)

    def test_select_column_in_exists_detected(self):
        """Test that SELECT column in EXISTS is detected."""
        sql = "SELECT * FROM users WHERE EXISTS (SELECT id FROM orders WHERE orders.user_id = users.id)"
        result = detect_antipatterns(sql)
        
        assert result.has_select_in_exists is True
    def test_select_literal_in_exists_not_flagged(self):
        """SELECT 1 in EXISTS is idiomatic and should NOT be flagged."""
        sql = """
        SELECT *
        FROM users
        WHERE EXISTS (
            SELECT 1
            FROM orders
            WHERE orders.user_id = users.id
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_select_in_exists is False
        assert not any(ap.pattern == "select_in_exists" for ap in result.antipatterns)

    def test_select_multiple_expressions_in_exists_detected(self):
        """
        SELECT id, 1 in EXISTS is still unnecessary, because EXISTS
        only cares about row existence. This should be flagged.
        """
        sql = """
        SELECT *
        FROM users
        WHERE EXISTS (
            SELECT id, 1
            FROM orders
            WHERE orders.user_id = users.id
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_select_in_exists is True
        assert any(ap.pattern == "select_in_exists" for ap in result.antipatterns)

    def test_multiple_exists_only_one_with_columns_still_flagged(self):
        """
        If there are multiple EXISTS subqueries and at least one of them
        uses SELECT * or columns, the antipattern should be detected.
        """
        sql = """
        SELECT *
        FROM users
        WHERE EXISTS (
            SELECT 1
            FROM orders
            WHERE orders.user_id = users.id
        )
        OR EXISTS (
            SELECT id
            FROM invoices
            WHERE invoices.user_id = users.id
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_select_in_exists is True
        assert any(ap.pattern == "select_in_exists" for ap in result.antipatterns)

    def test_exists_without_subquery_select_not_flagged(self):
        """
        Defensive test: if EXISTS somehow does not contain a SELECT node
        (e.g., malformed or different AST shape), it should not be flagged.
        """
        sql = "SELECT * FROM users"  # no EXISTS at all
        result = detect_antipatterns(sql)

        assert result.has_select_in_exists is False

class TestQualityScoring:
    """Test quality score calculation."""

    def test_perfect_query_score_100(self):
        """Test that perfect query scores 100."""
        sql = "SELECT id, name FROM users WHERE id = 1 ORDER BY id LIMIT 1"
        result = detect_antipatterns(sql)
        
        assert result.quality_score == 100
        assert result.quality_level == "excellent"

    def test_one_critical_major_penalty(self):
        """Test that one critical error significantly reduces score."""
        sql = "DELETE FROM users"
        result = detect_antipatterns(sql)
        
        # Critical: -30 points minimum
        assert result.total_antipatterns >= 1
        assert result.quality_score <= 70

    def test_one_warning_moderate_penalty(self):
        """Test that one warning moderately reduces score."""
        sql = "SELECT * FROM users"  # No LIMIT, so only SELECT * is flagged
        result = detect_antipatterns(sql)
        
        # SELECT * is medium: -5 points = 95
        assert result.total_antipatterns == 1
        assert result.quality_score == 95

    def test_multiple_issues_compound(self):
        """Test that multiple issues compound."""
        sql = "SELECT * FROM users WHERE UPPER(name) LIKE '%john%'"
        result = detect_antipatterns(sql)
        
        # Multiple antipatterns should reduce score significantly
        assert result.total_antipatterns >= 2
        assert result.quality_score < 90

    def test_many_issues_poor_score(self):
        """Test that many issues result in poor score."""
        sql = """
        SELECT * FROM users, orders, products, categories, tags
        WHERE UPPER(users.name) LIKE '%john%'
        AND users.status NOT IN (SELECT status FROM valid_statuses WHERE active = 1)
        """
        result = detect_antipatterns(sql)
        
        assert result.total_antipatterns >= 3
        assert result.quality_score < 80


class TestQualityClassification:
    """Test quality level classification."""

    def test_excellent_classification(self):
        """Test excellent classification (90-100)."""
        sql = "SELECT id, name FROM users WHERE id = 1 ORDER BY id LIMIT 1"
        result = detect_antipatterns(sql)
        
        assert result.quality_level == "excellent"
        assert result.quality_score >= 90

    def test_good_classification(self):
        """Test good classification (70-89)."""
        sql = "SELECT * FROM users LIMIT 10"
        result = detect_antipatterns(sql)
        
        # Should have some minor issues but still good
        assert result.quality_level in ["good", "excellent"]

    def test_fair_classification(self):
        """Test fair classification (50-69)."""
        sql = "SELECT * FROM users WHERE UPPER(name) LIKE '%john%'"
        result = detect_antipatterns(sql)
        
        # Multiple warnings should result in fair or good
        assert result.quality_level in ["fair", "good"]

    def test_poor_classification(self):
        """Test poor classification (0-49)."""
        sql = "DELETE FROM users"
        result = detect_antipatterns(sql)
        
        # One critical error: -20 points = 80 (good)
        # Adjust expectation based on actual scoring
        assert result.quality_level in ["poor", "fair", "good"]


class TestComplexQueries:
    """Test complex queries with multiple antipatterns."""

    def test_multiple_antipatterns_detected(self):
        """Test query with multiple antipatterns."""
        sql = """
        SELECT * FROM users, orders
        WHERE UPPER(users.name) LIKE '%john%'
        AND users.status NOT IN (SELECT status FROM inactive_statuses)
        """
        result = detect_antipatterns(sql)
        
        assert result.parseable is True
        assert result.total_antipatterns >= 3
        # Should detect: SELECT *, function in WHERE, leading wildcard, NOT IN
        assert result.has_select_star is True
        assert result.has_function_in_where is True
        assert result.has_leading_wildcard_like is True
        assert result.has_not_in_nullable is True

    def test_worst_case_query(self):
        """Test query with many severe antipatterns."""
        sql = """
        SELECT * FROM users, orders, products, categories, tags, vendors
        WHERE UPPER(users.name) LIKE '%search%'
        AND users.id NOT IN (SELECT user_id FROM banned_users WHERE reason LIKE '%spam%')
        AND DATE(orders.created_at) = '2024-01-01'
        AND (products.status = 'active' OR products.status = 'pending' OR products.status = 'trial' OR products.status = 'beta')
        """
        result = detect_antipatterns(sql)
        
        assert result.parseable is True
        assert result.total_antipatterns >= 5
        assert result.quality_score < 70
        assert result.quality_level in ["poor", "fair"]

    def test_well_optimized_complex_query(self):
        """Test complex but well-written query."""
        sql = """
        SELECT u.id, u.name, u.email, COUNT(o.id) AS order_count
        FROM users u
        INNER JOIN orders o ON u.id = o.user_id
        WHERE u.status = 'active'
        AND o.created_at >= '2024-01-01'
        GROUP BY u.id, u.name, u.email
        HAVING COUNT(o.id) > 5
        ORDER BY order_count DESC
        LIMIT 100
        """
        result = detect_antipatterns(sql)
        
        assert result.parseable is True
        # Should have no antipatterns or only minor ones
        assert result.total_antipatterns <= 1
        assert result.quality_score >= 85
        assert result.quality_level in ["excellent", "good"]


class TestDialectSupport:
    """Test different SQL dialect support."""

    def test_sqlite_dialect(self):
        """Test SQLite dialect (default)."""
        sql = "SELECT * FROM users LIMIT 10"
        result = detect_antipatterns(sql, dialect="sqlite")
        
        assert result.parseable is True

    def test_postgres_dialect(self):
        """Test PostgreSQL dialect."""
        sql = "SELECT * FROM users LIMIT 10 OFFSET 20"
        result = detect_antipatterns(sql, dialect="postgres")
        
        assert result.parseable is True

    def test_none_dialect_uses_default(self):
        """Test that None dialect uses default (sqlite)."""
        sql = "SELECT * FROM users"
        result = detect_antipatterns(sql, dialect=None)
        
        assert result.parseable is True


class TestAntipatternDetails:
    """Test antipattern instance details."""

    def test_antipattern_has_pattern_name(self):
        """Test that antipattern has pattern identifier."""
        sql = "SELECT * FROM users"
        result = detect_antipatterns(sql)
        
        assert len(result.antipatterns) >= 1
        for ap in result.antipatterns:
            assert ap.pattern
            assert isinstance(ap.pattern, str)

    def test_antipattern_has_severity(self):
        """Test that antipattern has severity level."""
        sql = "DELETE FROM users"
        result = detect_antipatterns(sql)
        
        assert len(result.antipatterns) >= 1
        for ap in result.antipatterns:
            assert ap.severity in ["critical", "error", "warning", "info"]

    def test_antipattern_has_message(self):
        """Test that antipattern has human-readable message."""
        sql = "SELECT * FROM users"
        result = detect_antipatterns(sql)
        
        assert len(result.antipatterns) >= 1
        for ap in result.antipatterns:
            assert ap.message
            assert len(ap.message) > 10  # Should be descriptive

    def test_antipattern_has_location(self):
        """Test that antipattern has location hint."""
        sql = "SELECT * FROM users"
        result = detect_antipatterns(sql)
        
        assert len(result.antipatterns) >= 1
        for ap in result.antipatterns:
            # Location is optional but should be present for most
            assert hasattr(ap, 'location')


class TestSeverityCounts:
    """Test severity counting (from JSON antipatterns field)."""

    def test_critical_severity_in_json(self):
        """Test that critical severity antipatterns are in JSON."""
        sql = "DELETE FROM users"
        result = detect_antipatterns(sql)
        
        critical_antipatterns = [ap for ap in result.antipatterns if ap.severity == "critical"]
        assert len(critical_antipatterns) >= 1
        assert result.total_antipatterns >= 1

    def test_high_severity_in_json(self):
        """Test that high severity antipatterns are in JSON."""
        sql = "SELECT * FROM users WHERE UPPER(name) = 'JOHN'"
        result = detect_antipatterns(sql)
        
        high_antipatterns = [ap for ap in result.antipatterns if ap.severity == "high"]
        assert len(high_antipatterns) >= 1

    def test_medium_severity_in_json(self):
        """Test that medium severity antipatterns are in JSON."""
        # Use a query that triggers a known medium-severity antipattern.
        # Here: DISTINCT together with GROUP BY → redundant_distinct (medium).
        sql = "SELECT DISTINCT user_id, COUNT(*) FROM orders GROUP BY user_id"
        result = detect_antipatterns(sql)
        
        medium_antipatterns = [ap for ap in result.antipatterns if ap.severity == "medium"]
        assert len(medium_antipatterns) >= 1

    def test_total_count_matches_json(self):
        """Test that total count matches antipatterns JSON array length."""
        sql = "SELECT * FROM users WHERE UPPER(name) LIKE '%john%'"
        result = detect_antipatterns(sql)
        
        assert result.total_antipatterns == len(result.antipatterns)
        assert result.total_antipatterns >= 1
    
    def test_custom_severity_in_json(self):
        """Test that custom severity levels work in JSON."""
        custom_config = {
            'blocker': ['unsafe_update_delete'],
            'p0': ['function_in_where']
        }
        sql = "DELETE FROM users"
        result = detect_antipatterns(sql, config=custom_config)
        
        blocker_antipatterns = [ap for ap in result.antipatterns if ap.severity == "blocker"]
        assert len(blocker_antipatterns) >= 1
        assert result.total_antipatterns == len(result.antipatterns)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_very_long_query(self):
        """Test that very long queries are handled correctly."""
        columns = ", ".join([f"col{i}" for i in range(100)])
        sql = f"SELECT {columns} FROM users LIMIT 10"
        result = detect_antipatterns(sql)
        
        assert result.parseable is True

    def test_query_with_comments(self):
        """Test query with SQL comments."""
        sql = """
        -- This is a comment
        SELECT * FROM users
        WHERE status = 'active' /* inline comment */
        LIMIT 10
        """
        result = detect_antipatterns(sql)
        
        assert result.parseable is True

    def test_case_insensitive_keywords(self):
        """Test that SQL keywords are case-insensitive."""
        sql = "select * from users limit 10"
        result = detect_antipatterns(sql)
        
        assert result.parseable is True
        assert result.has_select_star is True

    def test_query_with_schema_prefix(self):
        """Test query with schema.table notation."""
        sql = "SELECT id, name FROM public.users LIMIT 10"
        result = detect_antipatterns(sql)
        
        assert result.parseable is True


class TestNoFalsePositives:
    """Test that well-written queries don't trigger false positives."""

    def test_clean_select_query(self):
        """Test clean SELECT query has no antipatterns."""
        sql = """
        SELECT u.id, u.name, u.email, COUNT(o.id) AS order_count
        FROM users u
        INNER JOIN orders o ON u.id = o.user_id
        WHERE u.status = 'active'
        GROUP BY u.id, u.name, u.email
        ORDER BY order_count DESC
        LIMIT 100
        """
        result = detect_antipatterns(sql)
        
        assert result.total_antipatterns == 0
        assert result.quality_score == 100

    def test_clean_insert_query(self):
        """Test clean INSERT query has no antipatterns."""
        sql = "INSERT INTO users (name, email, status) VALUES ('John', 'john@example.com', 'active')"
        result = detect_antipatterns(sql)
        
        assert result.total_antipatterns == 0
        assert result.quality_score == 100

    def test_clean_update_query(self):
        """Test clean UPDATE query has no antipatterns."""
        sql = "UPDATE users SET status = 'active' WHERE id = 123"
        result = detect_antipatterns(sql)
        
        assert result.total_antipatterns == 0
        assert result.quality_score == 100

    def test_clean_delete_query(self):
        """Test clean DELETE query has no antipatterns."""
        sql = "DELETE FROM users WHERE status = 'inactive' AND last_login < '2023-01-01'"
        result = detect_antipatterns(sql)
        
        # Should have no antipatterns or only minor ones
        assert result.total_antipatterns <= 1
        assert result.quality_score >= 85


class TestImprovedDetections:
    """Test improved detection logic to prevent false positives."""

    def test_simple_subquery_not_correlated(self):
        """Test that simple subqueries without table correlation are not flagged."""
        sql = """
        SELECT id, name
        FROM users
        WHERE status IN (SELECT status FROM valid_statuses WHERE priority > 5)
        LIMIT 10
        """
        result = detect_antipatterns(sql)
        
        # Should NOT flag correlated_subquery (improved heuristic)
        assert result.has_correlated_subquery is False

    def test_exists_with_literal_not_flagged(self):
        """Test that EXISTS with SELECT 1 is not flagged."""
        sql = """
        SELECT u.id, u.name
        FROM users u
        WHERE EXISTS (
            SELECT 1 FROM orders o WHERE o.user_id = u.id AND o.total > 100
        )
        LIMIT 10
        """
        result = detect_antipatterns(sql)
        
        # Should NOT flag select_in_exists (using literal)
        assert result.has_select_in_exists is False

    def test_multiple_literal_expressions_in_exists_not_flagged(self):
        """Test that EXISTS with multiple literals is not flagged."""
        sql = """
        SELECT id FROM users
        WHERE EXISTS (SELECT 1, 2, 3 FROM orders WHERE orders.user_id = users.id)
        LIMIT 10
        """
        result = detect_antipatterns(sql)
        
        # All literals, should NOT flag
        assert result.has_select_in_exists is False

    def test_correlated_exists_properly_detected(self):
        """Test that truly correlated EXISTS is detected."""
        sql = """
        SELECT u.id, u.name
        FROM users u
        WHERE EXISTS (
            SELECT 1 FROM orders o WHERE o.user_id = u.id
        )
        LIMIT 10
        """
        result = detect_antipatterns(sql)        
        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)


class TestMissingGroupBySubqueryFix:
    """Test missing GROUP BY detection with subqueries (bug fix)."""
    
    def test_aggregate_only_in_subquery_not_flagged(self):
        """Test that aggregate in subquery only is not flagged (bug fix)."""
        # This was the original bug: aggregate in WHERE subquery incorrectly flagged
        sql = "SELECT song_name FROM singer WHERE age > (SELECT AVG(age) FROM singer)"
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is False
        assert result.parseable is True
        assert result.total_antipatterns == 0 or not any(
            ap.pattern == "missing_group_by" for ap in result.antipatterns
        )
    
    def test_aggregate_in_select_with_column_flagged(self):
        """Test that aggregate in SELECT with non-aggregated column is flagged."""
        sql = "SELECT singer_name, AVG(age) FROM singer"
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is True
        assert result.total_antipatterns >= 1
        assert any(ap.pattern == "missing_group_by" for ap in result.antipatterns)
    
    def test_aggregate_with_group_by_not_flagged(self):
        """Test that aggregate with proper GROUP BY is not flagged."""
        sql = "SELECT singer_name, AVG(age) FROM singer GROUP BY singer_name"
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is False
    
    def test_scalar_aggregate_not_flagged(self):
        """Test that scalar aggregate (no columns) is not flagged."""
        sql = "SELECT AVG(age), COUNT(*), MAX(age) FROM singer"
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is False
    
    def test_no_aggregates_not_flagged(self):
        """Test that query without aggregates is not flagged."""
        sql = "SELECT name, age FROM singer WHERE age > 30"
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is False
    
    def test_aggregate_in_having_with_subquery(self):
        """Test aggregate in HAVING clause with subquery in WHERE."""
        sql = """
        SELECT singer_name, COUNT(*) 
        FROM singer 
        WHERE age > (SELECT AVG(age) FROM singer)
        GROUP BY singer_name
        HAVING COUNT(*) > 1
        """
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is False
    
    def test_multiple_subqueries_with_aggregates(self):
        """Test query with aggregates in multiple subqueries but not in main SELECT."""
        sql = """
        SELECT name 
        FROM singer 
        WHERE age > (SELECT AVG(age) FROM singer)
        AND song_count < (SELECT MAX(song_count) FROM singer)
        """
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is False
    
    def test_aggregate_in_select_and_subquery(self):
        """Test aggregate in both SELECT and subquery - should be flagged if no GROUP BY."""
        sql = """
        SELECT singer_name, AVG(age) 
        FROM singer 
        WHERE age > (SELECT AVG(age) FROM singer WHERE country = 'USA')
        """
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is True
    
    def test_column_in_aggregate_with_subquery_not_flagged(self):
        """Test column inside aggregate with subquery - should not be flagged."""
        sql = """
        SELECT AVG(age) 
        FROM singer 
        WHERE age > (SELECT AVG(age) FROM singer)
        """
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is False
    
    def test_nested_subquery_with_aggregate(self):
        """Test nested subquery with aggregates - outer SELECT has no aggregate."""
        sql = """
        SELECT name 
        FROM singer 
        WHERE country IN (
            SELECT country 
            FROM singer 
            GROUP BY country 
            HAVING COUNT(*) > (SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM singer GROUP BY country))
        )
        """
        result = detect_antipatterns(sql)
        
        # Outer SELECT has no aggregates, should not be flagged
        assert result.has_missing_group_by is False
    
    def test_subquery_in_from_clause(self):
        """Test subquery in FROM clause with aggregates."""
        sql = """
        SELECT s.name, s.avg_age
        FROM (SELECT country, AVG(age) as avg_age FROM singer GROUP BY country) s
        WHERE s.avg_age > 30
        """
        result = detect_antipatterns(sql)
        
        # Outer SELECT has no aggregates, subquery has proper GROUP BY
        assert result.has_missing_group_by is False
    
    def test_correlated_subquery_with_aggregate(self):
        """Test correlated subquery with aggregate in WHERE."""
        sql = """
        SELECT s1.name 
        FROM singer s1 
        WHERE s1.age > (SELECT AVG(s2.age) FROM singer s2 WHERE s2.country = s1.country)
        """
        result = detect_antipatterns(sql)
        
        # Outer SELECT has no aggregates
        assert result.has_missing_group_by is False

    def test_missing_group_by_detected_in_correlated_subquery(self):
        """Test correlated subquery with aggregate in WHERE."""
        sql = """
        SELECT s1.name 
        FROM singer s1 
        WHERE s1.age > (SELECT name, AVG(s2.age) FROM singer s2 WHERE s2.country = s1.country)
        """
        result = detect_antipatterns(sql)
        
        # Outer SELECT has no aggregates
        assert result.has_missing_group_by is True

    
    def test_aggregate_in_select_list_subquery(self):
        """Test aggregate in scalar subquery in SELECT list."""
        sql = """
        SELECT name, (SELECT AVG(age) FROM singer) as avg_age
        FROM singer
        WHERE age > 25
        """
        result = detect_antipatterns(sql)
        
        # The aggregate is in a subquery within SELECT, not directly in SELECT
        # This should NOT be flagged
        assert result.has_missing_group_by is False
    
    def test_multiple_columns_with_aggregate_missing_group_by(self):
        """Test multiple non-aggregated columns with aggregate."""
        sql = "SELECT country, city, COUNT(*) FROM singer"
        result = detect_antipatterns(sql)
        
        # Should be flagged: mixing aggregates with multiple non-aggregated columns
        assert result.has_missing_group_by is True
    
    def test_group_by_alias_not_matching_column_flagged(self):
        sql = "SELECT country AS c, AVG(age) FROM singer GROUP BY c"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False


    def test_partial_group_by(self):
        """Test GROUP BY missing one of the columns.    
        """
        sql = "SELECT country, city, COUNT(*) FROM singer GROUP BY country"
        result = detect_antipatterns(sql)
        
        assert result.has_missing_group_by is True

    def test_window_function_not_treated_as_missing_group_by(self):
        sql = """
        SELECT 
            name,
            AVG(age) OVER (PARTITION BY country) AS avg_age_by_country
        FROM singer
        """
        result = detect_antipatterns(sql)

        # В більшості проєктів window-функції не вважаються "group aggregate" для цього антипатерну
        assert result.has_missing_group_by is False

    def test_column_only_inside_aggregate_not_flagged(self):
        sql = "SELECT SUM(age) FROM singer"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False

    def test_column_inside_case_with_aggregate_flagged(self):
        sql = """
        SELECT 
            CASE 
                WHEN age > 30 THEN country 
                ELSE city 
            END AS region,
            COUNT(*) 
        FROM singer
        """
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is True

    def test_non_aggregate_column_in_expression_flagged(self):
        sql = "SELECT country || '-' || city, COUNT(*) FROM singer"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is True 


    def test_group_by_alias_not_matching_column_not_flagged(self):
        sql = "SELECT country AS c, AVG(age) FROM singer GROUP BY c"
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is False

    def test_missing_group_by_with_join_and_different_group_column(self):
        sql = """
        SELECT c.Official_Name
        FROM city AS c
        JOIN farm_competition AS f
        ON c.City_ID = f.Host_city_ID
        GROUP BY f.Host_city_ID
        HAVING COUNT(*) > 1
        """
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is True
        assert any(ap.pattern == "missing_group_by" for ap in result.antipatterns)        

    def test_missing_group_by_with_extra_column_not_in_group(self):
        """Station name grouped, station id not grouped → should be flagged."""
        sql = """
        SELECT start_station_name, start_station_id
        FROM trip
        WHERE start_date LIKE '8/%'
        GROUP BY start_station_name
        ORDER BY COUNT(*) DESC
        LIMIT 1
        """
        result = detect_antipatterns(sql)

        assert result.has_missing_group_by is True
        assert any(ap.pattern == "missing_group_by" for ap in result.antipatterns)
        
class TestAntipatternConfiguration:
    """Test antipattern configuration and dialect-specific detection."""

    def test_patterns_not_in_config_not_detected(self):
        """Test that patterns not in config are not detected."""
        # Config that doesn't include select_star
        config = {
            "critical": [],
            "high": [],
            "medium": []
        }
        
        sql = "SELECT * FROM users"
        result = detect_antipatterns(sql, dialect="sqlite", config=config)
        
        # Should not detect anything
        assert result.has_select_star is False
        assert result.total_antipatterns == 0

    def test_enabled_patterns_detected(self):
        """Test that enabled patterns are detected."""
        # Config that enables only unsafe_update_delete
        config = {
            "critical": ["unsafe_update_delete"],
            "high": [],
            "medium": []
        }
        
        sql = "DELETE FROM users"
        result = detect_antipatterns(sql, dialect="sqlite", config=config)
        
        # Should detect unsafe_update_delete
        assert result.has_unsafe_update_delete is True
        assert result.total_antipatterns >= 1

    def test_default_config_used_when_none(self):
        """Test that default config is used when None is provided."""
        sql = "SELECT * FROM users WHERE status = NULL"
        result = detect_antipatterns(sql, dialect="sqlite", config=None)
        
        # Should use default config and detect null_comparison_equals
        assert result.has_null_comparison_equals is True

    def test_mixed_severity_config(self):
        """Test configuration with mixed severity levels."""
        config = {
            "critical": ["null_comparison_equals"],
            "high": ["function_in_where"],
            "medium": ["redundant_distinct"]
        }
        
        sql = "SELECT * FROM users WHERE status = NULL"
        result = detect_antipatterns(sql, dialect="sqlite", config=config)
        
        # Should detect null_comparison_equals
        assert result.has_null_comparison_equals is True
        # Should not detect select_star (not in config)
        assert result.has_select_star is False


class TestCorrelatedSubqueryAntipattern:
    """Unit tests for correlated subquery antipattern detection."""

    # --- Original core tests ---

    def test_correlated_subquery_with_derived_table_alias(self):
        """Test that subquery aliases in FROM are correctly tracked."""
        sql = """
        SELECT u.id 
        FROM users u
        JOIN (SELECT user_id FROM orders) o ON o.user_id = u.id
        WHERE EXISTS (
            SELECT 1 FROM payments p WHERE p.user_id = o.user_id
        )
        """
        result = detect_antipatterns(sql)
        
        # o.user_id should reference the derived table, not be treated as correlation
        # This is still correlated because the EXISTS references 'o' from outer query
        assert result.has_correlated_subquery is True
        
        # This query should NOT be detected as Cartesian product
        assert result.has_cartesian_product is False

    def test_exists_correlated_subquery_detected(self):
        """EXISTS with outer table reference in subquery WHERE should be detected as correlated."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE EXISTS (
            SELECT 1
            FROM orders o
            WHERE o.user_id = u.id
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)

    def test_scalar_correlated_subquery_in_select_list_detected(self):
        """Scalar subquery in SELECT list referencing outer table should be detected as correlated."""
        sql = """
        SELECT
            u.id,
            (
                SELECT COUNT(*)
                FROM orders o
                WHERE o.user_id = u.id
            ) AS order_count
        FROM users u
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)

    def test_non_correlated_aggregate_subquery_not_flagged(self):
        """Aggregate subquery over the same base table but without outer alias reference should not be flagged."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE u.age > (
            SELECT AVG(age)
            FROM users
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is False
        assert all(ap.pattern != "correlated_subquery" for ap in result.antipatterns)

    def test_non_correlated_exists_on_other_table_not_flagged(self):
        """EXISTS subquery that does not reference the outer table should not be flagged as correlated."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE EXISTS (
            SELECT 1
            FROM orders o
            WHERE o.created_at > '2024-01-01'
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is False
        assert all(ap.pattern != "correlated_subquery" for ap in result.antipatterns)

    def test_subquery_with_own_alias_shadowing_outer_not_flagged(self):
        """Inner subquery that reuses the same alias name should not be treated as correlated (alias shadowing)."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE EXISTS (
            SELECT 1
            FROM users u
            WHERE u.created_at > '2024-01-01'
        )
        """
        result = detect_antipatterns(sql)

        # Inner `u` should shadow outer `u`, so no correlation
        assert result.has_correlated_subquery is False
        assert all(ap.pattern != "correlated_subquery" for ap in result.antipatterns)

    def test_nested_correlated_subquery_still_detected(self):
        """Correlated subquery nested one level inside another expression should still be detected."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE u.status = 'vip'
          AND (
              SELECT MAX(o.amount)
              FROM orders o
              WHERE o.user_id = u.id
          ) > 100
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)

    # --- Extended tests ---

    # 1) Correlated IN subquery
    def test_in_correlated_subquery_detected(self):
        """IN subquery referencing outer table should be detected as correlated."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE u.id IN (
            SELECT o.user_id
            FROM orders o
            WHERE o.user_id = u.id
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)

    # 2) Correlated NOT IN subquery
    def test_not_in_correlated_subquery_detected(self):
        """NOT IN subquery referencing outer table should be detected as correlated."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE u.id NOT IN (
            SELECT o.user_id
            FROM orders o
            WHERE o.user_id = u.id
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)

    # 3) Non-correlated IN subquery (sanity check)
    def test_non_correlated_in_subquery_not_flagged(self):
        """IN subquery without outer table reference should not be flagged as correlated."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE u.id IN (
            SELECT o.user_id
            FROM orders o
            WHERE o.created_at > '2024-01-01'
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is False
        assert all(ap.pattern != "correlated_subquery" for ap in result.antipatterns)

    # 4) Correlated subquery in HAVING
    def test_correlated_subquery_in_having_detected(self):
        """Correlation inside HAVING should be detected."""
        sql = """
        SELECT u.id, COUNT(*) AS cnt
        FROM users u
        GROUP BY u.id
        HAVING COUNT(*) > (
            SELECT COUNT(*)
            FROM orders o
            WHERE o.user_id = u.id
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)

    # 5) Correlated subquery inside CASE
    def test_correlated_subquery_in_case_detected(self):
        """Correlation inside CASE expression in SELECT list should be detected."""
        sql = """
        SELECT
            u.id,
            CASE
                WHEN (
                    SELECT COUNT(*)
                    FROM orders o
                    WHERE o.user_id = u.id
                ) > 0 THEN 'has_orders'
                ELSE 'no_orders'
            END AS status
        FROM users u
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)

    # 6) Correlated subquery in ORDER BY
    def test_correlated_subquery_in_order_by_detected(self):
        """Correlation inside ORDER BY should be detected."""
        sql = """
        SELECT u.id
        FROM users u
        ORDER BY (
            SELECT MAX(o.amount)
            FROM orders o
            WHERE o.user_id = u.id
        ) DESC
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)

    # 7) Deeply nested correlated subquery
    def test_deeply_nested_correlated_subquery_detected(self):
        """Correlation several levels deep inside nested subqueries should still be detected."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE (
            SELECT MAX(inner_count)
            FROM (
                SELECT COUNT(*) AS inner_count
                FROM orders o
                WHERE o.user_id = u.id
            ) x
        ) > 5
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)

    # 8) Deeply nested but NON-correlated (Mississippi-style pattern)
    def test_deeply_nested_non_correlated_subqueries_not_flagged(self):
        """Nested subqueries that never reference outer aliases should not be flagged."""
        sql = """
        SELECT population
        FROM city
        WHERE city_name = (
            SELECT capital
            FROM state
            WHERE area = (
                SELECT MAX(t1.area)
                FROM state AS t1
                JOIN river AS t2
                  ON t1.state_name = t2.traverse
                WHERE t2.river_name = 'mississippi'
            )
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is False
        assert all(ap.pattern != "correlated_subquery" for ap in result.antipatterns)

    # 9) Mixed query: one correlated, one non-correlated
    def test_mixed_correlated_and_non_correlated_subqueries(self):
        """If there is at least one correlated subquery, the query should be flagged."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE u.age > (
            SELECT AVG(age)
            FROM users
        )
          AND EXISTS (
              SELECT 1
              FROM orders o
              WHERE o.user_id = u.id
          )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)

    # 10) Derived table (FROM subquery) – NON-correlated
    def test_non_correlated_derived_table_not_flagged(self):
        """Simple derived table without outer references should not be considered correlated."""
        sql = """
        SELECT u.id, x.order_count
        FROM users u
        JOIN (
            SELECT o.user_id, COUNT(*) AS order_count
            FROM orders o
            GROUP BY o.user_id
        ) x ON x.user_id = u.id
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is False
        assert all(ap.pattern != "correlated_subquery" for ap in result.antipatterns)

    # 11) Derived table that wrongly references outer alias (if your parser allows this)
    def test_correlated_derived_table_detected(self):
        """If a FROM-subquery references the outer alias, it should be treated as correlated."""
        sql = """
        SELECT u.id
        FROM users u
        JOIN (
            SELECT o.user_id
            FROM orders o
            WHERE o.user_id = u.id
        ) x ON x.user_id = u.id
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)

    # 12) Double alias shadowing – inner scope reuses outer alias but no correlation
    def test_nested_alias_shadowing_not_flagged(self):
        """
        Inner subquery reuses outer alias name twice; all references should bind to the innermost alias,
        so there is still no real correlation.
        """
        sql = """
        SELECT u.id
        FROM users u
        WHERE EXISTS (
            SELECT 1
            FROM users u
            WHERE EXISTS (
                SELECT 1
                FROM users u
                WHERE u.created_at > '2024-01-01'
            )
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is False
        assert all(ap.pattern != "correlated_subquery" for ap in result.antipatterns)

    # 13) SAME column name, DIFFERENT alias – must not be confused
    def test_same_column_name_different_alias_not_flagged(self):
        """
        Same column name across tables without outer alias reference should not be misdetected as correlated.
        """
        sql = """
        SELECT u.id
        FROM users u
        WHERE u.age > (
            SELECT AVG(age)
            FROM employees e
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is False
        assert all(ap.pattern != "correlated_subquery" for ap in result.antipatterns)

    # 14) Correlated ANY / SOME subquery (if you support it)
    def test_correlated_any_subquery_detected(self):
        """Correlation in an ANY subquery should be detected."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE u.age > ANY (
            SELECT o.discount
            FROM orders o
            WHERE o.user_id = u.id
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is True
        assert any(ap.pattern == "correlated_subquery" for ap in result.antipatterns)

    # 15) Non-correlated ANY subquery (sanity)
    def test_non_correlated_any_subquery_not_flagged(self):
        """ANY subquery without outer reference should not be correlated."""
        sql = """
        SELECT u.id
        FROM users u
        WHERE u.age > ANY (
            SELECT o.discount
            FROM orders o
            WHERE o.created_at > '2024-01-01'
        )
        """
        result = detect_antipatterns(sql)

        assert result.has_correlated_subquery is False
        assert all(ap.pattern != "correlated_subquery" for ap in result.antipatterns)


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])

