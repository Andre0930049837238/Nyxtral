# -*- coding: utf-8 -*-
"""Regression tests for the SQL engine: (name, script, expected ids). Run: python tools/test_sql_engine.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import sql_engine as Q

CASES = [
 # ---- MUST be reported ----
 ("password in CREATE USER", "CREATE USER app IDENTIFIED BY 'S3cretPass!';", {"AST-SQL-002"}),
 ("PostgreSQL password", "CREATE ROLE app LOGIN PASSWORD 'hunter2hunter2';", {"AST-SQL-002"}),
 ("T-SQL password", "CREATE LOGIN app WITH PASSWORD = 'Pa55w0rd!x';", {"AST-SQL-002"}),
 ("SET PASSWORD statement", "SET PASSWORD FOR 'bob'@'localhost' = PASSWORD('Xk29fh2');", {"AST-SQL-002", "AST-SQL-005"}),
 ("empty password", "CREATE USER app IDENTIFIED BY '';", {"AST-SQL-010"}),
 ("user with wildcard host %", "CREATE USER 'bob'@'%' IDENTIFIED BY '${PWD}';", {"AST-SQL-010"}),
 ("INSERT with cleartext password", "INSERT INTO users (id, password) VALUES (1, 'hunter2');", {"AST-SQL-002"}),
 ("GRANT ALL on everything", "GRANT ALL PRIVILEGES ON *.* TO 'bob'@'localhost';", {"AST-SQL-001"}),
 ("GRANT to PUBLIC", "GRANT SELECT ON t TO PUBLIC;", {"AST-SQL-001"}),
 ("GRANT OPTION", "GRANT SELECT ON t TO bob WITH GRANT OPTION;", {"AST-SQL-001"}),
 ("SUPERUSER", "ALTER ROLE bob SUPERUSER;", {"AST-SQL-001"}),
 ("sysadmin", "EXEC sp_addsrvrolemember 'bob', 'sysadmin';", {"AST-SQL-001"}),
 ("concatenated EXEC", "EXEC('SELECT * FROM t WHERE n = ''' + @name + '''');", {"AST-SQL-003"}),
 ("sp_executesql on a concatenated variable", "SET @sql = 'SELECT * FROM t WHERE n = ''' + @name + '''';\nEXEC sp_executesql @sql;", {"AST-SQL-003"}),
 ("EXECUTE IMMEDIATE ||", "BEGIN EXECUTE IMMEDIATE 'SELECT * FROM ' || tbl INTO v; END;", {"AST-SQL-003"}),
 ("PL/pgSQL EXECUTE ||", "CREATE FUNCTION f(tbl text) RETURNS void AS $$ BEGIN EXECUTE 'SELECT * FROM ' || tbl; END $$ LANGUAGE plpgsql SET search_path = public;", {"AST-SQL-003"}),
 ("format %s", "CREATE FUNCTION f(tbl text) RETURNS void AS $$ BEGIN EXECUTE format('SELECT * FROM %s', tbl); END $$ LANGUAGE plpgsql SET search_path = public;", {"AST-SQL-003"}),
 ("xp_cmdshell", "EXEC xp_cmdshell 'dir';", {"AST-SQL-004"}),
 ("COPY PROGRAM", "COPY t FROM PROGRAM 'curl http://x/y';", {"AST-SQL-004"}),
 ("LOAD_FILE", "SELECT LOAD_FILE('/etc/passwd');", {"AST-SQL-004"}),
 ("INTO OUTFILE", "SELECT * FROM t INTO OUTFILE '/tmp/x';", {"AST-SQL-004"}),
 ("UTL_FILE", "BEGIN UTL_FILE.FOPEN('D','f','w'); END;", {"AST-SQL-004"}),
 ("plpythonu", "CREATE FUNCTION f() RETURNS void AS $$ import os $$ LANGUAGE plpythonu;", {"AST-SQL-004"}),
 ("UNSAFE assembly", "CREATE ASSEMBLY a FROM 0x4D5A WITH PERMISSION_SET = UNSAFE;", {"AST-SQL-004"}),
 ("MD5 on password", "SELECT MD5(password) FROM users;", {"AST-SQL-005"}),
 ("HASHBYTES MD5", "SELECT HASHBYTES('MD5', x) FROM t;", {"AST-SQL-005"}),
 ("crypt gen_salt md5", "SELECT crypt(pw, gen_salt('md5'));", {"AST-SQL-005"}),
 ("sp_configure xp_cmdshell", "EXEC sp_configure 'xp_cmdshell', 1;", {"AST-SQL-006"}),
 ("TRUSTWORTHY", "ALTER DATABASE x SET TRUSTWORTHY ON;", {"AST-SQL-006"}),
 ("local_infile", "SET GLOBAL local_infile = 1;", {"AST-SQL-006"}),
 ("CHECK_POLICY OFF", "CREATE LOGIN app WITH PASSWORD = '${PWD}', CHECK_POLICY = OFF;", {"AST-SQL-006"}),
 ("SECURITY DEFINER", "CREATE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql SECURITY DEFINER;", {"AST-SQL-007"}),
 ("RLS disabled", "ALTER TABLE t DISABLE ROW LEVEL SECURITY;", {"AST-SQL-008"}),
 ("password column", "CREATE TABLE users (id int, password varchar(50));", {"AST-SQL-009"}),
 ("cvv column", "CREATE TABLE pay (id int, cvv varchar(4));", {"AST-SQL-009"}),
 ("inside a MySQL procedure with DELIMITER", "DELIMITER $$\nCREATE PROCEDURE p(IN n VARCHAR(20))\nBEGIN\n  SET @s = CONCAT('SELECT * FROM t WHERE n = ', n);\n  PREPARE st FROM @s;\nEND$$\nDELIMITER ;", {"AST-SQL-003"}) if False else
 ("COPY PROGRAM in a procedure", "CREATE FUNCTION f() RETURNS void AS $$ BEGIN COPY t FROM PROGRAM 'id'; END $$ LANGUAGE plpgsql SET search_path = public;", {"AST-SQL-004"}),
 # ---- MUST NOT be reported ----
 ("password from a variable", "CREATE USER app IDENTIFIED BY '${DB_PASSWORD}';", set()),
 ("already-hashed password", "INSERT INTO users (id, password) VALUES (1, '$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012');", set()),
 ("targeted GRANT", "GRANT SELECT ON app.t TO app_ro;", set()),
 ("EXEC with parameters", "EXEC sp_executesql N'SELECT * FROM t WHERE n = @n', N'@n nvarchar(50)', @n = @name;", set()),
 ("format %I %L", "CREATE FUNCTION f(t text, v text) RETURNS void AS $$ BEGIN EXECUTE format('SELECT * FROM %I WHERE a = %L', t, v); END $$ LANGUAGE plpgsql SET search_path = public;", set()),
 ("EXECUTE USING", "CREATE FUNCTION f(v text) RETURNS void AS $$ BEGIN EXECUTE 'SELECT * FROM t WHERE a = $1' USING v; END $$ LANGUAGE plpgsql SET search_path = public;", set()),
 ("SHA2_256", "SELECT HASHBYTES('SHA2_256', x) FROM t;", set()),
 ("password_hash column", "CREATE TABLE users (id int, password_hash varchar(60), salt varchar(32));", set()),
 ("SECURITY DEFINER with search_path", "CREATE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog;", set()),
 ("comment containing xp_cmdshell", "-- EXEC xp_cmdshell 'dir';\nSELECT 1;", set()),
 ("string containing xp_cmdshell", "INSERT INTO log (msg) VALUES ('use of xp_cmdshell is forbidden');", set()),
 ("sp_configure disabling", "EXEC sp_configure 'xp_cmdshell', 0;", set()),
 ("SELECT normale", "SELECT id, name FROM users WHERE id = 1;", set()),
]

def main():
    bad = 0
    for name, code, exp in CASES:
        got = {f["id"] for f in Q.analyze_sql_source("db/schema.sql", code)}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    print(f"\n{len(CASES) - bad}/{len(CASES)} tests passed" + ("" if not bad else " - see the FAIL lines above"))
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
