packages = ['psycopg2', 'sqlglot', 'pglast', 'sqlfluff', 'sqlparse', 'sqlalchemy', 'pg_dump', 'asyncpg']
for pkg in packages:
    try:
        mod = __import__(pkg)
        ver = getattr(mod, '__version__', 'unknown')
        print(f"{pkg}: available ({ver})")
    except ImportError as e:
        print(f"{pkg}: NOT available ({e})")

