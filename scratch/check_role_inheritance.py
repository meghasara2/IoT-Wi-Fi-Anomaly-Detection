# Test PostgreSQL role inheritance rules
# In PostgreSQL documentation:
# "The INHERIT attribute governs whether a role automatically inherits the privileges of roles it is a member of."
# If role A is granted to role B:
# If role B has INHERIT, B gets privileges of A.
# But if role A has NOINHERIT, does B inherit A's privileges?
# In PostgreSQL:
# CREATE ROLE parent; (default is INHERIT)
# CREATE ROLE child IN ROLE parent; (default is INHERIT)
# If parent has NOINHERIT, does child inherit?
# In PG docs: "The NOINHERIT attribute on a role only affects membership grants where the member role is the one with NOINHERIT."
# But setting NOINHERIT on the parent role does NOT prevent child from inheriting IF child has INHERIT,
# HOWEVER: To avoid ambiguity in Supabase and PostgreSQL, both roles should be explicitly configured:
# CREATE ROLE collector_role NOLOGIN;
# CREATE USER iot_collector WITH PASSWORD '...' INHERIT;
# GRANT collector_role TO iot_collector;
print("Role inheritance check documented.")

