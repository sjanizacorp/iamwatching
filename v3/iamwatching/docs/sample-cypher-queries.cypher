// ─────────────────────────────────────────────────────────────────────────────
// IamWatching — Sample Cypher Queries for Neo4j Browser
// Run at: http://localhost:7474
// ─────────────────────────────────────────────────────────────────────────────

// 1. All cross-cloud verified links (P0 findings)
MATCH (src)-[e:CROSS_CLOUD_LINK {verified: true}]->(tgt)
RETURN src, e, tgt;

// 2. Full assume-role chain from a specific principal
MATCH path = (p:AWSPrincipal {name: 'developer-role'})-[:CAN_ASSUME*1..5]->(admin)
WHERE admin.name CONTAINS 'Admin'
RETURN path;

// 3. All principals that can reach an admin role (transitive)
MATCH path = (start:AWSPrincipal)-[:CAN_ASSUME*1..4]->(target:AWSPrincipal)
WHERE target.name CONTAINS 'Admin' OR target.name CONTAINS 'admin'
RETURN start.arn AS start, length(path) AS hops, target.arn AS admin_role
ORDER BY hops;

// 4. Lambda functions with cross-cloud credential leaks
MATCH (fn:AWSResource {resource_type: 'lambda:Function'})
      -[e:CROSS_CLOUD_LINK]->(tgt)
RETURN fn.name, fn.arn, e.cred_type, e.target_cloud, e.verified, tgt.identity_hint;

// 5. Azure service principals with Owner role
MATCH (sp:AzurePrincipal {principal_type: 'ServicePrincipal'})
      -[:ASSIGNED_ROLE]->(rd:RoleDefinition)
WHERE rd.role_id CONTAINS 'Owner'
RETURN sp.display_name, sp.object_id, sp.app_id, rd.scope;

// 6. GCP service accounts with TokenCreator on other SAs (impersonation chain)
MATCH (low:GCPPrincipal)-[e:HAS_BINDING]->(res)
WHERE e.role IN ['roles/iam.serviceAccountTokenCreator', 'roles/iam.serviceAccountUser']
RETURN low.email AS can_impersonate_via, e.role, res.resource_id;

// 7. IAM delta events (state changes tracked by Go daemon)
MATCH (e:StateChangeEvent)
RETURN e.account_id, e.added_roles, e.removed_roles, e.modified_roles,
       datetime({epochMillis: e.timestamp}) AS changed_at
ORDER BY e.timestamp DESC
LIMIT 20;

// 8. Resources with env vars (potential secret stores)
MATCH (r:Resource)
WHERE r.has_env_vars = true
RETURN labels(r) AS cloud, r.name, r.resource_type,
       COALESCE(r.arn, r.resource_id) AS id
ORDER BY cloud, r.resource_type;

// 9. Principals with no resource-level permissions (orphaned)
MATCH (p:Principal)
WHERE NOT (p)-[:HAS_PERMISSION]->()
  AND NOT (p)-[:ASSIGNED_ROLE]->()
  AND NOT (p)-[:HAS_BINDING]->()
RETURN labels(p), p.name, COALESCE(p.arn, p.object_id, p.email) AS id;

// 10. Full graph overview
MATCH (n)
RETURN labels(n) AS type, count(n) AS count
ORDER BY count DESC;
