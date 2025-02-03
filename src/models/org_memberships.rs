use crate::models::schema::org_memberships;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum OrgMembershipError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] diesel::result::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OrgRole {
    Owner,
    Admin,
    Developer,
    Viewer,
}

impl OrgRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrgRole::Owner => "owner",
            OrgRole::Admin => "admin",
            OrgRole::Developer => "developer",
            OrgRole::Viewer => "viewer",
        }
    }
}

impl From<String> for OrgRole {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "owner" => OrgRole::Owner,
            "admin" => OrgRole::Admin,
            "developer" => OrgRole::Developer,
            "viewer" => OrgRole::Viewer,
            _ => OrgRole::Viewer, // Default to lowest privilege
        }
    }
}

#[derive(Queryable, Identifiable, AsChangeset, Serialize, Deserialize, Clone, Debug)]
#[diesel(table_name = org_memberships)]
pub struct OrgMembership {
    pub id: i32,
    pub platform_user_id: Uuid,
    pub org_id: i32,
    #[serde(with = "role_string")]
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Custom serialization for role field
mod role_string {
    use super::OrgRole;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(role: &str, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let role_enum: OrgRole = role.to_owned().into();
        role_enum.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let role_enum = OrgRole::deserialize(deserializer)?;
        Ok(role_enum.as_str().to_string())
    }
}

impl OrgMembership {
    pub fn get_by_id(
        conn: &mut PgConnection,
        lookup_id: i32,
    ) -> Result<Option<OrgMembership>, OrgMembershipError> {
        org_memberships::table
            .filter(org_memberships::id.eq(lookup_id))
            .first::<OrgMembership>(conn)
            .optional()
            .map_err(OrgMembershipError::DatabaseError)
    }

    pub fn get_by_platform_user_and_org(
        conn: &mut PgConnection,
        lookup_platform_user_id: Uuid,
        lookup_org_id: i32,
    ) -> Result<OrgMembership, OrgMembershipError> {
        org_memberships::table
            .filter(org_memberships::platform_user_id.eq(lookup_platform_user_id))
            .filter(org_memberships::org_id.eq(lookup_org_id))
            .first::<OrgMembership>(conn)
            .map_err(OrgMembershipError::DatabaseError)
    }

    pub fn get_all_for_platform_user(
        conn: &mut PgConnection,
        lookup_platform_user_id: Uuid,
    ) -> Result<Vec<OrgMembership>, OrgMembershipError> {
        org_memberships::table
            .filter(org_memberships::platform_user_id.eq(lookup_platform_user_id))
            .load::<OrgMembership>(conn)
            .map_err(OrgMembershipError::DatabaseError)
    }

    pub fn get_all_for_org(
        conn: &mut PgConnection,
        lookup_org_id: i32,
    ) -> Result<Vec<OrgMembership>, OrgMembershipError> {
        org_memberships::table
            .filter(org_memberships::org_id.eq(lookup_org_id))
            .load::<OrgMembership>(conn)
            .map_err(OrgMembershipError::DatabaseError)
    }

    pub fn update(&self, conn: &mut PgConnection) -> Result<(), OrgMembershipError> {
        diesel::update(org_memberships::table)
            .filter(org_memberships::id.eq(self.id))
            .set((
                org_memberships::role.eq(&self.role),
                org_memberships::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .map(|_| ())
            .map_err(OrgMembershipError::DatabaseError)
    }

    pub fn delete(&self, conn: &mut PgConnection) -> Result<(), OrgMembershipError> {
        diesel::delete(org_memberships::table)
            .filter(org_memberships::id.eq(self.id))
            .execute(conn)
            .map(|_| ())
            .map_err(OrgMembershipError::DatabaseError)
    }

    pub fn get_role(&self) -> OrgRole {
        self.role.clone().into()
    }

    pub fn update_role_with_owner_check(
        conn: &mut PgConnection,
        membership: &mut OrgMembership,
        new_role: OrgRole,
    ) -> Result<(), OrgMembershipError> {
        // Start transaction
        conn.transaction(|conn| {
            // If changing from owner role, check if this is the last owner
            if membership.role == OrgRole::Owner.as_str() && new_role != OrgRole::Owner {
                // Lock the memberships for this org to prevent concurrent modifications
                let owner_count: i64 = org_memberships::table
                    .filter(org_memberships::org_id.eq(membership.org_id))
                    .filter(org_memberships::role.eq(OrgRole::Owner.as_str()))
                    .for_update() // This locks the rows
                    .count()
                    .get_result(conn)?;

                if owner_count <= 1 {
                    return Err(OrgMembershipError::DatabaseError(
                        diesel::result::Error::RollbackTransaction,
                    ));
                }
            }

            // Update the role
            membership.role = new_role.as_str().to_string();
            diesel::update(org_memberships::table)
                .filter(org_memberships::id.eq(membership.id))
                .set((
                    org_memberships::role.eq(&membership.role),
                    org_memberships::updated_at.eq(diesel::dsl::now),
                ))
                .execute(conn)?;

            Ok(())
        })
    }

    pub fn delete_with_owner_check(
        conn: &mut PgConnection,
        membership: &OrgMembership,
    ) -> Result<(), OrgMembershipError> {
        // Start transaction
        conn.transaction(|conn| {
            // If deleting an owner, check if this is the last owner
            if membership.role == OrgRole::Owner.as_str() {
                // Lock the memberships for this org to prevent concurrent modifications
                let owner_count: i64 = org_memberships::table
                    .filter(org_memberships::org_id.eq(membership.org_id))
                    .filter(org_memberships::role.eq(OrgRole::Owner.as_str()))
                    .for_update() // This locks the rows
                    .count()
                    .get_result(conn)?;

                if owner_count <= 1 {
                    return Err(OrgMembershipError::DatabaseError(
                        diesel::result::Error::RollbackTransaction,
                    ));
                }
            }

            // Delete the membership
            diesel::delete(org_memberships::table)
                .filter(org_memberships::id.eq(membership.id))
                .execute(conn)?;

            Ok(())
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = org_memberships)]
pub struct NewOrgMembership {
    pub platform_user_id: Uuid,
    pub org_id: i32,
    pub role: String,
}

impl NewOrgMembership {
    pub fn new(platform_user_id: Uuid, org_id: i32, role: OrgRole) -> Self {
        NewOrgMembership {
            platform_user_id,
            org_id,
            role: role.as_str().to_string(),
        }
    }

    pub fn insert(&self, conn: &mut PgConnection) -> Result<OrgMembership, OrgMembershipError> {
        diesel::insert_into(org_memberships::table)
            .values(self)
            .get_result::<OrgMembership>(conn)
            .map_err(OrgMembershipError::DatabaseError)
    }
}
