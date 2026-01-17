use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! impl_id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        #[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn nil() -> Self {
                Self(Uuid::nil())
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            pub fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Uuid::parse_str(s)?))
            }
        }

        // Support for tokio-postgres
        impl<'a> tokio_postgres::types::FromSql<'a> for $name {
            fn from_sql(
                ty: &tokio_postgres::types::Type,
                raw: &'a [u8],
            ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
                let uuid = Uuid::from_sql(ty, raw)?;
                Ok(Self(uuid))
            }

            fn accepts(ty: &tokio_postgres::types::Type) -> bool {
                <Uuid as tokio_postgres::types::FromSql>::accepts(ty)
            }
        }

        impl tokio_postgres::types::ToSql for $name {
            fn to_sql(
                &self,
                ty: &tokio_postgres::types::Type,
                out: &mut bytes::BytesMut,
            ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>>
            {
                self.0.to_sql(ty, out)
            }

            fn accepts(ty: &tokio_postgres::types::Type) -> bool {
                <Uuid as tokio_postgres::types::ToSql>::accepts(ty)
            }

            tokio_postgres::types::to_sql_checked!();
        }
    };
}

// Define all our ID types
impl_id_type!(UserId);
impl_id_type!(SessionId);
impl_id_type!(OrganizationId);
impl_id_type!(WorkspaceId);
impl_id_type!(RoleId);
impl_id_type!(PermissionId);
impl_id_type!(WorkspaceMembershipId);
impl_id_type!(DomainVerificationId);
impl_id_type!(AuditLogId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id_creation() {
        let id = UserId::new();
        assert_ne!(id, UserId::nil());
    }

    #[test]
    fn test_session_id_creation() {
        let id = SessionId::new();
        assert_ne!(id, SessionId::nil());
    }

    #[test]
    fn test_id_equality() {
        let uuid = Uuid::new_v4();
        let id1 = UserId(uuid);
        let id2 = UserId(uuid);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_id_conversion() {
        let uuid = Uuid::new_v4();
        let user_id = UserId::from(uuid);
        let back_to_uuid: Uuid = user_id.into();
        assert_eq!(uuid, back_to_uuid);
    }

    #[test]
    fn test_id_display() {
        let uuid = Uuid::new_v4();
        let user_id = UserId(uuid);
        assert_eq!(format!("{user_id}"), format!("{}", uuid));
    }

    #[test]
    fn test_id_parse() {
        let uuid = Uuid::new_v4();
        let uuid_str = uuid.to_string();
        let user_id: UserId = uuid_str.parse().unwrap();
        assert_eq!(user_id.into_uuid(), uuid);
    }
}
