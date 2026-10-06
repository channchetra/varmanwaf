//! Stores the response side of every proxied request (headers, a body prefix
//! and the real sizes) plus the request scheme/protocol on `access_logs` rows,
//! so the dashboard can replay a full request–response pair without
//! Elasticsearch.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum AccessLogs {
    Table,
    Scheme,
    Protocol,
    ResponseHeaders,
    ResponseBody,
    ResponseBodySize,
    ResponseBodyTruncated,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(AccessLogs::Table)
                    .add_column(
                        ColumnDef::new(AccessLogs::Scheme)
                            .string_len(10)
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(AccessLogs::Protocol)
                            .string_len(20)
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(AccessLogs::ResponseHeaders)
                            .json_binary()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(AccessLogs::ResponseBody).text().null(),
                    )
                    .add_column(
                        ColumnDef::new(AccessLogs::ResponseBodySize)
                            .big_integer()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(AccessLogs::ResponseBodyTruncated)
                            .boolean()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(AccessLogs::Table)
                    .drop_column(AccessLogs::Scheme)
                    .drop_column(AccessLogs::Protocol)
                    .drop_column(AccessLogs::ResponseHeaders)
                    .drop_column(AccessLogs::ResponseBody)
                    .drop_column(AccessLogs::ResponseBodySize)
                    .drop_column(AccessLogs::ResponseBodyTruncated)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
