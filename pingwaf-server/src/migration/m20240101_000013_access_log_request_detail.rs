//! Stores the full request (headers and a body prefix) on `access_logs` rows so
//! operators can inspect requests from the dashboard without Elasticsearch.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum AccessLogs {
    Table,
    RequestHeaders,
    RequestBody,
    RequestBodySize,
    RequestBodyTruncated,
    RequestId,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(AccessLogs::Table)
                    .add_column(
                        ColumnDef::new(AccessLogs::RequestHeaders)
                            .json_binary()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(AccessLogs::RequestBody).text().null(),
                    )
                    .add_column(
                        ColumnDef::new(AccessLogs::RequestBodySize)
                            .big_integer()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(AccessLogs::RequestBodyTruncated)
                            .boolean()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_access_logs_request_id")
                    .table(AccessLogs::Table)
                    .col(AccessLogs::RequestId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_access_logs_request_id")
                    .table(AccessLogs::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(AccessLogs::Table)
                    .drop_column(AccessLogs::RequestHeaders)
                    .drop_column(AccessLogs::RequestBody)
                    .drop_column(AccessLogs::RequestBodySize)
                    .drop_column(AccessLogs::RequestBodyTruncated)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
