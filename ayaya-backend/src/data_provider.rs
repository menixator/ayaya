use std::{collections::VecDeque, ops::Range};

use leptos::*;
use leptos_struct_table::*;
use serde::{Deserialize, Serialize};
#[cfg(feature = "ssr")]
use sqlx::{QueryBuilder, Row};

use crate::classes::ClassesPreset;

#[derive(TableRow, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ssr", derive(sqlx::FromRow))]
#[table(classes_provider = ClassesPreset)]
pub struct Customer {
    timestamp: ::time::OffsetDateTime,
    username: String,
    groupname: String,
    event: String,
    path: String,
    path_secondary: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomerQuery {
    #[serde(default)]
    sort: VecDeque<(usize, ColumnSort)>,
    range: Range<usize>,
    name: String,
    start_timestamp: ::time::OffsetDateTime,
}

#[server]
pub async fn list_customers(query: CustomerQuery) -> Result<Vec<Customer>, ServerFnError<String>> {
    use crate::database::get_db;

    let CustomerQuery {
        start_timestamp,
        sort,
        range,
        name,
    } = query;

    let mut query = QueryBuilder::new(
        "SELECT timestamp, username, groupname, event, path, path_secondary FROM events WHERE timestamp <",
    );

    query.push_bind(start_timestamp);

    query.push(" ORDER BY timestamp DESC ");

    query.push(" LIMIT ");
    query.push_bind(range.len() as i64);
    query.push(" OFFSET ");
    query.push_bind(range.start as i64);

    let rows = query
        .build_query_as::<Customer>()
        .fetch_all(get_db())
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|mut row| {
                    row.timestamp = row.timestamp.to_offset(start_timestamp.offset());
                    row
                })
                .collect()
        })
        .map_err(|e| ServerFnError::WrappedServerError(format!("{e:?}")))?;

    Ok(rows)
}

#[server]
pub async fn customer_count() -> Result<usize, ServerFnError<String>> {
    use crate::database::get_db;

    let count: i64 = sqlx::query("SELECT COUNT(*) FROM events")
        .fetch_one(get_db())
        .await
        .map_err(|err| ServerFnError::WrappedServerError(format!("{err:?}")))?
        .get(0);

    Ok(count as usize)
}

pub struct CustomerTableDataProvider {
    sort: VecDeque<(usize, ColumnSort)>,
    pub last_uuid: RwSignal<String>,
    pub name: RwSignal<String>,
    start_timestamp: ::time::OffsetDateTime,
}

impl Default for CustomerTableDataProvider {
    fn default() -> Self {
        Self {
            sort: Default::default(),
            last_uuid: Default::default(),
            name: Default::default(),
            start_timestamp: ::time::OffsetDateTime::now_local()
                .expect("failed to get local offset"),
        }
    }
}

impl TableDataProvider<Customer> for CustomerTableDataProvider {
    async fn get_rows(&self, range: Range<usize>) -> Result<(Vec<Customer>, Range<usize>), String> {
        list_customers(CustomerQuery {
            name: self.name.get_untracked().trim().to_string(),
            sort: self.sort.clone(),
            range: range.clone(),
            start_timestamp: self.start_timestamp,
        })
        .await
        .map(|rows| {
            let len = rows.len();
            (rows, range.start..range.start + len)
        })
        .map_err(|e| format!("{e:?}"))
    }

    async fn row_count(&self) -> Option<usize> {
        customer_count().await.ok()
    }

    fn set_sorting(&mut self, sorting: &VecDeque<(usize, ColumnSort)>) {
        self.sort = sorting.clone();
    }

    fn track(&self) {
        self.name.track();
    }
}
