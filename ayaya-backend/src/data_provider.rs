use std::ops::Range;

use leptos::*;
use leptos_struct_table::*;
use serde::{Deserialize, Serialize};
#[cfg(feature = "ssr")]
use sqlx::{QueryBuilder, Row};

use crate::classes::ClassesPreset;

#[derive(TableRow, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ssr", derive(sqlx::FromRow))]
#[table(classes_provider = ClassesPreset)]
pub struct Event {
    timestamp: ::time::OffsetDateTime,
    username: String,
    groupname: String,
    event: String,
    path: String,
    path_secondary: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceQuery {
    #[serde(default)]
    range: Range<usize>,
    path_query: String,
    start_timestamp: ::time::OffsetDateTime,
}

#[server]
pub async fn list_traces(query: TraceQuery) -> Result<Vec<Event>, ServerFnError<String>> {
    use crate::database::get_db;

    let TraceQuery {
        start_timestamp,
        range,
        path_query,
    } = query;

    let mut query = QueryBuilder::new(
        "SELECT timestamp, username, groupname, event, path, path_secondary FROM events WHERE timestamp <",
    );

    query.push_bind(start_timestamp);

    if !path_query.is_empty() {
        query.push(" AND ( path LIKE concat('%', ");
        query.push_bind(&path_query);
        query.push(", '%') ");

        query.push(" OR path_secondary LIKE concat('%', ");
        query.push_bind(&path_query);
        query.push(", '%') )");
    }

    query.push(" ORDER BY timestamp DESC ");

    query.push(" LIMIT ");
    query.push_bind(range.len() as i64);
    query.push(" OFFSET ");
    query.push_bind(range.start as i64);

    let rows = query
        .build_query_as::<Event>()
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
pub async fn trace_count() -> Result<usize, ServerFnError<String>> {
    use crate::database::get_db;

    let count: i64 = sqlx::query("SELECT COUNT(*) FROM events")
        .fetch_one(get_db())
        .await
        .map_err(|err| ServerFnError::WrappedServerError(format!("{err:?}")))?
        .get(0);

    Ok(count as usize)
}

pub struct AyayaTableDataProvider {
    pub last_uuid: RwSignal<String>,
    pub path_query: RwSignal<String>,
    start_timestamp: ::time::OffsetDateTime,
}

impl Default for AyayaTableDataProvider {
    fn default() -> Self {
        Self {
            last_uuid: Default::default(),
            path_query: Default::default(),
            start_timestamp: ::time::OffsetDateTime::now_local()
                .expect("failed to get local offset"),
        }
    }
}

impl TableDataProvider<Event> for AyayaTableDataProvider {
    async fn get_rows(&self, range: Range<usize>) -> Result<(Vec<Event>, Range<usize>), String> {
        list_traces(TraceQuery {
            path_query: self.path_query.get_untracked().trim().to_string(),
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
        trace_count().await.ok()
    }

    fn track(&self) {
        self.path_query.track();
    }
}
