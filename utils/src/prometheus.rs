use std::{
    collections::HashMap,
    io::{self, BufRead, BufReader, Error},
    ops::Deref,
    str::FromStr,
};

use chrono::{DateTime, TimeZone, Utc};
use lazy_static::lazy_static;
use log::info;
use regex::Regex;

use crate::humanize;

// ref. https://github.com/cmars/prometheus-scrape/blob/master/src/lib.rs
// ref. https://github.com/ccakes/prometheus-parse-rs/blob/master/src/lib.rs
lazy_static! {
    static ref HELP_RE: Regex = Regex::new(r"^#\s+HELP\s+(\w+)\s+(.+)$").unwrap();
    static ref TYPE_RE: Regex = Regex::new(r"^#\s+TYPE\s+(\w+)\s+(\w+)").unwrap();
    static ref METRIC_RE: Regex = Regex::new(
        r"^(?P<name>\w+)(\{(?P<labels>[^}]+)\})?\s+(?P<value>\S+)(\s+(?P<timestamp>\S+))?"
    )
    .unwrap();
}

#[derive(Debug, Eq, PartialEq)]
pub enum Entry<'a> {
    Doc {
        metric_name: &'a str,
        doc: &'a str,
    },
    Type {
        metric_name: String,
        sample_type: MetricKind,
    },
    Metric {
        metric_name: &'a str,
        labels: Option<&'a str>,
        value: &'a str,
        timestamp: Option<&'a str>,
    },
    Empty,
    Ignored,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
    Summary,
    Untyped,
}

/// ref. https://doc.rust-lang.org/std/str/trait.FromStr.html
impl FromStr for MetricKind {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = match s {
            "counter" => MetricKind::Counter,
            "gauge" => MetricKind::Gauge,
            "histogram" => MetricKind::Histogram,
            "summary" => MetricKind::Summary,
            _ => MetricKind::Untyped,
        };
        Ok(decoded)
    }
}

impl<'a> Entry<'a> {
    pub fn parse_line(line: &'a str) -> Entry<'a> {
        let line = line.trim();
        if line.is_empty() {
            return Entry::Empty;
        }

        match HELP_RE.captures(line) {
            Some(ref caps) => {
                return match (caps.get(1), caps.get(2)) {
                    (Some(ref metric_name), Some(ref doc)) => Entry::Doc {
                        metric_name: metric_name.as_str(),
                        doc: doc.as_str(),
                    },
                    _ => Entry::Ignored,
                }
            }
            None => {}
        }

        match TYPE_RE.captures(line) {
            Some(ref caps) => {
                return match (caps.get(1), caps.get(2)) {
                    (Some(ref metric_name), Some(ref sample_type)) => {
                        let sample_type = MetricKind::from_str(sample_type.as_str()).unwrap();
                        Entry::Type {
                            metric_name: match sample_type {
                                MetricKind::Histogram => format!("{}_bucket", metric_name.as_str()),
                                _ => metric_name.as_str().to_string(),
                            },
                            sample_type,
                        }
                    }
                    _ => Entry::Ignored,
                }
            }
            None => {}
        }

        match METRIC_RE.captures(line) {
            Some(ref caps) => {
                return match (
                    caps.name("name"),
                    caps.name("labels"),
                    caps.name("value"),
                    caps.name("timestamp"),
                ) {
                    (Some(ref name), labels, Some(ref value), timestamp) => Entry::Metric {
                        metric_name: name.as_str(),
                        labels: labels.map(|c| c.as_str()),
                        value: value.as_str(),
                        timestamp: timestamp.map(|c| c.as_str()),
                    },
                    _ => Entry::Ignored,
                }
            }
            None => Entry::Ignored,
        }
    }
}

#[test]
fn test_lineinfo_parse() {
    assert_eq!(
        Entry::parse_line("foo 2"),
        Entry::Metric {
            metric_name: "foo",
            value: "2",
            labels: None,
            timestamp: None,
        }
    );
    assert_eq!(
        Entry::parse_line("foo wtf -1"),
        Entry::Metric {
            metric_name: "foo",
            value: "wtf",
            labels: None,
            timestamp: Some("-1"),
        }
    );
    assert_eq!(Entry::parse_line("foo=2"), Entry::Ignored,);
    assert_eq!(
        Entry::parse_line("foo 2 1543182234"),
        Entry::Metric {
            metric_name: "foo",
            value: "2",
            labels: None,
            timestamp: Some("1543182234"),
        }
    );
    assert_eq!(
        Entry::parse_line("foo{bar=baz} 2 1543182234"),
        Entry::Metric {
            metric_name: "foo",
            value: "2",
            labels: Some("bar=baz"),
            timestamp: Some("1543182234"),
        }
    );
    assert_eq!(
        Entry::parse_line("foo{bar=baz,quux=nonce} 2 1543182234"),
        Entry::Metric {
            metric_name: "foo",
            value: "2",
            labels: Some("bar=baz,quux=nonce"),
            timestamp: Some("1543182234"),
        }
    );
    assert_eq!(
        Entry::parse_line("# HELP foo this is a docstring"),
        Entry::Doc {
            metric_name: "foo",
            doc: "this is a docstring"
        },
    );
    assert_eq!(
        Entry::parse_line("# TYPE foobar bazquux"),
        Entry::Type {
            metric_name: "foobar".to_string(),
            sample_type: MetricKind::Untyped,
        },
    );
}

#[derive(Debug, PartialEq, Clone)]
pub struct Metric {
    pub metric: String,
    pub value: Value,
    pub labels: Option<Labels>,
    pub timestamp: Option<DateTime<Utc>>,
}

impl Default for Metric {
    fn default() -> Self {
        Self::default()
    }
}

impl Metric {
    pub fn default() -> Self {
        Self {
            metric: String::new(),
            value: Value::Untyped(0.0),
            labels: None,
            timestamp: None,
        }
    }
}

fn parse_bucket(s: &str, label: &str) -> Option<f64> {
    if let Some(kv) = s.split(',').next() {
        let kvpair = kv.split('=').collect::<Vec<_>>();
        let (k, v) = (kvpair[0], kvpair[1].trim_matches('"'));
        if k == label {
            match parse_golang_float(v) {
                Ok(v) => Some(v),
                Err(_) => None,
            }
        } else {
            None
        }
    } else {
        None
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct HistogramCount {
    pub less_than: f64,
    pub count: f64,
}

#[derive(Debug, PartialEq, Clone)]
pub struct SummaryCount {
    pub quantile: f64,
    pub count: f64,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Labels(HashMap<String, String>);

impl Labels {
    fn from_str(s: &str) -> Labels {
        let mut l = HashMap::new();
        for kv in s.split(',') {
            let kvpair = kv.split('=').collect::<Vec<_>>();
            if kvpair.len() != 2 || kvpair[0].is_empty() {
                continue;
            }
            l.insert(
                kvpair[0].to_string(),
                kvpair[1].trim_matches('"').to_string(),
            );
        }
        Labels(l)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(|x| x.as_str())
    }
}

impl Deref for Labels {
    type Target = HashMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[test]
fn test_labels_parse() {
    assert_eq!(
        Labels::from_str("foo=bar"),
        Labels([("foo", "bar")].iter().map(pair_to_string).collect())
    );
    assert_eq!(
        Labels::from_str("foo=bar,"),
        Labels([("foo", "bar")].iter().map(pair_to_string).collect())
    );
    assert_eq!(
        Labels::from_str(",foo=bar,"),
        Labels([("foo", "bar")].iter().map(pair_to_string).collect())
    );
    assert_eq!(
        Labels::from_str("=,foo=bar,"),
        Labels([("foo", "bar")].iter().map(pair_to_string).collect())
    );
    assert_eq!(
        Labels::from_str(r#"foo="bar""#),
        Labels([("foo", "bar")].iter().map(pair_to_string).collect())
    );
    assert_eq!(
        Labels::from_str(r#"foo="bar",baz="quux""#),
        Labels(
            [("foo", "bar"), ("baz", "quux")]
                .iter()
                .map(pair_to_string)
                .collect()
        )
    );
    assert_eq!(
        Labels::from_str(r#"foo="foo bar",baz="baz quux""#),
        Labels(
            [("foo", "foo bar"), ("baz", "baz quux")]
                .iter()
                .map(pair_to_string)
                .collect()
        )
    );
    assert_eq!(Labels::from_str("==="), Labels(HashMap::new()),);
}

#[derive(Debug, PartialEq, Clone)]
pub enum Value {
    Counter(f64),
    Gauge(f64),
    Histogram(Vec<HistogramCount>),
    Summary(Vec<SummaryCount>),
    Untyped(f64),
}

impl Value {
    pub fn to_f64(&self) -> f64 {
        match self {
            Value::Counter(v) => *v,
            Value::Gauge(v) => *v,
            Value::Untyped(v) => *v,

            // TODO: fix this
            Value::Histogram(_) => 0.0,
            Value::Summary(_) => 0.0,
        }
    }

    fn push_histogram(&mut self, h: HistogramCount) {
        if let &mut Value::Histogram(ref mut hs) = self {
            hs.push(h)
        }
    }

    fn push_summary(&mut self, s: SummaryCount) {
        if let &mut Value::Summary(ref mut ss) = self {
            ss.push(s)
        }
    }
}

#[derive(Debug)]
pub struct Scrape {
    pub docs: HashMap<String, String>,
    pub metrics: Vec<Metric>,
}

impl Scrape {
    pub fn from_bytes(d: &[u8]) -> io::Result<Self> {
        info!("scraping {} bytes", humanize::bytes(d.len() as f64));
        let br = BufReader::new(d);
        Self::parse(br.lines())
    }

    pub fn parse(lines: impl Iterator<Item = io::Result<String>>) -> io::Result<Self> {
        let mut docs: HashMap<String, String> = HashMap::new();
        let mut types: HashMap<String, MetricKind> = HashMap::new();
        let mut buckets: HashMap<String, Metric> = HashMap::new();
        let mut samples: Vec<Metric> = vec![];
        for line in lines {
            let cur = match line {
                Ok(v) => v,
                Err(e) => return Err(e),
            };

            match Entry::parse_line(&cur) {
                Entry::Doc {
                    ref metric_name,
                    ref doc,
                } => {
                    docs.insert(metric_name.to_string(), doc.to_string());
                }
                Entry::Type {
                    ref metric_name,
                    ref sample_type,
                } => {
                    types.insert(metric_name.to_string(), *sample_type);
                }
                Entry::Metric {
                    metric_name,
                    ref labels,
                    value,
                    timestamp,
                } => {
                    // Parse value or skip
                    let fvalue = if let Ok(v) = parse_golang_float(value) {
                        v
                    } else {
                        continue;
                    };
                    // Parse timestamp or use given sample time
                    let timestamp = if let Some(Ok(ts_millis)) = timestamp.map(|x| x.parse::<i64>())
                    {
                        Some(Utc.timestamp_millis(ts_millis))
                    } else {
                        None
                    };
                    match (types.get(metric_name), labels) {
                        (Some(MetricKind::Histogram), Some(labels)) => {
                            if let Some(lt) = parse_bucket(labels, "le") {
                                let sample =
                                    buckets.entry(metric_name.to_string()).or_insert(Metric {
                                        metric: metric_name.to_string(),
                                        labels: None,
                                        value: Value::Histogram(vec![]),
                                        timestamp,
                                    });
                                sample.value.push_histogram(HistogramCount {
                                    less_than: lt,
                                    count: fvalue,
                                })
                            }
                        }
                        (Some(MetricKind::Summary), Some(labels)) => {
                            if let Some(q) = parse_bucket(labels, "quantile") {
                                let sample =
                                    buckets.entry(metric_name.to_string()).or_insert(Metric {
                                        metric: metric_name.to_string(),
                                        labels: None,
                                        value: Value::Summary(vec![]),
                                        timestamp,
                                    });
                                sample.value.push_summary(SummaryCount {
                                    quantile: q,
                                    count: fvalue,
                                })
                            }
                        }
                        (ty, labels) => {
                            let labels = {
                                if labels.is_some() {
                                    Some(Labels::from_str(labels.unwrap()))
                                } else {
                                    None
                                }
                            };
                            samples.push(Metric {
                                metric: metric_name.to_string(),
                                labels,
                                value: match ty {
                                    Some(MetricKind::Counter) => Value::Counter(fvalue),
                                    Some(MetricKind::Gauge) => Value::Gauge(fvalue),
                                    _ => Value::Untyped(fvalue),
                                },
                                timestamp,
                            });
                        }
                    };
                }
                _ => {}
            }
        }
        samples.extend(buckets.drain().map(|(_k, v)| v).collect::<Vec<_>>());
        Ok(Scrape {
            docs,
            metrics: samples,
        })
    }
}

#[test]
fn test_parse_samples() {
    let scrape = r#"
# HELP http_requests_total The total number of HTTP requests.
# TYPE http_requests_total counter
http_requests_total{method="post",code="200"} 1027 1395066363000
http_requests_total{method="post",code="400"}    3 1395066363000

# Escaping in label values:
msdos_file_access_time_seconds{path="C:\\DIR\\FILE.TXT",error="Cannot find file:\n\"FILE.TXT\""} 1.458255915e9

# Minimalistic line:
metric_without_timestamp_and_labels 12.47

# TYPE metric_counter_with_no_label counter
metric_counter_with_no_label 100.10

# A weird metric from before the epoch:
something_weird{problem="division by zero"} +Inf -3982045

# A histogram, which has a pretty complex representation in the text format:
# HELP http_request_duration_seconds A histogram of the request duration.
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{le="0.05"} 24054
http_request_duration_seconds_bucket{le="0.1"} 33444
http_request_duration_seconds_bucket{le="0.2"} 100392
http_request_duration_seconds_bucket{le="0.5"} 129389
http_request_duration_seconds_bucket{le="1"} 133988
http_request_duration_seconds_bucket{le="+Inf"} 144320
http_request_duration_seconds_sum 53423
http_request_duration_seconds_count 144320

# Finally a summary, which has a complex representation, too:
# HELP rpc_duration_seconds A summary of the RPC duration in seconds.
# TYPE rpc_duration_seconds summary
rpc_duration_seconds{quantile="0.01"} 3102
rpc_duration_seconds{quantile="0.05"} 3272
rpc_duration_seconds{quantile="0.5"} 4773
rpc_duration_seconds{quantile="0.9"} 9001
rpc_duration_seconds{quantile="0.99"} 76656
rpc_duration_seconds_sum 1.7560473e+07
rpc_duration_seconds_count 2693
"#;

    let s = Scrape::from_bytes(scrape.as_bytes()).unwrap();
    assert_eq!(s.metrics.len(), 12);

    assert_eq!(
        match_metric(&s.metrics, |s| s.metric
            == "metric_without_timestamp_and_labels"),
        &Metric {
            metric: "metric_without_timestamp_and_labels".to_string(),
            value: Value::Untyped(12.47),
            labels: None,
            timestamp: None,
        }
    );

    assert_eq!(
        match_metric(&s.metrics, |s| s.metric == "metric_counter_with_no_label"),
        &Metric {
            metric: "metric_counter_with_no_label".to_string(),
            value: Value::Counter(100.10),
            labels: None,
            timestamp: None,
        }
    );

    assert_eq!(
        match_metric(&s.metrics, |s| s.metric == "http_requests_total"
            && s.labels.clone().unwrap().get("code") == Some("200")),
        &Metric {
            metric: "http_requests_total".to_string(),
            value: Value::Counter(1027f64),
            labels: Some(Labels(
                [("method", "post"), ("code", "200")]
                    .iter()
                    .map(pair_to_string)
                    .collect()
            )),
            timestamp: Some(Utc.timestamp_millis(1395066363000)),
        }
    );

    assert_eq!(
        match_metric(&s.metrics, |s| s.metric == "http_requests_total"
            && s.labels.clone().unwrap().get("code") == Some("400")),
        &Metric {
            metric: "http_requests_total".to_string(),
            value: Value::Counter(3f64),
            labels: Some(Labels(
                [("method", "post"), ("code", "400")]
                    .iter()
                    .map(pair_to_string)
                    .collect()
            )),
            timestamp: Some(Utc.timestamp_millis(1395066363000)),
        }
    );
}

lazy_static! {
    static ref NOT_FOUND_METRIC: Metric = Metric {
        metric: "not_found".to_string(),
        value: Value::Gauge(0.0),
        labels: None,
        timestamp: None
    };
}

pub fn match_metric<'a, F>(samples: &'a [Metric], f: F) -> &'a Metric
where
    for<'r> F: FnMut(&'r &'a Metric) -> bool,
{
    let metric = samples.iter().find(f);
    if let Some(v) = metric {
        return v;
    }
    &NOT_FOUND_METRIC
}

pub fn pair_to_string(pair: &(&str, &str)) -> (String, String) {
    (pair.0.to_string(), pair.1.to_string())
}

fn parse_golang_float(s: &str) -> Result<f64, <f64 as std::str::FromStr>::Err> {
    match s.to_lowercase().as_str() {
        "nan" => Ok(std::f64::NAN), // f64::parse doesn't recognize 'nan'
        s => s.parse::<f64>(),      // f64::parse expects lowercase [+-]inf
    }
}

#[test]
fn test_golang_float() {
    assert_eq!(parse_golang_float("1.0"), Ok(1.0f64));
    assert_eq!(parse_golang_float("-1.0"), Ok(-1.0f64));
    assert!(parse_golang_float("NaN").unwrap().is_nan());
    assert_eq!(parse_golang_float("Inf"), Ok(std::f64::INFINITY));
    assert_eq!(parse_golang_float("+Inf"), Ok(std::f64::INFINITY));
    assert_eq!(parse_golang_float("-Inf"), Ok(std::f64::NEG_INFINITY));
}
