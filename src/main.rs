use chrono::{DateTime, Utc};
use reqwest::Client;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::sync::OnceLock;
use std::time::Instant;
use tokio::task::JoinHandle;

const CREDIT_FILE: &str = "credit.txt";
const TWO_PART_TLDS_FILE: &str = "2part.txt";
const BLOCKLIST_FILE: &str = "blocklist.txt";
const ALLOWLIST_FILE: &str = "allowlist.txt";
const PROJECT_URL: &str = "https://github.com/Tahosol/blist-v2";

static TWO_PART_TLDS: OnceLock<HashSet<String>> = OnceLock::new();

#[derive(Debug, Clone, Eq, PartialEq)]
enum Entry {
    Block(String),
    Allow(String),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let started_at = Instant::now();
    let urls = read_sources(CREDIT_FILE)?;
    let client = Client::new();
    let fetched_lists = fetch_sources(&client, urls).await;

    let (blocklist, allowlist) = build_lists(&fetched_lists);

    fs::write(BLOCKLIST_FILE, blocklist)?;
    fs::write(ALLOWLIST_FILE, allowlist)?;

    println!("Done after {:.2?}", started_at.elapsed());
    Ok(())
}

async fn fetch_sources(client: &Client, urls: Vec<String>) -> Vec<String> {
    let handles: Vec<JoinHandle<Option<String>>> = urls
        .into_iter()
        .map(|url| {
            let client = client.clone();
            tokio::spawn(async move {
                match fetch_url(&client, &url).await {
                    Ok(content) => Some(content),
                    Err(error) => {
                        eprintln!("Error fetching {url}: {error}");
                        None
                    }
                }
            })
        })
        .collect();

    let mut lists = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(Some(content)) => lists.push(content),
            Ok(None) => {}
            Err(error) => eprintln!("Fetch task failed: {error}"),
        }
    }

    lists
}

async fn fetch_url(client: &Client, url: &str) -> Result<String, reqwest::Error> {
    client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}

fn read_sources(path: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let contents = fs::read_to_string(path)?;
    let urls = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect();

    Ok(urls)
}

fn build_lists(contents: &[String]) -> (String, String) {
    let started_at = Instant::now();
    let generated_at = Utc::now();
    let mut blocks = HashSet::new();
    let mut allows = HashSet::new();

    for line in contents.iter().flat_map(|content| content.lines()) {
        match parse_entry(line) {
            Some(Entry::Block(domain)) => {
                blocks.insert(domain);
            }
            Some(Entry::Allow(domain)) => {
                allows.insert(domain);
            }
            None => {}
        }
    }

    remove_redundant_subdomains(&mut blocks);

    let blocklist = render_blocklist(&blocks, generated_at);
    let allowlist = render_allowlist(&allows, generated_at);

    println!("Merged in {:.2?}", started_at.elapsed());
    (blocklist, allowlist)
}

fn parse_entry(line: &str) -> Option<Entry> {
    let line = strip_inline_comment(line);
    let line = line.trim();

    if line.is_empty() || is_comment(line) {
        return None;
    }

    if let Some(rule) = line.strip_prefix("@@") {
        return parse_adblock_domain(rule).map(Entry::Allow);
    }

    if line.starts_with('/') || line.starts_with('|') && !line.starts_with("||") {
        return None;
    }

    if let Some(rule) = line.strip_prefix("||") {
        return parse_adblock_domain(rule).map(Entry::Block);
    }

    parse_hosts_or_domain(line).map(Entry::Block)
}

fn strip_inline_comment(line: &str) -> &str {
    line.split_once(" #")
        .map_or(line, |(before_comment, _)| before_comment)
}

fn is_comment(line: &str) -> bool {
    line.starts_with('!') || line.starts_with('#') || line.starts_with('[')
}

fn parse_hosts_or_domain(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    let first = parts.next()?;

    if is_ip_address(first) {
        return parts.next().and_then(normalize_domain);
    }

    normalize_domain(first)
}

fn parse_adblock_domain(rule: &str) -> Option<String> {
    let domain = rule
        .split(['^', '$'])
        .next()
        .unwrap_or_default()
        .trim_start_matches('|');

    normalize_domain(domain)
}

fn normalize_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();

    if is_valid_domain(&domain) {
        Some(domain)
    } else {
        None
    }
}

fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty()
        || domain.len() > 253
        || domain.contains('*')
        || domain.contains('/')
        || domain.contains(':')
        || domain.contains('@')
        || domain.contains('_')
        || !domain.contains('.')
    {
        return false;
    }

    domain.split('.').all(is_valid_label)
}

fn is_valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_ip_address(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

fn remove_redundant_subdomains(domains: &mut HashSet<String>) {
    let redundant: Vec<String> = domains
        .iter()
        .filter(|domain| {
            let root_domain = root_domain(domain);
            root_domain != **domain && domains.contains(&root_domain)
        })
        .cloned()
        .collect();

    for domain in redundant {
        domains.remove(&domain);
    }
}

fn root_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return domain.to_owned();
    }

    let suffix = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    if two_part_tlds().contains(&suffix) && parts.len() >= 3 {
        format!("{}.{}", parts[parts.len() - 3], suffix)
    } else {
        suffix
    }
}

fn two_part_tlds() -> &'static HashSet<String> {
    TWO_PART_TLDS.get_or_init(|| {
        fs::read_to_string(TWO_PART_TLDS_FILE)
            .expect("failed to read two-part TLD list")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| line.to_ascii_lowercase())
            .collect()
    })
}

fn render_blocklist(domains: &HashSet<String>, generated_at: DateTime<Utc>) -> String {
    let mut lines = header("Blocklist: Blist", generated_at);
    lines.extend(sorted(domains));
    lines.join("\n")
}

fn render_allowlist(domains: &HashSet<String>, generated_at: DateTime<Utc>) -> String {
    let mut lines = header("Allowlist: Blist", generated_at);
    lines.extend(sorted(domains));
    lines.join("\n")
}

fn header(title: &str, generated_at: DateTime<Utc>) -> Vec<String> {
    vec![
        format!("# {title}"),
        format!("# Last modified: {}", generated_at.to_rfc3339()),
        format!("# More info: {PROJECT_URL}"),
    ]
}

fn sorted(domains: &HashSet<String>) -> Vec<String> {
    let mut domains: Vec<String> = domains.iter().cloned().collect();
    domains.sort_unstable();
    domains
}
