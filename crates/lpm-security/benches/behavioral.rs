//! Benchmarks for behavioral analysis, query resolution, and entropy calculation.
//!
//! Run: `cargo bench -p lpm-security`
//!
//! Performance budget (from phase-25-todo.md):
//! - analyze_package (100 files, 500KB): < 100ms
//! - Shannon entropy, 1000 strings: < 5ms
//! - Regex compilation (OnceLock): < 10ms (one-time)
//! - Query ":eval" on 1000-package lockfile: < 500ms

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tempfile::TempDir;

/// Create a temporary package directory with N source files for benchmarking.
fn create_test_package(num_files: usize, lines_per_file: usize) -> TempDir {
	let dir = TempDir::new().unwrap();

	// Write package.json
	let pkg_json = serde_json::json!({
		"name": "bench-package",
		"version": "1.0.0",
		"license": "MIT",
		"dependencies": {
			"express": "^4.0.0",
			"lodash": "^4.17.0"
		}
	});
	std::fs::write(dir.path().join("package.json"), pkg_json.to_string()).unwrap();

	// Write source files with varied content
	let src_dir = dir.path().join("src");
	std::fs::create_dir_all(&src_dir).unwrap();

	for i in 0..num_files {
		let mut content = String::with_capacity(lines_per_file * 50);
		content.push_str(&format!("// File {i}\n"));
		content.push_str("import fs from \"fs\"\n");
		content.push_str("import { createHash } from \"crypto\"\n");

		if i % 5 == 0 {
			content.push_str("const result = eval(code)\n");
		}
		if i % 7 == 0 {
			content.push_str("fetch(\"https://api.example.com/data\")\n");
		}
		if i % 10 == 0 {
			content.push_str("process.env.SECRET_KEY\n");
		}

		for j in 0..lines_per_file {
			content.push_str(&format!(
				"const value_{j} = computeSomething({j}, \"{i}\")\n"
			));
		}

		content.push_str("module.exports = { main }\n");

		std::fs::write(src_dir.join(format!("module_{i}.js")), &content).unwrap();
	}

	dir
}

fn bench_analyze_package(c: &mut Criterion) {
	let dir = create_test_package(100, 20);

	c.bench_function("analyze_package_100_files", |b| {
		b.iter(|| {
			lpm_security::behavioral::analyze_package(black_box(dir.path()))
		})
	});
}

fn bench_analyze_package_small(c: &mut Criterion) {
	let dir = create_test_package(10, 10);

	c.bench_function("analyze_package_10_files", |b| {
		b.iter(|| {
			lpm_security::behavioral::analyze_package(black_box(dir.path()))
		})
	});
}

fn bench_shannon_entropy(c: &mut Criterion) {
	// Generate 1000 random-ish strings
	let strings: Vec<String> = (0..1000)
		.map(|i| format!("aB3xZ9qW{i}mK7pL2nR5sT8vY1cF4gH6jD0eU"))
		.collect();

	c.bench_function("shannon_entropy_1000_strings", |b| {
		b.iter(|| {
			for s in &strings {
				let _ = black_box(lpm_security::behavioral::supply_chain::shannon_entropy(
					s.as_bytes(),
				));
			}
		})
	});
}

fn bench_source_tag_analysis(c: &mut Criterion) {
	let source = r#"
		import fs from "fs"
		import { exec } from "child_process"
		import { createHash } from "crypto"

		const data = fs.readFileSync("config.json")
		const result = eval(code)
		fetch("https://api.example.com")
		process.env.API_KEY
		new WebSocket("wss://stream.example.com")
		require(dynamicPath)
		execSync("ls -la")
	"#;

	c.bench_function("source_analyze_mixed_patterns", |b| {
		b.iter(|| {
			lpm_security::behavioral::source::analyze_source(black_box(source))
		})
	});
}

fn bench_comment_stripping(c: &mut Criterion) {
	let mut source = String::with_capacity(50_000);
	for i in 0..500 {
		source.push_str(&format!("// Comment line {i}\n"));
		source.push_str(&format!("const x_{i} = \"value\"\n"));
		source.push_str(&format!("/* block comment {i} */\n"));
		source.push_str(&format!("const y_{i} = `template ${{expr}}`\n"));
	}

	let input = source.into_bytes();
	let mut buf = Vec::with_capacity(input.len());

	c.bench_function("strip_comments_2000_lines", |b| {
		b.iter(|| {
			lpm_security::behavioral::source::strip_comments(black_box(&input), &mut buf);
		})
	});
}

fn bench_query_parse(c: &mut Criterion) {
	c.bench_function("parse_selector_simple", |b| {
		b.iter(|| {
			lpm_security::query::parse_selector(black_box(":eval")).unwrap()
		})
	});

	c.bench_function("parse_selector_complex", |b| {
		b.iter(|| {
			lpm_security::query::parse_selector(black_box(
				":eval:network,:shell,:root > :scripts:not(:built)",
			))
			.unwrap()
		})
	});
}

criterion_group!(
	benches,
	bench_analyze_package,
	bench_analyze_package_small,
	bench_shannon_entropy,
	bench_source_tag_analysis,
	bench_comment_stripping,
	bench_query_parse,
);
criterion_main!(benches);
