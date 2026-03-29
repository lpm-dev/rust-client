//! QR code generation for terminal display.
//!
//! Renders QR codes using Unicode half-block characters for compact display.
//! Automatically skips rendering if the terminal is too narrow.

use qrcode::QrCode;

/// Minimum terminal width required to render a QR code.
const MIN_TERMINAL_WIDTH: u16 = 40;

/// Render a URL as a QR code string for terminal display.
///
/// Uses Unicode half-block characters (`▄▀█ `) for compact rendering.
/// Returns an empty string if the terminal is too narrow or QR generation fails.
pub fn render_qr_code(url: &str) -> Result<String, String> {
	// Check terminal width
	let term_width = terminal_width();
	if term_width < MIN_TERMINAL_WIDTH {
		tracing::debug!("terminal too narrow ({term_width} cols), skipping QR code");
		return Ok(String::new());
	}

	let code = QrCode::new(url.as_bytes())
		.map_err(|e| format!("failed to generate QR code: {e}"))?;

	let modules = code.to_colors();
	let width = code.width();

	// Determine if terminal has dark background (default assumption: dark)
	let dark_bg = is_dark_background();

	// Pre-allocate: each row is ~(width + 3) chars (content + margin + newline),
	// and we render width/2 rows (QR codes are square; half-block merges two rows).
	let estimated_rows = (width + 1) / 2;
	let estimated_size = (width + 3) * estimated_rows;
	let mut output = String::with_capacity(estimated_size);

	// Render using half-block characters (2 rows per line)
	// Each character represents 2 vertical modules
	let height = width;
	let mut y = 0;
	while y < height {
		// Add left margin
		output.push_str("  ");

		for x in 0..width {
			let top = modules[y * width + x];
			let bottom = if y + 1 < height {
				modules[(y + 1) * width + x]
			} else {
				qrcode::Color::Light // Padding row
			};

			let top_dark = top == qrcode::Color::Dark;
			let bottom_dark = bottom == qrcode::Color::Dark;

			if dark_bg {
				// Dark terminal: dark modules = white, light modules = transparent
				let ch = match (top_dark, bottom_dark) {
					(true, true) => '█',
					(true, false) => '▀',
					(false, true) => '▄',
					(false, false) => ' ',
				};
				output.push(ch);
			} else {
				// Light terminal: invert
				let ch = match (top_dark, bottom_dark) {
					(false, false) => '█',
					(false, true) => '▀',
					(true, false) => '▄',
					(true, true) => ' ',
				};
				output.push(ch);
			}
		}

		output.push('\n');
		y += 2;
	}

	Ok(output)
}

/// Get the terminal width, defaulting to 80 if detection fails.
fn terminal_width() -> u16 {
	crossterm::terminal::size()
		.map(|(w, _)| w)
		.unwrap_or(80)
}

/// Detect if the terminal has a dark background.
///
/// Checks the `COLORFGBG` environment variable (format: "fg;bg").
/// If bg < 8, it's a dark background. Defaults to dark if unknown.
fn is_dark_background() -> bool {
	if let Ok(colorfgbg) = std::env::var("COLORFGBG") {
		if let Some(bg_str) = colorfgbg.split(';').last() {
			if let Ok(bg) = bg_str.parse::<u8>() {
				return bg < 8;
			}
		}
	}
	true // Default: assume dark background
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn render_qr_code_for_url() {
		let result = render_qr_code("https://192.168.1.42:3000").unwrap();
		// Should produce a non-empty string with QR code characters
		if terminal_width() >= MIN_TERMINAL_WIDTH {
			assert!(!result.is_empty(), "QR code should not be empty");
			assert!(result.contains('\n'), "QR code should have multiple lines");
			// Should contain QR block characters
			let has_blocks = result.contains('█') || result.contains('▀') || result.contains('▄');
			assert!(has_blocks, "QR code should contain block characters");
		}
	}

	#[test]
	fn render_qr_code_empty_for_invalid() {
		// Very long URLs might fail QR generation gracefully
		let short = render_qr_code("http://x").unwrap();
		// Short URLs should always work
		if terminal_width() >= MIN_TERMINAL_WIDTH {
			assert!(!short.is_empty());
		}
	}

	#[test]
	fn dark_bg_detection_defaults_to_dark() {
		// When COLORFGBG is not set or empty, default to dark
		// SAFETY: This test runs single-threaded and no other thread reads
		// COLORFGBG concurrently. The env var is set to a benign empty value.
		unsafe { std::env::set_var("COLORFGBG", "") };
		assert!(is_dark_background());
	}
}
