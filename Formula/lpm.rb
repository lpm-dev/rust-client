class Lpm < Formula
  desc "Fast, intelligent package manager for lpm.dev"
  homepage "https://lpm.dev"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/lpm-dev/cli/releases/download/v#{version}/lpm-darwin-arm64"
      sha256 "PLACEHOLDER"
    end

    on_intel do
      url "https://github.com/lpm-dev/cli/releases/download/v#{version}/lpm-darwin-x64"
      sha256 "PLACEHOLDER"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lpm-dev/cli/releases/download/v#{version}/lpm-linux-arm64"
      sha256 "PLACEHOLDER"
    end

    on_intel do
      url "https://github.com/lpm-dev/cli/releases/download/v#{version}/lpm-linux-x64"
      sha256 "PLACEHOLDER"
    end
  end

  def install
    binary = Dir["lpm-*"].first
    bin.install binary => "lpm"
  end

  test do
    assert_match "lpm", shell_output("#{bin}/lpm --version")
  end
end
