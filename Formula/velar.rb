class Velar < Formula
  desc "Security proxy for AI provider communication"
  homepage "https://github.com/dmitrybondarchuk/prompt-shield"
  license "MIT"
  version "0.0.0"

  on_macos do
    on_arm do
      url "https://github.com/dmitrybondarchuk/prompt-shield/releases/download/v0.0.0/velar-darwin-arm64-v0.0.0.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end

    on_intel do
      url "https://github.com/dmitrybondarchuk/prompt-shield/releases/download/v0.0.0/velar-darwin-x86_64-v0.0.0.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "velar", "velard"
    (etc/"velar").mkpath
  end

  def post_install
    config_dir = Pathname.new(File.expand_path("~/.velar"))
    config_dir.mkpath

    config_file = config_dir/"velar.yaml"
    return if config_file.exist?

    config_file.write(default_config)
  end

  service do
    run [opt_bin/"velard", "-config", File.expand_path("~/.velar/velar.yaml")]
    keep_alive true
    require_root false
    working_dir File.expand_path("~")
    log_path var/"log/velar.log"
    error_log_path var/"log/velar.err.log"
  end

  def caveats
    <<~EOS
      A default config file has been created at ~/.velar/velar.yaml (if missing).
      Initialize local MITM CA assets before first HTTPS interception:
        velar ca init
    EOS
  end

  private

  def default_config
    <<~YAML
      port: 8080
      log_file: #{File.expand_path("~/.velar/audit.log")}
      mitm:
        enabled: false
        domains: []
      sanitizer:
        enabled: true
        types:
          - email
          - aws_access_key
          - db_url
        confidence_threshold: 0.8
        max_replacements: 10
        restore_responses: true
      notifications:
        enabled: true
      rules:
        - id: allow-all
          action: allow
    YAML
  end
end
