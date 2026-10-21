//! # Canonical Bot Signature Registry
//! Single Job: Store static signature catalogs for AI scrapers, recon scanners, automation tools, and search engines.

/// Known AI model scrapers, training datasets, and synthetic search crawlers.
/// Both legacy names and newly rebranded search/web bots MUST be preserved.
pub const AI_SCRAPER_SIGNATURES: &[(&str, &str)] = &[
    // Anthropic (Specific to General)
    ("claude-searchbot", "Claude-SearchBot"),
    ("claude-web", "Claude-Web"),
    ("claudebot", "ClaudeBot"),
    ("anthropic-ai", "anthropic-ai"),
    // OpenAI (Specific to General)
    ("oai-searchbot", "OAI-SearchBot"),
    ("chatgpt-user", "ChatGPT-User"),
    ("gptbot", "GPTBot"),
    // Google AI Training (Distinct from Googlebot search)
    ("google-extended", "Google-Extended"),
    // Meta / Facebook (Specific to General)
    ("meta-externalagent", "Meta-ExternalAgent"),
    ("meta-externalfetcher", "Meta-ExternalFetcher"),
    ("facebookexternalhit", "facebookexternalhit"),
    ("facebookbot", "FacebookBot"),
    // Apple AI Intelligence (Distinct from Applebot Siri search)
    ("applebot-extended", "Applebot-Extended"),
    // ByteDance / TikTok (Specific to General)
    ("bytespiderbot", "BytespiderBot"),
    ("bytespider", "Bytespider"),
    ("tiktokbot", "TikTokBot"),
    // Perplexity AI
    ("perplexity-ai", "Perplexity-AI"),
    ("perplexitybot", "PerplexityBot"),
    // Amazon AI
    ("amazonbot", "Amazonbot"),
    // Cohere AI
    ("cohere-training-data-crawler", "cohere-training-data-crawler"),
    ("cohere-ai", "cohere-ai"),
    // Common Crawl & Open Training Datasets
    ("omgilibot", "Omgilibot"),
    ("omgili", "Omgili"),
    ("ccbot", "CCBot"),
    ("diffbot", "Diffbot"),
    ("youbot", "YouBot"),
    ("webzio", "Webzio-Extended"),
    ("ai2bot", "AI2Bot"),
    ("timpibot", "TimpiBot"),
    ("velenpublicwebcrawler", "VelenPublicWebCrawler"),
];

/// Technology stack profilers, commercial SEO scrapers, and automated recon probes.
pub const RECON_SCANNER_SIGNATURES: &[(&str, &str)] = &[
    // Stack Profilers & Metadata Harvesters (Specific to General)
    ("builtwith", "BuiltWith"),
    ("censysinspect", "CensysInspect"),
    ("censys", "Censys"),
    ("shodan", "Shodan"),
    ("zoominfobot", "ZoominfoBot"),
    ("netcraftsurveyagent", "NetcraftSurveyAgent"),
    // Commercial SEO Harvesters (Specific to General)
    ("semrushbot", "SemrushBot"),
    ("semrush", "Semrush"),
    ("ahrefsbot", "AhrefsBot"),
    ("ahrefs", "Ahrefs"),
    ("dotbot", "DotBot"),
    ("mj12bot", "MJ12bot"),
    ("petalbot", "PetalBot"),
    ("dataforseobot", "DataForSeoBot"),
    ("seekport", "Seekport"),
    ("exabot", "Exabot"),
    ("blexbot", "BLEXBot"),
    ("serpstatbot", "SerpstatBot"),
    ("screaming frog", "Screaming Frog"),
    // Academic & Plagiarism Harvesters
    ("turnitinbot", "TurnitinBot"),
];

/// Automation frameworks, headless browsers, attack tools, and penetration testing suites.
pub const AUTOMATION_TOOL_SIGNATURES: &[(&str, &str)] = &[
    // Headless Browser Drivers
    ("headlesschrome", "HeadlessChrome"),
    ("phantomjs", "PhantomJS"),
    ("puppeteer", "Puppeteer"),
    ("selenium", "Selenium"),
    ("playwright", "Playwright"),
    // Scripting Libraries & Scrapers
    ("scrapy", "Scrapy"),
    ("go-http-client", "Go-http-client"),
    ("python-requests", "python-requests"),
    ("python-urllib", "python-urllib"),
    ("aiohttp", "aiohttp"),
    ("httpx", "httpx"),
    ("libwww-perl", "libwww-perl"),
    ("postmanruntime", "PostmanRuntime"),
    // Kali Linux & Offensive Security Fuzzers & Content Discovery
    ("ffuf", "ffuf"),
    ("feroxbuster", "feroxbuster"),
    ("dirsearch", "dirsearch"),
    ("dirbuster", "DirBuster"),
    ("gobuster", "Gobuster"),
    ("wfuzz", "wfuzz"),
    ("nuclei", "Nuclei"),
    ("arjun", "Arjun"),
    ("paramspider", "ParamSpider"),
    // Vulnerability & Web Application Scanners
    ("acunetix", "Acunetix"),
    ("nessus", "Nessus"),
    ("openvas", "OpenVAS"),
    ("burpcollaborator", "BurpCollaborator"),
    ("burpsuite", "BurpSuite"),
    ("owasp-zap", "OWASP ZAP"),
    ("zaproxy", "OWASP ZAP"),
    ("arachni", "Arachni"),
    ("whatweb", "WhatWeb"),
    ("wprecon", "WPRecon"),
    ("wpscan", "WPScan"),
    ("netsparker", "Netsparker"),
    ("qualysguard", "QualysGuard"),
    ("qualys", "Qualys"),
    // Port Scanners, Asset Finders & Network Recon
    ("zgrab", "zgrab"),
    ("masscan", "masscan"),
    ("nmap", "nmap"),
    ("nikto", "nikto"),
    ("rustscan", "RustScan"),
    ("sublist3r", "Sublist3r"),
    ("amass", "OWASP Amass"),
    ("assetfinder", "assetfinder"),
    ("katana", "Katana"),
    // Exploitation Frameworks & Injection Engines
    ("sqlmap", "sqlmap"),
    ("sqlninja", "SQLNinja"),
    ("commix", "Commix"),
    ("havij", "Havij"),
    ("metasploit", "Metasploit"),
    // Password Sprayers & Credential Bruteforcers
    ("hydra", "THC-Hydra"),
    ("medusa", "Medusa"),
    ("patator", "Patator"),
    ("crowbar", "Crowbar"),
    // Digital Forensics & Ingestion Engines (Automated Extraction)
    ("encase", "EnCase"),
    ("autopsy", "Autopsy"),
    ("sleuthkit", "SleuthKit"),
    ("x-ways", "X-Ways"),
    ("magnet-axiom", "Magnet AXIOM"),
    ("axiom", "Magnet AXIOM"),
];

/// Legitimate public search engines permitted on public storefront routes.
pub const LEGITIMATE_SEARCH_SIGNATURES: &[(&str, &str)] = &[
    ("googlebot", "Googlebot"),
    ("bingbot", "Bingbot"),
    ("bingpreview", "BingPreview"),
    ("duckduckbot", "DuckDuckBot"),
    ("slurp", "Slurp"),
    ("baiduspider", "Baiduspider"),
    ("yandexbot", "YandexBot"),
    ("applebot", "Applebot"),
    ("qwantify", "Qwantify"),
];

#[cfg(test)]
mod tests {
    use super::super::{BotCategory, BotGuard};

    #[test]
    fn test_ai_scrapers_profilers_and_kali_tools() {
        let guard = BotGuard::new();
        for (ua, expected_cat, expected_tok) in [
            ("ClaudeBot/1.0", BotCategory::AiScraper, "ClaudeBot"),
            ("Mozilla/5.0 (compatible; Claude-SearchBot/1.0)", BotCategory::AiScraper, "Claude-SearchBot"),
            ("Mozilla/5.0 (compatible; GPTBot/1.2)", BotCategory::AiScraper, "GPTBot"),
            ("Mozilla/5.0 (compatible; OAI-SearchBot/1.0)", BotCategory::AiScraper, "OAI-SearchBot"),
            ("Mozilla/5.0 (compatible; Google-Extended)", BotCategory::AiScraper, "Google-Extended"),
            ("BuiltWith/1.4", BotCategory::ReconScanner, "BuiltWith"),
            ("CensysInspect/1.1", BotCategory::ReconScanner, "CensysInspect"),
            ("ffuf/v2.1.0", BotCategory::AutomationTool, "ffuf"),
            ("nuclei - v3.1.0", BotCategory::AutomationTool, "Nuclei"),
            ("metasploit-framework/v6.3", BotCategory::AutomationTool, "Metasploit"),
            ("Mozilla/5.0 (compatible; Googlebot/2.1)", BotCategory::LegitimateSearch, "Googlebot"),
        ] {
            let (cat, tok) = guard.classify(ua);
            assert_eq!(cat, expected_cat);
            assert_eq!(tok.as_deref(), Some(expected_tok));
        }
    }

    #[test]
    fn test_dynamic_self_healing_and_perimeter_rules() {
        let guard = BotGuard::new();
        let strange_ua = "ZeroDayScannerX/9.9 (Hostile Threat Actor)";
        assert_eq!(guard.classify(strange_ua).0, BotCategory::Unknown);
        let token = guard.harvest_canary_probe(Some(strange_ua), "Tripped canary", 1_700_000_000_000);
        assert_eq!(token.as_deref(), Some("ZeroDayScannerX"));
        assert!(guard.evaluate_perimeter(Some(strange_ua), "/pricing").is_blocked());
        assert!(guard.evaluate_perimeter(Some("Claude-SearchBot/1.0"), "/robots.txt").is_allowed());
        assert!(guard.evaluate_perimeter(Some("curl/8.5.0"), "/install/metaforge").is_allowed());
        assert!(guard.evaluate_perimeter(Some("Claude-SearchBot/1.0"), "/").is_blocked());
    }
}
