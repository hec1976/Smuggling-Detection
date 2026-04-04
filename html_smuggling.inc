# HTML Smuggling Detection - Optimale Config
# Version 4.3.7
# /etc/rspamd/conf.d/html_smuggling.inc

html_smuggling {
    # ========================================
    # 1. CORE SCORING
    # ========================================
    max_final_score = 12.0;
    soft_only_cap = 4.0;
    min_score = 0.5;
    critical_boost = 0.0;
    
    # ========================================
    # 2. NEWSLETTER KONTROLLE
    # ========================================
    heur_mul_newsletter_header = 0.4;
    heur_mul_newsletter_heuristic = 0.5;
    heur_mul_trusted_newsletter = 0.15;
    trusted_newsletter_domains_map = "/etc/rspamd/trusted_nl.map";
    deep_scan_newsletter_header = true;
    
    # ========================================
    # 3. GEWICHTE
    # ========================================
    weights {
        JS_SMUGGLING       = 1.0;
        OBFUSCATION        = 2.2;
        SUSPICIOUS_API     = 0.6;
        EVASION_LOGIC      = 1.2;
        CONTAINER          = 6.5;
        SCRIPT_HARD        = 7.5;
        CRITICAL           = 13.0;
        EXTERNAL_SCRIPT    = 1.0;
        CSS_EXFIL          = 2.0;
        CLICKFIX_LURE      = 1.2;
        WASM_STAGING       = 1.4;
        BLOCKCHAIN_STAGING = 1.2;
        ATTACHMENT_VECTOR  = 1.4;
        CERT_SMUGGLING     = 1.1;
        ROTATION_BONUS     = 0.8;
        GEO_TARGETING      = 0.6;
    }
    
    # ========================================
    # 4. MODULE KONTROLLE
    # ========================================
    modules {
        rc4_detection {
            enabled = false;
        }
        wasm_binary_analysis {
            enabled = true;
        }
        push_abuse {
            info_only = true;
        }
    }
    
    # ========================================
    # 5. PERFORMANCE
    # ========================================
    limits {
        scan {
            max_bytes = 250 * 1024;
            smart_chunk = 60 * 1024;
        }
        script {
            max_script_time_ms = 100.0;
            max_total_script_scan = 150 * 1024;
        }
    }
    
    # ========================================
    # 6. LOGGING
    # ========================================
    debug = false;
    score_debug = false;
    log_score_threshold = 6.0;
    slow_log_ms = 200.0;
    force_extended_log = true;
    force_extended_log_min_score = 8.0;
    redact_log_fields = true;
    
    # ========================================
    # 7. SICHERHEIT
    # ========================================
    require_script_context_for_external = true;
    require_strong_gate_for_decode = true;
    safe_task_access = true;
    safe_part_access = true;
    hard_fail_on_bad_config = false;
    strict_weight_validation = false;
    log_config_validation = true;
}
