
return {
    paranoia_level = 1,     -- 1 (safe) → 4 (very strict)
    anomaly_threshold = 2,
    enabled_categories = {
        sqli = true,
        xss  = true,
        lfi  = true,
        rce  = true
    }
}
