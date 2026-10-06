use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Data collected from the browser for fingerprinting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserFingerprint {
    pub user_agent: String,
    pub screen_width: u32,
    pub screen_height: u32,
    pub timezone_offset: i32,
    pub language: String,
    pub platform: String,
    pub canvas_hash: String,
    pub webgl_vendor: String,
    pub webgl_renderer: String,
    pub plugins_count: u32,
    pub touch_support: bool,
    pub hardware_concurrency: u32,
    pub device_memory: Option<f32>,
}

impl BrowserFingerprint {
    /// Compute a SHA-256 hash of the fingerprint for cookie binding.
    /// Only uses a subset of stable fields to avoid false negatives
    /// when minor values change between requests.
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.user_agent.as_bytes());
        hasher.update(self.screen_width.to_le_bytes());
        hasher.update(self.screen_height.to_le_bytes());
        hasher.update(self.timezone_offset.to_le_bytes());
        hasher.update(self.language.as_bytes());
        hasher.update(self.platform.as_bytes());
        hasher.update(self.canvas_hash.as_bytes());
        hasher.update(self.hardware_concurrency.to_le_bytes());
        let result = hasher.finalize();
        // Return first 16 bytes as hex (32 chars) — enough for binding
        hex::encode(&result[..16])
    }

    /// Parse fingerprint from JSON (submitted by challenge page JS)
    pub fn from_json(json: &str) -> Result<Self, anyhow::Error> {
        let fp: Self = serde_json::from_str(json)?;
        Ok(fp)
    }
}

/// Generate the JavaScript code that collects browser fingerprint data.
/// This is embedded in the challenge page and sends data back to the server.
pub fn fingerprint_collection_js() -> &'static str {
    r#"(function() {
  'use strict';

  function getCanvasHash() {
    try {
      var canvas = document.createElement('canvas');
      canvas.width = 200;
      canvas.height = 50;
      var ctx = canvas.getContext('2d');
      if (!ctx) return '';
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('PingWAF', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('PingWAF', 4, 17);
      var dataUrl = canvas.toDataURL();
      // Simple hash of the data URL
      var hash = 0;
      for (var i = 0; i < dataUrl.length; i++) {
        var char = dataUrl.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
      }
      return Math.abs(hash).toString(16);
    } catch (e) {
      return '';
    }
  }

  function getWebGLInfo() {
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return { vendor: '', renderer: '' };
      var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (!debugInfo) return { vendor: '', renderer: '' };
      return {
        vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || '',
        renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || ''
      };
    } catch (e) {
      return { vendor: '', renderer: '' };
    }
  }

  function collect() {
    var webgl = getWebGLInfo();
    var data = {
      user_agent: navigator.userAgent || '',
      screen_width: screen.width || 0,
      screen_height: screen.height || 0,
      timezone_offset: new Date().getTimezoneOffset() || 0,
      language: navigator.language || '',
      platform: navigator.platform || '',
      canvas_hash: getCanvasHash(),
      webgl_vendor: webgl.vendor,
      webgl_renderer: webgl.renderer,
      plugins_count: (navigator.plugins && navigator.plugins.length) || 0,
      touch_support: ('ontouchstart' in window) || (navigator.maxTouchPoints > 0),
      hardware_concurrency: navigator.hardwareConcurrency || 0,
      device_memory: navigator.deviceMemory || null
    };
    return JSON.stringify(data);
  }

  window.__pingwaf_fingerprint = collect;
})();"#
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fingerprint() -> BrowserFingerprint {
        BrowserFingerprint {
            user_agent:
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    .to_string(),
            screen_width: 1920,
            screen_height: 1080,
            timezone_offset: -480,
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
            canvas_hash: "a1b2c3d4".to_string(),
            webgl_vendor: "Google Inc.".to_string(),
            webgl_renderer: "ANGLE (NVIDIA GeForce GTX 1080)".to_string(),
            plugins_count: 3,
            touch_support: false,
            hardware_concurrency: 8,
            device_memory: Some(8.0),
        }
    }

    #[test]
    fn test_fingerprint_hash_deterministic() {
        let fp = sample_fingerprint();
        let hash1 = fp.hash();
        let hash2 = fp.hash();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn test_fingerprint_hash_changes_with_data() {
        let fp1 = sample_fingerprint();
        let mut fp2 = sample_fingerprint();
        fp2.screen_width = 2560;
        assert_ne!(fp1.hash(), fp2.hash());
    }

    #[test]
    fn test_fingerprint_from_json() {
        let fp = sample_fingerprint();
        let json = serde_json::to_string(&fp).unwrap();
        let parsed = BrowserFingerprint::from_json(&json).unwrap();
        assert_eq!(parsed.user_agent, fp.user_agent);
        assert_eq!(parsed.screen_width, fp.screen_width);
        assert_eq!(parsed.hardware_concurrency, fp.hardware_concurrency);
    }

    #[test]
    fn test_fingerprint_from_invalid_json() {
        let result = BrowserFingerprint::from_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_fingerprint_js_not_empty() {
        let js = fingerprint_collection_js();
        assert!(!js.is_empty());
        assert!(js.contains("__pingwaf_fingerprint"));
        assert!(js.contains("canvas"));
        assert!(js.contains("webgl"));
    }
}
