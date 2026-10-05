//! Authoritative Capability Registry.
//!
//! Enforces:
//! - INV-005: Risk is derived from registry metadata, not untrusted action proposals.
//! - TRD Section 8: Typed capability models and prohibition of unrestricted SHELL capabilities.
//! - TRD Section 9: Deterministic risk classifications (OBSERVATION, LOW, MODERATE, HIGH, CRITICAL).

use arka_core_types::capabilities::{CapabilityMetadata, RiskClass, TargetClass};
use arka_core_types::errors::KernelSecurityError;
use arka_core_types::id::CapabilityId;
use std::collections::HashMap;

pub trait CapabilityRegistry: Send + Sync {
    fn get(&self, id: &CapabilityId) -> Option<CapabilityMetadata>;
    fn list(&self) -> Vec<CapabilityMetadata>;
}

/// Standard built-in Capability Registry populated with TRD v2.2 capabilities.
#[derive(Debug, Clone)]
pub struct StandardCapabilityRegistry {
    capabilities: HashMap<CapabilityId, CapabilityMetadata>,
}

impl StandardCapabilityRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            capabilities: HashMap::new(),
        };
        registry.populate_standard_capabilities();
        registry
    }

    fn populate_standard_capabilities(&mut self) {
        self.register_internal(CapabilityMetadata {
            id: CapabilityId::new("DNS_LOOKUP").unwrap(),
            name: "DNS Lookup".to_string(),
            description: "Passive and active DNS resolution".to_string(),
            risk_class: RiskClass::Observation,
            requires_approval: false,
            allowed_target_classes: vec![TargetClass::Domain],
            network_required: true,
            timeout_seconds: 15,
            sandbox_profile: "network-minimal".to_string(),
        });

        self.register_internal(CapabilityMetadata {
            id: CapabilityId::new("TCP_CONNECT").unwrap(),
            name: "TCP Connect".to_string(),
            description: "Direct TCP connection check".to_string(),
            risk_class: RiskClass::Low,
            requires_approval: false,
            allowed_target_classes: vec![TargetClass::Ip, TargetClass::Domain],
            network_required: true,
            timeout_seconds: 30,
            sandbox_profile: "network-connect".to_string(),
        });

        self.register_internal(CapabilityMetadata {
            id: CapabilityId::new("PORT_SCAN").unwrap(),
            name: "Port Scan".to_string(),
            description: "TCP/UDP port enumeration within authorized scope".to_string(),
            risk_class: RiskClass::Moderate,
            requires_approval: false,
            allowed_target_classes: vec![TargetClass::Ip, TargetClass::Cidr],
            network_required: true,
            timeout_seconds: 300,
            sandbox_profile: "network-scan".to_string(),
        });

        self.register_internal(CapabilityMetadata {
            id: CapabilityId::new("HTTP_REQUEST").unwrap(),
            name: "HTTP Request".to_string(),
            description: "Single HTTP/HTTPS request".to_string(),
            risk_class: RiskClass::Low,
            requires_approval: false,
            allowed_target_classes: vec![TargetClass::Url],
            network_required: true,
            timeout_seconds: 30,
            sandbox_profile: "http-standard".to_string(),
        });

        self.register_internal(CapabilityMetadata {
            id: CapabilityId::new("WEB_DISCOVERY").unwrap(),
            name: "Web Discovery".to_string(),
            description: "Crawling, robots.txt, sitemap, directory enumeration".to_string(),
            risk_class: RiskClass::Moderate,
            requires_approval: false,
            allowed_target_classes: vec![TargetClass::Url],
            network_required: true,
            timeout_seconds: 300,
            sandbox_profile: "http-crawler".to_string(),
        });

        self.register_internal(CapabilityMetadata {
            id: CapabilityId::new("BROWSER_AUTOMATION").unwrap(),
            name: "Browser Automation".to_string(),
            description: "Headless browser DOM interaction".to_string(),
            risk_class: RiskClass::Moderate,
            requires_approval: false,
            allowed_target_classes: vec![TargetClass::Url],
            network_required: true,
            timeout_seconds: 300,
            sandbox_profile: "browser-isolated".to_string(),
        });

        self.register_internal(CapabilityMetadata {
            id: CapabilityId::new("OSINT_LOOKUP").unwrap(),
            name: "OSINT Lookup".to_string(),
            description: "Passive external intelligence collection (WHOIS, BGP, Shodan)"
                .to_string(),
            risk_class: RiskClass::Observation,
            requires_approval: false,
            allowed_target_classes: vec![TargetClass::Domain, TargetClass::Ip],
            network_required: true,
            timeout_seconds: 60,
            sandbox_profile: "osint-query".to_string(),
        });

        self.register_internal(CapabilityMetadata {
            id: CapabilityId::new("SERVICE_ENUMERATION").unwrap(),
            name: "Service Enumeration".to_string(),
            description: "Banner grabbing, version discovery, SSL handshake inspection".to_string(),
            risk_class: RiskClass::Moderate,
            requires_approval: false,
            allowed_target_classes: vec![TargetClass::Ip, TargetClass::Domain],
            network_required: true,
            timeout_seconds: 300,
            sandbox_profile: "network-scan".to_string(),
        });

        self.register_internal(CapabilityMetadata {
            id: CapabilityId::new("CREDENTIAL_VALIDATION").unwrap(),
            name: "Credential Validation".to_string(),
            description: "Testing single set of credentials against a login service".to_string(),
            risk_class: RiskClass::High,
            requires_approval: true,
            allowed_target_classes: vec![TargetClass::Url, TargetClass::Ip],
            network_required: true,
            timeout_seconds: 60,
            sandbox_profile: "cred-isolated".to_string(),
        });

        self.register_internal(CapabilityMetadata {
            id: CapabilityId::new("CONTROLLED_EXPLOITATION").unwrap(),
            name: "Controlled Exploitation".to_string(),
            description: "Proof-of-concept payload execution against identified vulnerability"
                .to_string(),
            risk_class: RiskClass::Critical,
            requires_approval: true,
            allowed_target_classes: vec![TargetClass::Ip, TargetClass::Url],
            network_required: true,
            timeout_seconds: 300,
            sandbox_profile: "strong-virtualization".to_string(),
        });

        self.register_internal(CapabilityMetadata {
            id: CapabilityId::new("LINUX_TOOL_EXECUTION").unwrap(),
            name: "Linux Tool Execution".to_string(),
            description: "Hardened rootless container worker tool execution".to_string(),
            risk_class: RiskClass::High,
            requires_approval: true,
            allowed_target_classes: vec![TargetClass::Ip, TargetClass::Domain, TargetClass::Url],
            network_required: true,
            timeout_seconds: 300,
            sandbox_profile: "rootless-container".to_string(),
        });
    }

    fn register_internal(&mut self, meta: CapabilityMetadata) {
        self.capabilities.insert(meta.id.clone(), meta);
    }

    /// Extends or registers a custom capability, strictly enforcing that no generic unrestricted
    /// 'SHELL' capability can be introduced (TRD Section 8).
    pub fn register(&mut self, meta: CapabilityMetadata) -> Result<(), KernelSecurityError> {
        let id_str = meta.id.as_str().to_ascii_uppercase();
        if id_str == "SHELL" || id_str == "BASH" || id_str == "SH" || id_str == "CMD" {
            return Err(KernelSecurityError::CapabilityNotFound(
                "Generic unrestricted SHELL capabilities are strictly forbidden by security policy"
                    .to_string(),
            ));
        }

        self.capabilities.insert(meta.id.clone(), meta);
        Ok(())
    }
}

impl Default for StandardCapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityRegistry for StandardCapabilityRegistry {
    fn get(&self, id: &CapabilityId) -> Option<CapabilityMetadata> {
        self.capabilities.get(id).cloned()
    }

    fn list(&self) -> Vec<CapabilityMetadata> {
        self.capabilities.values().cloned().collect()
    }
}
