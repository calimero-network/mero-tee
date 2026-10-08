//! Shared test helpers.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use calimero_server_primitives::admin::{
    CertificationData, QeReportCertificationDataInfo, Quote, QuoteBody, QuoteHeader,
};

/// A directory under the system temp dir, removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "mero-agent-gate-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A quote with every register zeroed, as mero-kms's tests build one.
pub fn zero_quote() -> Quote {
    let zero_48b = "0".repeat(96);
    let zero_16b = "0".repeat(32);
    let zero_8b = "0".repeat(16);
    Quote {
        header: QuoteHeader {
            version: 4,
            attestation_key_type: 2,
            tee_type: 0x81,
            qe_vendor_id: "939a7233f79c4ca9940a0db3957f0607".to_owned(),
            user_data: zero_16b.clone(),
        },
        body: QuoteBody {
            tdx_version: "1.0".to_owned(),
            tee_tcb_svn: zero_16b,
            mrseam: zero_48b.clone(),
            mrsignerseam: zero_48b.clone(),
            seamattributes: zero_8b.clone(),
            tdattributes: zero_8b.clone(),
            xfam: zero_8b,
            mrtd: zero_48b.clone(),
            mrconfigid: zero_48b.clone(),
            mrowner: zero_48b.clone(),
            mrownerconfig: zero_48b.clone(),
            rtmr0: zero_48b.clone(),
            rtmr1: zero_48b.clone(),
            rtmr2: zero_48b.clone(),
            rtmr3: zero_48b,
            reportdata: "0".repeat(128),
            tee_tcb_svn_2: None,
            mrservicetd: None,
        },
        signature: "0".repeat(128),
        attestation_key: "04".to_owned() + &"0".repeat(128),
        certification_data: CertificationData::QeReportCertificationData(
            QeReportCertificationDataInfo {
                qe_report: "0".repeat(768),
                signature: "0".repeat(128),
                qe_authentication_data: "0".repeat(64),
                certification_data_type: "PckCertChain".to_owned(),
                certification_data: "0".repeat(200),
            },
        ),
    }
}
