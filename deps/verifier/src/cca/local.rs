// Copyright (c) 2023 Arm Ltd.
// Copyright (c) 2025 Linaro Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use base64::engine::general_purpose;
use ccatoken::store::*;
use ccatoken::token::Evidence;
use config::Config;
use core::result::Result::Ok;
use ear::{Appraisal, Ear, RawValue, VerifierID};
use ear::{Extensions, TrustTier};
use log::debug;
use std::collections::BTreeMap;
use std::fs;

pub fn verify(
    config: Config,
    token: &Vec<u8>,
    _expected_report_data: &Vec<u8>,
) -> Result<Ear, anyhow::Error> {
    debug!("using config: {:?}", config);

    let ta_store = config.local_verifier.clone().unwrap().ta_store;
    let rv_store = config.local_verifier.clone().unwrap().rv_store;

    let jta = fs::read_to_string(ta_store).context("loading TA store")?;
    let jrv = fs::read_to_string(rv_store).context("loading RV store")?;

    let mut tas: MemoTrustAnchorStore = Default::default();
    tas.load_json(&jta)
        .context("loading trust anchors from JSON store")?;

    let mut rvs: MemoRefValueStore = Default::default();
    rvs.load_json(&jrv)
        .context("loading reference values from JSON store")?;

    let mut e: Evidence = Evidence::decode(&token).context("decoding CCA evidence")?;

    e.verify(&tas).context("verifying CCA evidence")?;
    e.appraise(&rvs).context("appraising CCA evidence")?;

    let (platform_tvec, realm_tvec) = e.get_trust_vectors();

    // Check that the Realm token was correctly signed using the RAK and that
    // the RAK was correctly attested.
    if realm_tvec.instance_identity.tier() != TrustTier::Affirming {
        bail!("RAK signature or RAK attestation could not be verified");
    }

    // Synthesize TCB claims the way EAR wants to report them:
    // realm part
    let realm_annotated_evidence =
        realm_annotated_evidence(&e).context("syntesizing CCA Realm TCB claims-set")?;

    let mut realm_appraisal = Appraisal::new();
    realm_appraisal.annotated_evidence = realm_annotated_evidence;
    realm_appraisal.trust_vector = realm_tvec;
    realm_appraisal.update_status_from_trust_vector();

    // platform part
    let platform_annotated_evidence =
        platform_annotated_evidence(&e).context("syntesizing CCA Platform TCB claims-set")?;

    let mut platform_appraisal = Appraisal::new();
    platform_appraisal.annotated_evidence = platform_annotated_evidence;
    platform_appraisal.trust_vector = platform_tvec;
    platform_appraisal.update_status_from_trust_vector();

    let ear = Ear {
        profile: "tag:github.com,2023:veraison/ear".to_string(),
        vid: VerifierID {
            build: "CoCo CCA local verifier".to_string(),
            developer: "https://veraison-project.org".to_string(),
        },
        submods: BTreeMap::from([
            ("CCA_SSD_PLATFORM".to_string(), platform_appraisal),
            ("CCA_REALM".to_string(), realm_appraisal),
        ]),
        iat: 0,                        // not relevant
        nonce: None,                   // not relevant
        raw_evidence: None,            // not relevant
        extensions: Extensions::new(), // not relevant
    };

    /*
    let ear = Ear {
        profile: "tag:github.com,2023:veraison/ear".to_string(),
        vid: VerifierID {
            build: "CoCo CCA local verifier".to_string(),
            developer: "https://veraison-project.org".to_string(),
        },
        submods: BTreeMap::from([("CCA_SSD_PLATFORM".to_string(), appraisal)]),
        iat: 0,             // not relevant
        nonce: None,        // not relevant
        raw_evidence: None, // not relevant
    };
    */

    Ok(ear)
}

fn realm_annotated_evidence(e: &Evidence) -> Result<BTreeMap<String, RawValue>, anyhow::Error> {
    let pv = general_purpose::STANDARD.encode(e.realm_claims.perso.clone());
    let rim = general_purpose::STANDARD.encode(e.realm_claims.rim.clone());
    let rem0 = general_purpose::STANDARD.encode(e.realm_claims.rem[0].clone());
    let rem1 = general_purpose::STANDARD.encode(e.realm_claims.rem[1].clone());
    let rem2 = general_purpose::STANDARD.encode(e.realm_claims.rem[2].clone());
    let rem3 = general_purpose::STANDARD.encode(e.realm_claims.rem[3].clone());
    let nonce = general_purpose::STANDARD.encode(e.realm_claims.challenge.clone());

    // I am making the choice of reporting only the claims that are related to
    // (currently) unvalidate pieces of the TCB.  The assumption is that CCA
    // platform has been already fully validated (including RAK attestation),
    // and that the only piece of TCB that remains to be validated is the Realm.
    let j = format!(
        r#"{{
            "cca-realm-challenge": "{nonce}",
            "cca-realm-extensible-measurements": [ "{rem0}", "{rem1}", "{rem2}", "{rem3}" ],
            "cca-realm-hash-algo-id": "",
            "cca-realm-initial-measurement": "{rim}",
            "cca-realm-personalization-value": "{pv}",
            "cca-realm-public-key": "",
            "cca-realm-public-key-hash-algo-id": ""
        }}
    "#
    );

    let realm_claims = serde_json::from_str(&j)?;

    Ok(realm_claims)
}

fn platform_annotated_evidence(e: &Evidence) -> Result<BTreeMap<String, RawValue>, anyhow::Error> {
    let instance_id = general_purpose::STANDARD.encode(e.platform_claims.inst_id.clone());
    let implementation_id = general_purpose::STANDARD.encode(e.platform_claims.impl_id.clone());

    // only report class and instance information for the appraised platform
    let j = format!(
        r#"{{
            "cca-platform-instance-id": "{instance_id}",
            "cca-platform-implementation-id": "{implementation_id}"
        }}
    "#
    );

    let platform_claims = serde_json::from_str(&j)?;

    Ok(platform_claims)
}
