use std::{
    net::Ipv4Addr,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use alloy_rlp::{Encodable, RlpDecodableWrapper, RlpEncodableWrapper};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use discv5::enr::{CombinedKey, Enr as Discv5Enr};
use rand::{rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssz::DecodeError;
use validator::ValidationError;

pub type Enr = Discv5Enr<CombinedKey>;

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, RlpEncodableWrapper, RlpDecodableWrapper,
)]
pub struct SszEnr(pub Enr);

impl SszEnr {
    pub fn new(enr: Enr) -> SszEnr {
        SszEnr(enr)
    }
}

impl From<SszEnr> for Enr {
    fn from(ssz_enr: SszEnr) -> Self {
        ssz_enr.0
    }
}

impl TryFrom<&Value> for SszEnr {
    type Error = ValidationError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let enr = value
            .as_str()
            .ok_or_else(|| ValidationError::new("Enr value is not a string!"))?;
        match Enr::from_str(enr) {
            Ok(enr) => Ok(Self(enr)),
            Err(_) => Err(ValidationError::new("Invalid enr value")),
        }
    }
}

impl Deref for SszEnr {
    type Target = Enr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SszEnr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ssz::Decode for SszEnr {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let string = URL_SAFE_NO_PAD.encode(bytes);
        Ok(SszEnr(
            Enr::from_str(&string).map_err(DecodeError::BytesInvalid)?,
        ))
    }
}

impl ssz::Encode for SszEnr {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.encode(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        let mut buf = vec![];
        self.encode(&mut buf);
        buf.ssz_bytes_len()
    }
}

pub fn generate_random_remote_enr() -> (CombinedKey, Enr) {
    let key = CombinedKey::generate_secp256k1();
    let mut rng = rng();

    // Generate an IP between 1.0.0.0 and 223.255.255.255
    // We don't want to generate a multicast address (224.0.0.0 - 239.255.255.255)
    let ip = Ipv4Addr::from(rng.random_range(0x1000000..=0xDFFFFFFF)); // 0xDFFFFFFF == 223.255.255.255

    let enr = Discv5Enr::builder()
        .ip(ip.into())
        .udp4(8000)
        .build(&key)
        .expect("Failed to generate random ENR.");

    (key, enr)
}

#[cfg(test)]
mod test {
    use discv5::enr::NodeId;
    use test_log::test;

    use crate::{
        generate_random_node_id,
        types::distance::{Metric, XorMetric},
    };

    #[test]
    fn test_generate_random_node_id_1() {
        let target_bucket_idx: u8 = 5;
        let local_node_id = NodeId::random();
        let random_node_id = generate_random_node_id(target_bucket_idx, local_node_id);
        let distance = XorMetric::distance(&random_node_id.raw(), &local_node_id.raw());
        let distance = distance.big_endian();

        assert_eq!(distance[0..31], vec![0; 31]);
        assert!(distance[31] < 64 && distance[31] >= 32)
    }

    #[test]
    fn test_generate_random_node_id_2() {
        let target_bucket_idx: u8 = 0;
        let local_node_id = NodeId::random();
        let random_node_id = generate_random_node_id(target_bucket_idx, local_node_id);
        let distance = XorMetric::distance(&random_node_id.raw(), &local_node_id.raw());
        let distance = distance.big_endian();

        assert_eq!(distance[0..31], vec![0; 31]);
        assert_eq!(distance[31], 1);
    }

    #[test]
    fn test_generate_random_node_id_3() {
        let target_bucket_idx: u8 = 255;
        let local_node_id = NodeId::random();
        let random_node_id = generate_random_node_id(target_bucket_idx, local_node_id);
        let distance = XorMetric::distance(&random_node_id.raw(), &local_node_id.raw());
        let distance = distance.big_endian();

        assert!(distance[0] > 127);
    }
}
