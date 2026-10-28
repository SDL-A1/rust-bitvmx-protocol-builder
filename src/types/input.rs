use std::fmt::{Display, Formatter};

use bitcoin::{secp256k1::Message, Amount, EcdsaSighashType, TapSighashType};
use key_manager::{lamport::LamportSignature, winternitz::WinternitzSignature};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{GraphError, ProtocolBuilderError},
    scripts::SignMode,
    types::output::SignatureType,
};

use super::OutputType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpendMode {
    /// Compute sighashes and signatures for all script paths plus the internal key path.
    All { key_path_sign: SignMode },

    /// Compute sighashes and signatures only for the internal key path.
    KeyOnly { key_path_sign: SignMode },

    /// Compute sighashes and signatures for all the script paths excluding the internal key.
    ScriptsOnly,

    /// Compute sighashes and signatures for the specified script paths excluding the internal key.
    Scripts { leaves: Vec<usize> },

    /// Compute sighashes and signatures for a specific script path.
    Script { leaf: usize },

    /// Spend mode for P2WSH and P2WPKH.
    Segwit,

    /// No sighashes or signatures are computed for any path.
    None,
}

impl Display for SpendMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SpendMode::All {
                key_path_sign: key_path_sign_mode,
            } => write!(f, "All({})", key_path_sign_mode),
            SpendMode::KeyOnly {
                key_path_sign: key_path_sign_mode,
            } => write!(f, "KeyOnly({})", key_path_sign_mode),
            SpendMode::ScriptsOnly => write!(f, "ScriptsOnly"),
            SpendMode::Script { leaf } => write!(f, "Script({})", leaf),
            SpendMode::Scripts { leaves } => write!(f, "Scripts({:?})", leaves),
            SpendMode::None => write!(f, "None"),
            SpendMode::Segwit => write!(f, "Segwit"),
        }
    }
}

impl SpendMode {
    pub fn is_all(&self) -> bool {
        matches!(self, SpendMode::All { .. })
    }

    pub fn is_key_only(&self) -> bool {
        matches!(self, SpendMode::KeyOnly { .. })
    }

    pub fn is_scripts_only(&self) -> bool {
        matches!(self, SpendMode::ScriptsOnly)
    }

    pub fn is_scripts(&self) -> bool {
        matches!(self, SpendMode::Scripts { .. })
    }

    pub fn is_script(&self) -> bool {
        matches!(self, SpendMode::Script { .. })
    }

    pub fn is_segwit(&self) -> bool {
        matches!(self, SpendMode::Segwit)
    }

    pub fn is_none(&self) -> bool {
        matches!(self, SpendMode::None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Signature {
    Ecdsa(bitcoin::ecdsa::Signature),
    Taproot(bitcoin::taproot::Signature),
}

#[derive(Clone, Debug)]
pub struct InputSignatures {
    signatures: Vec<Option<Signature>>,
}

impl InputSignatures {
    pub fn new(signatures: Vec<Option<Signature>>) -> Self {
        InputSignatures { signatures }
    }

    pub fn get_taproot_signature(
        &self,
        index: usize,
    ) -> Result<Option<bitcoin::taproot::Signature>, ProtocolBuilderError> {
        match self.signatures.get(index) {
            Some(Some(Signature::Ecdsa(_))) => Err(ProtocolBuilderError::InvalidSignatureType),
            Some(Some(Signature::Taproot(signature))) => Ok(Some(*signature)),
            Some(None) => Ok(None),
            None => Err(ProtocolBuilderError::MissingSignature),
        }
    }

    pub fn get_ecdsa_signature(
        &self,
        index: usize,
    ) -> Result<Option<bitcoin::ecdsa::Signature>, ProtocolBuilderError> {
        match self.signatures.get(index) {
            Some(Some(Signature::Ecdsa(signature))) => Ok(Some(*signature)),
            Some(Some(Signature::Taproot(_))) => Err(ProtocolBuilderError::InvalidSignatureType),
            Some(None) => Ok(None),
            None => Err(ProtocolBuilderError::MissingSignature),
        }
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Option<Signature>> {
        self.signatures.iter()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SighashType {
    Taproot(TapSighashType),
    Ecdsa(EcdsaSighashType),
}

impl SighashType {
    pub fn taproot_all() -> SighashType {
        SighashType::Taproot(TapSighashType::All)
    }

    pub fn ecdsa_all() -> SighashType {
        SighashType::Ecdsa(EcdsaSighashType::All)
    }
}

impl Display for SighashType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SighashType::Taproot(tap_sighash) => write!(f, "Taproot({:?})", tap_sighash),
            SighashType::Ecdsa(ecdsa_sighash) => write!(f, "Ecdsa({:?})", ecdsa_sighash),
        }
    }
}

#[derive(Clone, Debug)]
pub enum InputArgs {
    TaprootKey { args: Vec<Vec<u8>> },
    TaprootScript { args: Vec<Vec<u8>>, leaf: usize },
    Segwit { args: Vec<Vec<u8>> },
}

impl InputArgs {
    pub fn new_taproot_script_args(leaf: usize) -> Self {
        Self::TaprootScript { args: vec![], leaf }
    }

    pub fn new_taproot_key_args() -> Self {
        Self::TaprootKey { args: vec![] }
    }

    pub fn new_segwit_args() -> Self {
        Self::Segwit { args: vec![] }
    }

    pub fn push_slice(&mut self, args: &[u8]) -> &mut Self {
        match self {
            Self::TaprootKey { args: taproot_args } => taproot_args.push(args.to_vec()),
            Self::TaprootScript {
                args: taproot_args, ..
            } => taproot_args.push(args.to_vec()),
            Self::Segwit { args: segwit_args } => segwit_args.push(args.to_vec()),
        }

        self
    }

    pub fn push_taproot_signature(
        &mut self,
        taproot_signature: bitcoin::taproot::Signature,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        match self {
            Self::TaprootKey { .. } => self.push_slice(&taproot_signature.serialize()),
            Self::TaprootScript { .. } => self.push_slice(&taproot_signature.serialize()),
            _ => return Err(ProtocolBuilderError::InvalidSignatureType),
        };

        Ok(self)
    }

    pub fn push_ecdsa_signature(
        &mut self,
        ecdsa_signature: bitcoin::ecdsa::Signature,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        match self {
            Self::Segwit { .. } => self.push_slice(&ecdsa_signature.serialize()),
            _ => return Err(ProtocolBuilderError::InvalidSignatureType),
        };

        Ok(self)
    }

    pub fn push_winternitz_signature(
        &mut self,
        winternitz_signature: WinternitzSignature,
    ) -> &mut Self {
        let hashes = winternitz_signature.to_hashes();
        let digits = winternitz_signature.checksummed_message_digits();

        for (hash, digit) in hashes.iter().zip(digits.iter()) {
            let digit = if *digit == 0 {
                [].to_vec()
            } else {
                [*digit].to_vec()
            };

            self.push_slice(hash);
            self.push_slice(&digit);
        }

        self
    }

    pub fn push_lamport_signature(&mut self, lamport_signature: LamportSignature) -> &mut Self {
        let hashes = lamport_signature.to_hashes();

        for hash in hashes {
            self.push_slice(&hash);
        }

        self
    }

    pub fn push_one_time_signature(&mut self, signature: SignatureType) -> &mut Self {
        match signature {
            SignatureType::Lamport(sig) => self.push_lamport_signature(sig),
            SignatureType::Winternitz(sig) => self.push_winternitz_signature(sig),
        };

        self
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Vec<u8>> {
        match self {
            Self::TaprootKey { args } => args.iter(),
            Self::TaprootScript { args, .. } => args.iter(),
            Self::Segwit { args } => args.iter(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::TaprootKey { args } => args.len(),
            Self::TaprootScript { args, .. } => args.len(),
            Self::Segwit { args } => args.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputType {
    output_type: Option<OutputType>,
    sighash_type: SighashType,
    hashed_messages: Vec<Option<Vec<u8>>>,
    signatures: Vec<Option<Signature>>,
    spend_mode: SpendMode,
    /// A BIP341 annex, if this input carries one.  It is witness data,
    /// so it sits outside the txid and outside any `SIGHASH_ALL`
    /// pre-signature made for a *different* input -- which is what makes
    /// it useful for data chosen after the graph is signed.
    ///
    /// `#[serde(default)]` keeps stored graphs from before this field
    /// deserialisable.
    #[serde(default)]
    annex: Option<Vec<u8>>,
}

impl InputType {
    pub(crate) fn new(spend_mode: &SpendMode, sighash_type: &SighashType) -> Self {
        Self {
            output_type: None,
            sighash_type: sighash_type.clone(),
            hashed_messages: vec![],
            signatures: vec![],
            spend_mode: spend_mode.clone(),
            annex: None,
        }
    }

    pub(crate) fn set_hashed_messages(&mut self, messages: Vec<Option<Message>>) {
        self.hashed_messages = messages
            .iter()
            .map(|msg| msg.as_ref().map(|m| m.as_ref().to_vec()).or(None))
            .collect();
    }

    pub(crate) fn set_output_type(&mut self, output_type: OutputType) -> Result<(), GraphError> {
        match self.sighash_type {
            SighashType::Taproot(_) => match output_type {
                OutputType::Taproot { .. } => {}
                _ => Err(GraphError::InvalidOutputTypeForSighashType)?,
            },
            SighashType::Ecdsa(_) => match output_type {
                OutputType::SegwitPublicKey { .. } => {}
                OutputType::SegwitScript { .. } => {}
                OutputType::SegwitUnspendable { .. } => {}
                _ => Err(GraphError::InvalidOutputTypeForSighashType)?,
            },
        }

        self.output_type = Some(output_type);
        Ok(())
    }

    pub fn set_signatures(&mut self, signatures: Vec<Option<Signature>>) {
        self.signatures = signatures;
    }

    pub fn set_signature(
        &mut self,
        signature: Option<Signature>,
        signature_index: usize,
    ) -> Result<(), GraphError> {
        if signature_index >= self.signatures.len() {
            return Err(GraphError::InvalidSignatureIndex(signature_index));
        }
        self.signatures[signature_index] = signature;

        Ok(())
    }

    pub fn spend_mode(&self) -> &SpendMode {
        &self.spend_mode
    }

    pub fn sighash_type(&self) -> &SighashType {
        &self.sighash_type
    }

    pub fn hashed_messages(&self) -> Vec<Option<Message>> {
        self.hashed_messages
            .iter()
            .map(|msg| {
                msg.as_ref().and_then(|m| {
                    if m.is_empty() {
                        None
                    } else {
                        Some(Message::from_digest_slice(m).expect("Invalid message size"))
                    }
                })
            })
            .collect()
    }

    pub fn output_type(&self) -> Result<&OutputType, GraphError> {
        self.output_type
            .as_ref()
            .ok_or(GraphError::MissingOutputTypeForInput(format!(
                "{:?}",
                self.sighash_type
            )))
    }

    pub fn set_value(&mut self, value: Amount) {
        if let Some(output_type) = &mut self.output_type {
            output_type.set_value(value);
        }
    }

    pub fn signatures(&self) -> &Vec<Option<Signature>> {
        &self.signatures
    }

    pub fn get_signature(&self, index: usize) -> Result<&Option<Signature>, GraphError> {
        self.signatures
            .get(index)
            .ok_or(GraphError::MissingSignature)
    }

    /// Attach a BIP341 annex to this input.  The leading `0x50` is part
    /// of the annex and must be present.
    pub fn set_annex(&mut self, annex: Vec<u8>) -> Result<(), GraphError> {
        match annex.first() {
            Some(&0x50) => {
                self.annex = Some(annex);
                Ok(())
            }
            _ => Err(GraphError::InvalidAnnex),
        }
    }

    pub fn annex(&self) -> Option<&[u8]> {
        self.annex.as_deref()
    }

    pub fn annex_len(&self) -> usize {
        self.annex.as_ref().map_or(0, |a| a.len())
    }
}
