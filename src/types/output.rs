use std::fmt;

use bitcoin::{
    secp256k1::{self, Message},
    sighash::{self, Annex, SighashCache},
    taproot::{LeafVersion, TaprootSpendInfo},
    Amount, EcdsaSighashType, PublicKey, ScriptBuf, TapLeafHash, TapSighashType, TapTweakHash,
    Transaction, TxOut, Txid, WScriptHash, XOnlyPublicKey,
};
use key_manager::{
    key_manager::KeyManager, lamport::LamportSignature, verifier::SignatureVerifier,
    winternitz::WinternitzSignature,
};
use serde::{Deserialize, Serialize};

use crate::{
    errors::ProtocolBuilderError,
    scripts::{self, ProtocolScript, SignMode},
    types::input::Signature,
};

use super::input::SpendMode;
pub const MAX_DUST_LIMIT: u64 = 540;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageId {
    transaction: String,
    input_index: u32,
    script_index: u32,
}

impl MessageId {
    pub fn new(transaction: String, input_index: u32, script_index: u32) -> Self {
        MessageId {
            transaction,
            input_index,
            script_index,
        }
    }

    pub fn new_string_id(transaction: &str, input_index: u32, script_index: u32) -> String {
        format!("tx:{}_ix:{}_sx:{}", transaction, input_index, script_index)
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tx:{}_ix:{}_sx:{}",
            self.transaction, self.input_index, self.script_index
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub amount: u64,
    pub pub_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureType {
    Winternitz(WinternitzSignature),
    Lamport(LamportSignature),
}

impl From<WinternitzSignature> for SignatureType {
    fn from(wits: WinternitzSignature) -> Self {
        SignatureType::Winternitz(wits)
    }
}

impl From<LamportSignature> for SignatureType {
    fn from(lamp: LamportSignature) -> Self {
        SignatureType::Lamport(lamp)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedupData {
    pub utxo: Option<Utxo>,
    pub partial_utxo: Option<(Txid, u32, u64)>,
    pub output_type: Option<OutputType>,
    pub sigs: Option<Vec<SignatureType>>,
    pub leaf_index: Option<usize>,
    pub leaf_identification: bool,
}

impl SpeedupData {
    pub fn new(utxo: Utxo) -> Self {
        Self {
            utxo: Some(utxo),
            partial_utxo: None,
            output_type: None,
            sigs: None,
            leaf_index: None,
            leaf_identification: false,
        }
    }

    pub fn new_with_input<S: Into<SignatureType>>(
        partial_utxo: (Txid, u32, u64),
        output_type: &OutputType,
        sigs: Vec<S>,
        leaf_index: usize,
        leaf_id: bool,
    ) -> Self {
        Self {
            utxo: None,
            partial_utxo: Some(partial_utxo),
            output_type: Some(output_type.clone()),
            sigs: Some(sigs.into_iter().map(Into::into).collect()),
            leaf_index: Some(leaf_index),
            leaf_identification: leaf_id,
        }
    }
}

impl Utxo {
    pub fn new(txid: Txid, vout: u32, amount: u64, pub_key: &PublicKey) -> Self {
        Utxo {
            txid,
            vout,
            amount,
            pub_key: *pub_key,
        }
    }
}
impl From<Utxo> for SpeedupData {
    fn from(val: Utxo) -> Self {
        SpeedupData::new(val)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AmountType {
    Value(Amount),
    Return,
    Auto,
    Recover,
    None,
}
impl AmountType {
    pub fn is_none(&self) -> bool {
        matches!(self, AmountType::None)
    }
    pub fn is_return(&self) -> bool {
        matches!(self, AmountType::Return)
    }
    pub fn is_auto(&self) -> bool {
        matches!(self, AmountType::Auto)
    }
    pub fn is_recover(&self) -> bool {
        matches!(self, AmountType::Recover)
    }
    pub fn get_value(&self) -> Option<Amount> {
        match self {
            AmountType::Value(v) => Some(*v),
            _ => None,
        }
    }
}
impl From<u64> for AmountType {
    fn from(value: u64) -> Self {
        AmountType::Value(Amount::from_sat(value))
    }
}
impl From<Amount> for AmountType {
    fn from(value: Amount) -> Self {
        AmountType::Value(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputType {
    Taproot {
        value: AmountType,
        internal_key: PublicKey,
        script_pubkey: ScriptBuf,
        leaves: Vec<ProtocolScript>,
    },
    SegwitPublicKey {
        value: AmountType,
        script_pubkey: ScriptBuf,
        public_key: PublicKey,
    },
    SegwitScript {
        value: AmountType,
        script_pubkey: ScriptBuf,
        script: ProtocolScript,
    },
    SegwitUnspendable {
        value: AmountType,
        script_pubkey: ScriptBuf,
    },
    ExternalUnknown {
        value: AmountType,
        script_pubkey: ScriptBuf,
    },
}

/// BIP342's default codeseparator position: none was executed.
///
/// The signature-hash message carries it whether or not the script uses
/// `OP_CODESEPARATOR`, so it has to be supplied when the general
/// signature-hash form is used in place of the script-spend convenience
/// wrapper.
const DEFAULT_CODESEPARATOR_POSITION: u32 = 0xFFFF_FFFF;

/// Borrow an annex for signing.
///
/// `None` is the ordinary case and signs exactly as before. `Some` must
/// begin with `0x50`, which is what makes it an annex rather than a
/// witness element, and `Annex::new` is where that is enforced.
fn as_annex(annex: Option<&[u8]>) -> Result<Option<Annex<'_>>, ProtocolBuilderError> {
    match annex {
        None => Ok(None),
        Some(bytes) => Annex::new(bytes)
            .map(Some)
            .map_err(|_| ProtocolBuilderError::InvalidAnnex),
    }
}

impl OutputType {
    pub fn taproot<V: Into<AmountType>>(
        value: V,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
    ) -> Result<Self, ProtocolBuilderError> {
        let secp = secp256k1::Secp256k1::new();
        let spend_info = Self::compute_spend_info(internal_key, leaves)?;

        let script_pubkey =
            ScriptBuf::new_p2tr(&secp, spend_info.internal_key(), spend_info.merkle_root());

        Ok(OutputType::Taproot {
            value: value.into(),
            internal_key: *internal_key,
            script_pubkey,
            leaves: leaves.to_vec(),
        })
    }

    pub fn segwit_key<V: Into<AmountType>>(
        value: V,
        public_key: &PublicKey,
    ) -> Result<Self, ProtocolBuilderError> {
        let witness_public_key_hash = public_key.wpubkey_hash()?;
        let script_pubkey = ScriptBuf::new_p2wpkh(&witness_public_key_hash);

        Ok(OutputType::SegwitPublicKey {
            value: value.into(),
            public_key: *public_key,
            script_pubkey,
        })
    }

    pub fn segwit_script<V: Into<AmountType>>(
        value: V,
        script: &ProtocolScript,
    ) -> Result<Self, ProtocolBuilderError> {
        let script_pubkey = ScriptBuf::new_p2wsh(&WScriptHash::from(script.get_script().clone()));

        Ok(OutputType::SegwitScript {
            value: value.into(),
            script_pubkey,
            script: script.clone(),
        })
    }

    pub fn segwit_unspendable(script_pubkey: ScriptBuf) -> Result<Self, ProtocolBuilderError> {
        Ok(OutputType::SegwitUnspendable {
            value: AmountType::Return,
            script_pubkey,
        })
    }

    pub fn external_unknown(script_pubkey: ScriptBuf) -> Result<Self, ProtocolBuilderError> {
        Ok(OutputType::ExternalUnknown {
            value: AmountType::None,
            script_pubkey,
        })
    }

    // TODO: for a more precise estimation we can set different dust limits for different output types
    pub fn dust_limit(&self) -> Amount {
        match self {
            OutputType::Taproot { .. } => Amount::from_sat(MAX_DUST_LIMIT),
            OutputType::SegwitPublicKey { .. } => Amount::from_sat(MAX_DUST_LIMIT),
            OutputType::SegwitScript { .. } => Amount::from_sat(MAX_DUST_LIMIT),
            OutputType::SegwitUnspendable { .. } => Amount::from_sat(MAX_DUST_LIMIT),
            OutputType::ExternalUnknown { .. } => Amount::from_sat(MAX_DUST_LIMIT),
        }
    }

    pub fn generic_dust_limit(output_type: Option<&OutputType>) -> Amount {
        match output_type {
            Some(output) => output.dust_limit(),
            None => Amount::from_sat(MAX_DUST_LIMIT),
        }
    }

    pub fn get_name(&self) -> &'static str {
        match self {
            OutputType::Taproot { .. } => "TaprootScript",
            OutputType::SegwitPublicKey { .. } => "SegwitPublicKey",
            OutputType::SegwitScript { .. } => "SegwitScript",
            OutputType::SegwitUnspendable { .. } => "SegwitUnspendable",
            OutputType::ExternalUnknown { .. } => "ExternalUnknown",
        }
    }

    pub fn get_value(&self) -> Option<Amount> {
        match self {
            OutputType::Taproot { value, .. }
            | OutputType::SegwitPublicKey { value, .. }
            | OutputType::SegwitScript { value, .. }
            | OutputType::SegwitUnspendable { value, .. }
            | OutputType::ExternalUnknown { value, .. } => match value {
                AmountType::Value(v) => Some(*v),
                AmountType::Return => Some(Amount::from_sat(0)),
                _ => None,
            },
        }
    }

    pub fn get_value_or_err(&self) -> Result<Amount, ProtocolBuilderError> {
        self.get_value()
            .ok_or(ProtocolBuilderError::AmountTypeValueExpected)
    }

    pub fn get_value_or_dust(&self) -> Result<Amount, ProtocolBuilderError> {
        match self.get_value() {
            Some(value) => {
                if value < self.dust_limit() && !self.return_value() {
                    return Err(ProtocolBuilderError::DustOutput {
                        value,
                        dust_limit: self.dust_limit(),
                        output_type: Box::new(self.clone()),
                    });
                }
                Ok(value)
            }
            None => Ok(self.dust_limit()),
        }
    }

    pub fn set_value(&mut self, new_value: Amount) {
        match self {
            OutputType::Taproot { value, .. } => *value = new_value.into(),
            OutputType::SegwitPublicKey { value, .. } => *value = new_value.into(),
            OutputType::SegwitScript { value, .. } => *value = new_value.into(),
            OutputType::SegwitUnspendable { value, .. } => *value = new_value.into(),
            OutputType::ExternalUnknown { value, .. } => *value = new_value.into(),
        }
    }

    fn amount_type(&self) -> &AmountType {
        match self {
            OutputType::Taproot { value, .. }
            | OutputType::SegwitPublicKey { value, .. }
            | OutputType::SegwitScript { value, .. }
            | OutputType::SegwitUnspendable { value, .. }
            | OutputType::ExternalUnknown { value, .. } => value,
        }
    }

    pub fn auto_value(&self) -> bool {
        self.amount_type().is_auto()
    }

    pub fn recover_value(&self) -> bool {
        self.amount_type().is_recover()
    }

    pub fn return_value(&self) -> bool {
        self.amount_type().is_return()
    }

    pub fn get_script_pubkey(&self) -> &ScriptBuf {
        match self {
            OutputType::Taproot { script_pubkey, .. }
            | OutputType::SegwitPublicKey { script_pubkey, .. }
            | OutputType::SegwitScript { script_pubkey, .. }
            | OutputType::ExternalUnknown { script_pubkey, ..} //FIX
            | OutputType::SegwitUnspendable { script_pubkey, .. } => script_pubkey,
        }
    }

    pub fn get_taproot_spend_info(&self) -> Result<Option<TaprootSpendInfo>, ProtocolBuilderError> {
        match self {
            OutputType::Taproot {
                leaves,
                internal_key,
                ..
            } => Ok(Some(Self::compute_spend_info(internal_key, leaves)?)),
            _ => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// `annex`, when present, is the BIP341 annex this input publishes.
    ///
    /// It is signed data: the annex is stripped before the script runs,
    /// but its hash is in the signature-hash message, which is what makes
    /// a published annex binding at all. An input that carries one and
    /// signs without it would commit to nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_taproot_sighash(
        &self,
        hasher: &mut SighashCache<&Transaction>,
        transaction_name: &str,
        input_index: usize,
        prevouts: &[TxOut],
        spend_mode: &SpendMode,
        tap_sighash_type: &TapSighashType,
        annex: Option<&[u8]>,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Vec<Option<Message>>, ProtocolBuilderError> {
        let messages = match self {
            OutputType::Taproot {
                internal_key,
                leaves,
                ..
            } => self.taproot_sighash(
                hasher,
                transaction_name,
                input_index,
                prevouts,
                tap_sighash_type,
                internal_key,
                leaves,
                spend_mode,
                annex,
                key_manager,
                id,
            )?,
            _ => {
                return Err(ProtocolBuilderError::InvalidOutputType(
                    "Taproot".to_string(),
                    self.get_name().to_string(),
                ));
            }
        };

        Ok(messages)
    }

    pub fn compute_ecdsa_sighash(
        &self,
        hasher: &mut SighashCache<&Transaction>,
        _transaction_name: &str,
        input_index: usize,
        spend_mode: &SpendMode,
        ecdsa_sighash_type: &EcdsaSighashType,
    ) -> Result<Vec<Option<Message>>, ProtocolBuilderError> {
        if spend_mode.is_none() {
            return Ok(vec![None]);
        }

        let messages = match self {
            OutputType::SegwitPublicKey {
                value, public_key, ..
            } => self.ecdsa_key_sighash(
                hasher,
                input_index,
                ecdsa_sighash_type,
                &value.get_value().unwrap_or_else(|| self.dust_limit()),
                public_key,
            )?,
            OutputType::SegwitScript { value, script, .. } => self.ecdsa_script_sighash(
                hasher,
                input_index,
                ecdsa_sighash_type,
                &value.get_value().unwrap_or_else(|| self.dust_limit()),
                script,
            )?,
            OutputType::SegwitUnspendable { .. } => {
                vec![None]
            }
            _ => {
                return Err(ProtocolBuilderError::InvalidOutputType(
                    "Segwit".to_string(),
                    self.get_name().to_string(),
                ));
            }
        };

        Ok(messages)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compute_taproot_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
        hashed_messages: &[Option<Message>],
        spend_mode: &SpendMode,
        tap_sighash_type: &TapSighashType,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Vec<Option<Signature>>, ProtocolBuilderError> {
        let signatures = match self {
            OutputType::Taproot {
                internal_key,
                leaves,
                ..
            } => self.taproot_signature(
                transaction_name,
                input_index,
                hashed_messages,
                tap_sighash_type,
                internal_key,
                leaves,
                spend_mode,
                key_manager,
                id,
            )?,
            _ => {
                return Err(ProtocolBuilderError::InvalidOutputType(
                    "Taproot".to_string(),
                    self.get_name().to_string(),
                ));
            }
        };

        Ok(signatures)
    }

    pub fn compute_ecdsa_signature(
        &self,
        _transaction_name: &str,
        _input_index: usize,
        hashed_messages: &[Option<Message>],
        spend_mode: &SpendMode,
        ecdsa_sighash_type: &EcdsaSighashType,
        key_manager: &KeyManager,
    ) -> Result<Vec<Option<Signature>>, ProtocolBuilderError> {
        if spend_mode.is_none() {
            return Ok(vec![None]);
        }

        let signatures = match self {
            OutputType::SegwitPublicKey { public_key, .. } => self.ecdsa_key_signature(
                hashed_messages,
                ecdsa_sighash_type,
                key_manager,
                public_key,
            )?,
            OutputType::SegwitScript { script, .. } => self.ecdsa_script_signature(
                hashed_messages,
                ecdsa_sighash_type,
                key_manager,
                script,
            )?,
            OutputType::SegwitUnspendable { .. } => {
                vec![None]
            }
            _ => {
                return Err(ProtocolBuilderError::InvalidOutputType(
                    "Segwit".to_string(),
                    self.get_name().to_string(),
                ));
            }
        };

        Ok(signatures)
    }

    fn compute_spend_info(
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
    ) -> Result<TaprootSpendInfo, ProtocolBuilderError> {
        let secp = secp256k1::Secp256k1::new();
        let spend_info =
            scripts::build_taproot_spend_info(&secp, &XOnlyPublicKey::from(*internal_key), leaves)?;
        Ok(spend_info)
    }

    #[allow(clippy::too_many_arguments)]
    fn taproot_sighash(
        &self,
        hasher: &mut SighashCache<&Transaction>,
        transaction_name: &str,
        input_index: usize,
        prevouts: &[TxOut],
        tap_sighash_type: &TapSighashType,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
        spend_mode: &SpendMode,
        annex: Option<&[u8]>,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Vec<Option<Message>>, ProtocolBuilderError> {
        let (key_path, scripts_path, key_path_sign_mode, selected_leaves) =
            spend_mode_params(leaves, spend_mode)?;

        // Initialize the vector of hashed messages with None for all paths.
        let mut hashed_messages: Vec<Option<Message>> = vec![None; leaves.len() + 1];

        if key_path {
            let hashed_message = self.taproot_key_only_sighash(
                hasher,
                transaction_name,
                input_index,
                prevouts,
                tap_sighash_type,
                &key_path_sign_mode.unwrap(),
                internal_key,
                leaves,
                annex,
                key_manager,
                id,
            )?;

            // Push the key path hash to the end of the vector.
            let last_index = hashed_messages.len() - 1;
            hashed_messages[last_index] = hashed_message;
        };

        if scripts_path {
            // Script path hashes
            for (leaf_index, leaf) in selected_leaves.as_ref().unwrap().iter() {
                let hashed_message = self.taproot_script_only_sighash(
                    hasher,
                    transaction_name,
                    input_index,
                    prevouts,
                    tap_sighash_type,
                    leaf,
                    *leaf_index,
                    annex,
                    key_manager,
                    id,
                )?;

                // Push the script path hash to the correct position in the vector.
                hashed_messages[*leaf_index] = hashed_message;
            }
        };

        Ok(hashed_messages)
    }

    #[allow(clippy::too_many_arguments)]
    fn taproot_script_only_sighash(
        &self,
        hasher: &mut SighashCache<&Transaction>,
        transaction_name: &str,
        input_index: usize,
        prevouts: &[TxOut],
        tap_sighash_type: &TapSighashType,
        leaf: &ProtocolScript,
        leaf_index: usize,
        annex: Option<&[u8]>,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Option<Message>, ProtocolBuilderError> {
        let hashed_message = Message::from(hasher.taproot_signature_hash(
            input_index,
            &sighash::Prevouts::All(prevouts),
            as_annex(annex)?,
            Some((
                TapLeafHash::from_script(leaf.get_script(), LeafVersion::TapScript),
                DEFAULT_CODESEPARATOR_POSITION,
            )),
            *tap_sighash_type,
        )?);

        if leaf.aggregate_signing() && leaf.get_verifying_key().is_some() {
            key_manager.generate_nonce(
                MessageId::new_string_id(transaction_name, input_index as u32, leaf_index as u32)
                    .as_str(),
                hashed_message.as_ref().to_vec(),
                &leaf.get_verifying_key().unwrap(),
                id,
                None,
            )?;
        };

        Ok(Some(hashed_message))
    }

    #[allow(clippy::too_many_arguments)]
    fn taproot_key_only_sighash(
        &self,
        hasher: &mut SighashCache<&Transaction>,
        transaction_name: &str,
        input_index: usize,
        prevouts: &[TxOut],
        tap_sighash_type: &TapSighashType,
        key_path_sign_mode: &SignMode,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
        annex: Option<&[u8]>,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Option<Message>, ProtocolBuilderError> {
        // Compute a sighash for the key spend path.
        let key_path_hashed_message = Message::from(hasher.taproot_signature_hash(
            input_index,
            &sighash::Prevouts::All(prevouts),
            as_annex(annex)?,
            None,
            *tap_sighash_type,
        )?);

        if *key_path_sign_mode == SignMode::Aggregate {
            let spend_info = Self::compute_spend_info(internal_key, leaves)?;

            let tweak = TapTweakHash::from_key_and_tweak(
                XOnlyPublicKey::from(*internal_key),
                spend_info.merkle_root(),
            )
            .to_scalar();
            let musig2_tweak =
                musig2::secp256k1::Scalar::from_be_bytes(tweak.to_be_bytes()).unwrap();

            key_manager.generate_nonce(
                MessageId::new_string_id(transaction_name, input_index as u32, leaves.len() as u32)
                    .as_str(),
                key_path_hashed_message.as_ref().to_vec(),
                internal_key,
                id,
                Some(musig2_tweak),
            )?;
        }

        Ok(Some(key_path_hashed_message))
    }

    fn ecdsa_key_sighash(
        &self,
        hasher: &mut SighashCache<&Transaction>,
        input_index: usize,
        ecdsa_sighash_type: &EcdsaSighashType,
        value: &Amount,
        public_key: &PublicKey,
    ) -> Result<Vec<Option<Message>>, ProtocolBuilderError> {
        let wpkh = public_key.wpubkey_hash()?;
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

        Ok(vec![Some(Message::from(hasher.p2wpkh_signature_hash(
            input_index,
            &script_pubkey,
            *value,
            *ecdsa_sighash_type,
        )?))])
    }

    fn ecdsa_script_sighash(
        &self,
        sighasher: &mut SighashCache<&Transaction>,
        input_index: usize,
        ecdsa_sighash_type: &EcdsaSighashType,
        value: &Amount,
        script: &ProtocolScript,
    ) -> Result<Vec<Option<Message>>, ProtocolBuilderError> {
        let script_hash = WScriptHash::from(script.get_script().clone());
        let script_pubkey = ScriptBuf::new_p2wsh(&script_hash);

        let hashed_message = Message::from(sighasher.p2wsh_signature_hash(
            input_index,
            &script_pubkey,
            *value,
            *ecdsa_sighash_type,
        )?);

        Ok(vec![Some(hashed_message)])
    }

    #[allow(clippy::too_many_arguments)]
    pub fn taproot_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
        hashed_messages: &[Option<Message>],
        tap_sighash_type: &TapSighashType,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
        spend_mode: &SpendMode,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Vec<Option<Signature>>, ProtocolBuilderError> {
        assert!(
            hashed_messages.len() == leaves.len() + 1,
            "Expected one message for each script and one for the key spend path"
        );

        let (key_path, scripts_path, key_path_sign_mode, selected_leaves) =
            spend_mode_params(leaves, spend_mode)?;

        // Initialize the vector of signatures with None for all paths.
        let mut signatures: Vec<Option<Signature>> = vec![None; leaves.len() + 1];

        if key_path {
            // Key path signature
            let signature = self.taproot_key_only_signature(
                transaction_name,
                input_index,
                hashed_messages,
                tap_sighash_type,
                &key_path_sign_mode.unwrap(),
                internal_key,
                leaves,
                key_manager,
                id,
            )?;

            // Push the key path signature to the end of the vector.
            let last_index = signatures.len() - 1;
            signatures[last_index] = signature;
        };

        if scripts_path {
            // Script path signatures
            for (leaf_index, leaf) in selected_leaves.as_ref().unwrap().iter() {
                let signature = self.taproot_script_only_signature(
                    transaction_name,
                    input_index,
                    hashed_messages,
                    tap_sighash_type,
                    leaf,
                    *leaf_index,
                    key_manager,
                    id,
                )?;

                signatures[*leaf_index] = signature;
            }
        };

        Ok(signatures)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn taproot_script_only_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
        hashed_messages: &[Option<Message>],
        tap_sighash_type: &TapSighashType,
        leaf: &ProtocolScript,
        leaf_index: usize,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Option<Signature>, ProtocolBuilderError> {
        if leaf.skip_signing() {
            return Ok(None);
        };

        let schnorr_signature = if leaf.aggregate_signing() {
            let message_id =
                MessageId::new_string_id(transaction_name, input_index as u32, leaf_index as u32);
            key_manager.get_aggregated_signature(
                &leaf.get_verifying_key().unwrap(),
                id,
                &message_id,
            )?
        } else {
            let hashed_message = hashed_messages[leaf_index].unwrap();

            let schnorr_signature = key_manager
                .sign_schnorr_message(&hashed_message, &leaf.get_verifying_key().unwrap())?;

            // Verify the signature.
            if !SignatureVerifier::new().verify_schnorr_signature(
                &schnorr_signature,
                &hashed_message,
                leaf.get_verifying_key().unwrap(),
            ) {
                return Err(ProtocolBuilderError::ScriptSpendSignatureGenerationFailed(
                    transaction_name.to_string(),
                    input_index,
                    leaf_index,
                ));
            };

            schnorr_signature
        };

        Ok(Some(Signature::Taproot(bitcoin::taproot::Signature {
            signature: schnorr_signature,
            sighash_type: *tap_sighash_type,
        })))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn taproot_key_only_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
        hashed_messages: &[Option<Message>],
        tap_sighash_type: &TapSighashType,
        key_path_sign_mode: &SignMode,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Option<Signature>, ProtocolBuilderError> {
        // Compute a signature for the key spend path.
        let key_path_hashed_message = hashed_messages.last().unwrap().unwrap();
        hashed_messages[leaves.len()].as_ref().unwrap();

        let schnorr_signature = if *key_path_sign_mode == SignMode::Aggregate {
            let message_id =
                MessageId::new_string_id(transaction_name, input_index as u32, leaves.len() as u32);

            key_manager.get_aggregated_signature(internal_key, id, &message_id)?
        } else {
            let spend_info = Self::compute_spend_info(internal_key, leaves)?;

            let (schnorr_signature, output_key) = key_manager.sign_schnorr_message_with_tap_tweak(
                &key_path_hashed_message,
                internal_key,
                spend_info.merkle_root(),
            )?;

            // Verify the signature.
            if !SignatureVerifier::new().verify_schnorr_signature(
                &schnorr_signature,
                &key_path_hashed_message,
                output_key,
            ) {
                return Err(ProtocolBuilderError::KeySpendSignatureGenerationFailed(
                    transaction_name.to_string(),
                    input_index,
                ));
            }

            schnorr_signature
        };

        Ok(Some(Signature::Taproot(bitcoin::taproot::Signature {
            signature: schnorr_signature,
            sighash_type: *tap_sighash_type,
        })))
    }

    pub fn ecdsa_key_signature(
        &self,
        hashed_messages: &[Option<Message>],
        ecdsa_sighash_type: &EcdsaSighashType,
        key_manager: &KeyManager,
        public_key: &PublicKey,
    ) -> Result<Vec<Option<Signature>>, ProtocolBuilderError> {
        assert!(
            hashed_messages.len() == 1,
            "Expected only one message to sign"
        );
        assert!(hashed_messages[0].is_some(), "Expected a message to sign");
        let ecdsa_signature =
            key_manager.sign_ecdsa_message(&hashed_messages[0].unwrap(), public_key)?;
        let signature = Signature::Ecdsa(bitcoin::ecdsa::Signature {
            signature: ecdsa_signature,
            sighash_type: *ecdsa_sighash_type,
        });
        Ok(vec![Some(signature)])
    }

    pub fn ecdsa_script_signature(
        &self,
        hashed_messages: &[Option<Message>],
        ecdsa_sighash_type: &EcdsaSighashType,
        key_manager: &KeyManager,
        script: &ProtocolScript,
    ) -> Result<Vec<Option<Signature>>, ProtocolBuilderError> {
        assert!(
            hashed_messages.len() == 1,
            "Expected only one message to sign"
        );
        Ok(if script.skip_signing() {
            vec![None]
        } else {
            let ecdsa_signature = key_manager.sign_ecdsa_message(
                &hashed_messages[0].unwrap(),
                &script.get_verifying_key().unwrap(),
            )?;
            let signature = Signature::Ecdsa(bitcoin::ecdsa::Signature {
                signature: ecdsa_signature,
                sighash_type: *ecdsa_sighash_type,
            });

            vec![Some(signature)]
        })
    }
}

#[allow(clippy::type_complexity)]
fn spend_mode_params(
    leaves: &[ProtocolScript],
    spend_mode: &SpendMode,
) -> Result<
    (
        bool,
        bool,
        Option<SignMode>,
        Option<Vec<(usize, ProtocolScript)>>,
    ),
    ProtocolBuilderError,
> {
    let (key_path, scripts_path, key_path_sign_mode, selected_leaves) = match spend_mode {
        SpendMode::All {
            key_path_sign: key_path_sign_mode,
        } => (
            true,
            true,
            Some(*key_path_sign_mode),
            Some(select_leaves(leaves, &[])),
        ),
        SpendMode::KeyOnly {
            key_path_sign: key_path_sign_mode,
        } => (true, false, Some(*key_path_sign_mode), None),
        SpendMode::ScriptsOnly => (false, true, None, Some(select_leaves(leaves, &[]))),
        SpendMode::Scripts { leaves: indexes } => {
            (false, true, None, Some(select_leaves(leaves, indexes)))
        }
        SpendMode::Script { leaf } => (false, true, None, Some(select_leaves(leaves, &[*leaf]))),
        SpendMode::None => (false, false, None, None),
        SpendMode::Segwit => {
            return Err(ProtocolBuilderError::InvalidSpendMode(
                "Taproot".to_string(),
                spend_mode.clone(),
            ))
        }
    };
    Ok((key_path, scripts_path, key_path_sign_mode, selected_leaves))
}

fn select_leaves(leaves: &[ProtocolScript], indexes: &[usize]) -> Vec<(usize, ProtocolScript)> {
    if indexes.is_empty() {
        return leaves
            .iter()
            .cloned()
            .enumerate()
            .collect::<Vec<(usize, ProtocolScript)>>();
    };

    indexes
        .iter()
        .map(|&leaf_index| (leaf_index, leaves[leaf_index].clone()))
        .collect::<Vec<(usize, ProtocolScript)>>()
}
