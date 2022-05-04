use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Wrong token type")]
    WrongTokenType(String),

    #[error("Only one native token deposit at a time")]
    OneTokenAtATime{},

    #[error("No funds")]
    NoFunds {},

    #[error("Invalid beacon instruction")]
    InvalidBeaconInstruction {},

    #[error("Invalid key instruction")]
    InvalidKeysInInstruction {},

    #[error("Mismatch keys and indexes")]
    InvalidKeysAndIndexes {},

    #[error("Invalid number of signature")]
    InvalidNumberOfSignature {},

    #[error("Invalid beacon signature")]
    InvalidBeaconSignature {},

    #[error("Invalid beacon merkle tree")]
    InvalidBeaconMerkleTree {},

    #[error("Tx burn already used")]
    AlreadyUsed {},

    #[error("The beacon list is empty")]
    InvalidBeaconList {},

    #[error("Invalid beacon heights")]
    InvalidBeaconHeights {},
}
