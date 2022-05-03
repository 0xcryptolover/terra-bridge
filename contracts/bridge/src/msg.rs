use cw20::Cw20ReceiveMsg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub committees: Vec<[u8; 64]>,
    pub heights: Vec<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Deposit {
        incognitoAddr: String,
    },
    Withdraw {
        proof: UnshieldRequest
    },
    /// This accepts a properly-encoded ReceiveMsg from a cw20 contract
    Receive(Cw20ReceiveMsg),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// GetCount returns the current count as a json-encoded number
    GetCount {},
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct CountResponse {
    pub count: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveMsg {
    /// Only valid cw20 message is to shield cw20 token
    Deposit {},
}

/// Reserve liquidity
#[derive(Clone, Debug, PartialEq)]
pub struct UnshieldRequest {
    // instruction in bytes
    pub inst: [u8; 162],
    // beacon height
    pub height: u64,
    // inst paths to build merkle tree
    pub inst_paths: Vec<[u8; 32]>,
    // inst path indicator
    pub inst_path_is_lefts: Vec<bool>,
    // instruction root
    pub inst_root: [u8; 32],
    // blkData
    pub blk_data: [u8; 32],
    // signature index
    pub indexes: Vec<u8>,
    // signature
    pub signatures: Vec<[u8; 65]>
}
