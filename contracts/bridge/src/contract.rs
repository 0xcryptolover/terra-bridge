#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, DepsMut, Env, MessageInfo, Response, from_slice, SubMsg, WasmMsg, coins, BankMsg, StdResult, Deps, Binary};
use cosmwasm_std::{Addr, Uint128};
use cw2::{set_contract_version};
use std::convert::{TryFrom};
use crate::error::ContractError;
use crate::msg::{BeaconResponse, ExecuteMsg, InstantiateMsg, PtokenResponse, QueryMsg, ReceiveMsg, TotalNativeResponse, TxBurnResponse, UnshieldRequest, MigrateMsg};
use cw20::{Balance, Cw20ReceiveMsg, Cw20CoinVerified, Cw20ExecuteMsg};
use crate::state::{BEACON_HEIGHTS, BEACONS, BURNTX, NATIVE_TOKENS, TOTAL_NATIVE_TOKENS};
use sha3::{Digest, Keccak256};
use arrayref::{array_refs, array_ref};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:bridge";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
const LEN: usize = 1 + 1 + 32 + 32 + 32 + 32; // ignore last 32 bytes in instruction

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    TOTAL_NATIVE_TOKENS.save(deps.storage, &Uint128::new(0))?;
    BEACONS.save(deps.storage, &msg.height.to_be_bytes()[..], &msg.committees)?;
    BEACON_HEIGHTS.save(deps.storage, &vec![Uint128::new(msg.height)])?;
    Ok(Response::new()
       .add_attribute("method", "instantiate")
       .add_attribute("owner", info.sender)
       .add_attribute("heights", msg.height.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Deposit { incognito_addr } => try_deposit(deps, Balance::from(info.funds), incognito_addr),
        ExecuteMsg::Withdraw { proof } => try_withdraw(deps, proof),
        ExecuteMsg::Receive(msg) => execute_receive(deps, _env, info, msg),
    }
}

pub fn try_deposit(deps: DepsMut, amount: Balance, incognito: String) -> Result<Response, ContractError> {
    // detect token deposit and emit event
    let (token, amount) = match &amount {
        Balance::Native(have) => {
            match have.0.len() {
                0 => Err(ContractError::NoFunds {}),
                1 => {
                    let balance = &have.0[0];
                    let is_exist = NATIVE_TOKENS.may_load(deps.storage, &balance.clone().denom)?.unwrap_or_default();
                    // check native token existed
                    if is_exist == 0 {
                        let total_native = TOTAL_NATIVE_TOKENS.may_load(deps.storage)?.unwrap_or_default();
                        NATIVE_TOKENS.update(deps.storage, &balance.clone().denom, |_| -> StdResult<_> {
                            Ok(1)
                        })?;
                        TOTAL_NATIVE_TOKENS.update(deps.storage, |_| -> StdResult<_> {
                            Ok(total_native.checked_add(Uint128::new(1))?)
                        })?;
                    }
                    Ok((balance.clone().denom, balance.amount))
                }
                _ => Err(ContractError::OneTokenAtATime {}),
            }
        },
        Balance::Cw20(have) => {
            Ok((have.address.clone().into_string(), have.amount))
        }
    }?;

    Ok(Response::new().
        add_attribute("token", token).
        add_attribute("incognitoAddress", incognito).
        add_attribute("value", amount)
    )
}
pub fn try_withdraw(deps: DepsMut, unshield_info: UnshieldRequest) -> Result<Response, ContractError> {
    let inst = hex::decode(unshield_info.inst).unwrap_or_default();
    if inst.len() < LEN {
        return Err(ContractError::InvalidBeaconInstruction {});
    }
    let inst_ = array_ref![inst, 0, LEN];
    #[allow(clippy::ptr_offset_with_cast)]
        let (
        meta_type,
        shard_id,
        token,
        receiver_key,
        _,
        unshield_amount,
        tx_id,
    ) = array_refs![
         inst_,
         1,
         1,
         32,
         32,
         24,
         8,
         32
     ];
    let meta_type = u8::from_le_bytes(*meta_type);
    let shard_id = u8::from_le_bytes(*shard_id);
    let unshield_amount = Uint128::from(u64::from_be_bytes(*unshield_amount));

    // validate metatype and key provided
    if (meta_type != 157 && meta_type != 158) || shard_id != 1 {
        return Err(ContractError::InvalidKeysInInstruction {});
    }

    // verify beacon signature
    if unshield_info.indexes.len() != unshield_info.signatures.len() ||
        unshield_info.signatures.len() != unshield_info.vs.len(){
        return Err(ContractError::InvalidKeysAndIndexes {});
    }

    let beacons = get_beacons(&deps, unshield_info.height)?;
    if beacons.len() == 0 {
        return Err(ContractError::InvalidBeaconList {});
    }

    if unshield_info.signatures.len() <= beacons.len() * 2 / 3 {
        return Err(ContractError::InvalidNumberOfSignature {});
    }

    let api = deps.api;
    let mut blk_data_bytes = unshield_info.blk_data.to_vec();
    blk_data_bytes.extend_from_slice(&unshield_info.inst_root);
    // Get double block hash from instRoot and other data
    let blk = hash_keccak(&hash_keccak(&blk_data_bytes[..]).0).0;

    for i in 0..unshield_info.indexes.len() {
        let (s_r, v) = (hex::decode(unshield_info.signatures[i].clone()).unwrap_or_default(), unshield_info.vs[i]);
        let beacon_key_from_signature_result = api.secp256k1_recover_pubkey(
            &blk,
            &s_r[..],
            v,
        ).unwrap();
        let index_beacon = unshield_info.indexes[i];
        let beacon_key = beacons[index_beacon as usize].clone();
        if hex::encode(beacon_key_from_signature_result) != beacon_key {
            return Err(ContractError::InvalidBeaconSignature {});
        }
    }

    // append block height to instruction
    let height_vec = append_at_top(unshield_info.height);
    let mut inst_vec = inst.to_vec();
    inst_vec.extend_from_slice(&height_vec);
    let inst_hash = hash_keccak(&inst_vec[..]).0;
    if !instruction_in_merkle_tree(
        &inst_hash,
        &unshield_info.inst_root,
        &unshield_info.inst_paths,
        &unshield_info.inst_path_is_lefts
    ) {
        return Err(ContractError::InvalidBeaconMerkleTree {});
    }

    // store tx burn
    let tx_id_str = hex::encode(tx_id);
    BURNTX.update(deps.storage, &tx_id_str, |tx| match tx {
        Some(_) => Err(ContractError::AlreadyUsed {}),
        None => Ok(1),
    })?;

    let token_addr = hex::encode(token);
    let recipient_str = hex::encode(receiver_key);
    let is_native: u8 = NATIVE_TOKENS.may_load(deps.storage, &token_addr)?.unwrap_or_default();
    let amount_str: String = coin_to_string(unshield_amount, &token_addr);
    let message ;
    // transfer tokens
    if is_native == 1 {
        let amount = coins(unshield_amount.u128(), token_addr.clone());
        message = SubMsg::new(BankMsg::Send {
            to_address: recipient_str.clone(),
            amount,
        });
    } else {
        let transfer = Cw20ExecuteMsg::Transfer {
            recipient: recipient_str.clone(),
            amount: unshield_amount,
        };
        message = SubMsg::new(WasmMsg::Execute {
            contract_addr: token_addr.clone(),
            msg: to_binary( &transfer)?,
            funds: vec! [],
        })
    }

    Ok(Response::new()
        .add_submessage(message)
        .add_attribute("action", "withdraw")
        .add_attribute("tokens", amount_str)
        .add_attribute("receiver", recipient_str.clone()))
}

pub fn execute_receive(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    wrapper: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    // info.sender is the address of the cw20 contract (that re-sent this message).
    // wrapper.sender is the address of the user that requested the cw20 contract to send this.
    // This cannot be fully trusted (the cw20 contract can fake it), so only use it for actions
    // in the address's favor (like paying/bonding tokens, not withdrawals)
    let msg: ReceiveMsg = from_slice(&wrapper.msg)?;
    let balance = Balance::Cw20(Cw20CoinVerified {
        address: info.sender,
        amount: wrapper.amount,
    });

    match msg {
        ReceiveMsg::Deposit {} => {
            try_deposit( deps,balance, wrapper.msg.to_string())
        }
    }
}

#[inline]
fn coin_to_string(amount: Uint128, denom: &str) -> String {
    format!("{} {}", amount, denom)
}

pub const HASH_BYTES: usize = 32;
#[repr(transparent)]
pub struct Hash(pub [u8; HASH_BYTES]);

fn instruction_in_merkle_tree(
    leaf: &[u8; 32],
    root: &[u8; 32],
    paths: &Vec<[u8; 32]>,
    path_lefts: &Vec<bool>
) -> bool {
    if paths.len() != path_lefts.len() {
        return false;
    }
    let mut build_root = leaf.clone();
    let mut temp;
    for i in 0..paths.len() {
        if path_lefts[i] {
            temp = paths[i][..].to_vec();
            temp.extend_from_slice(&build_root[..]);
        } else if paths[i] == [0; 32] {
            temp = build_root[..].to_vec();
            temp.extend_from_slice(&build_root[..]);
        } else {
            temp = build_root[..].to_vec();
            temp.extend_from_slice(&paths[i][..]);
        }
        build_root = hash_keccak(&temp[..]).0;
    }
    build_root == *root
}

fn append_at_top(input: Uint128) -> Vec<u8>  {
    let mut  input_vec = input.to_be_bytes().to_vec();
    for _ in 0..24 {
        input_vec.insert(0, 0);
    }

    input_vec
}

fn hash_keccak(temp: &[u8]) -> Hash {
    let mut hasher = Keccak256::default();
    hasher.update(temp);
    Hash(<[u8; HASH_BYTES]>::try_from(hasher.finalize().as_slice()).unwrap())
}

fn get_beacons(deps: &DepsMut, height: Uint128) -> Result<Vec<String>, ContractError> {
    let beacon_heights = BEACON_HEIGHTS.may_load(deps.storage)?.unwrap_or_default();
    if beacon_heights.len() == 0 {
        return Err(ContractError::InvalidBeaconHeights {});
    }
    let mut l = 0;
    let mut r = beacon_heights.len();
    loop {
        let m = (r + l) / 2;
        if height >= beacon_heights[m] {
            l = m;
        } else {
            r = m - 1;
        }
        if l == r {
            break;
        }
    }
    Ok(BEACONS.may_load(deps.storage, &r.to_be_bytes()[..])?.unwrap_or_default())
}

/// queries
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetBeacons {index} => to_binary(&query_beacon(deps, index)?),
        QueryMsg::CheckTxBurn {burnid} => to_binary(&query_tx_burn(deps, burnid.as_str())?),
    }
}

// get beacon by height
pub fn query_beacon(deps: Deps, index: Uint128) -> StdResult<BeaconResponse> {
    let heights = BEACON_HEIGHTS.may_load(deps.storage)?.unwrap_or_default();
    let mut beacons: Vec<String> = vec![];
    let mut height: Uint128 = Uint128::new(0);
    let index_usize = index.u128() as usize;
    if index_usize < heights.len() {
        height = heights[index_usize];
        beacons = BEACONS.may_load(deps.storage, height.to_be_bytes().as_ref())?.unwrap_or_default();
    }

    Ok(BeaconResponse { beacons, height })
}

// get burn txid is used
pub fn query_tx_burn(deps: Deps, txburn: &str) -> StdResult<TxBurnResponse> {
    let res = BURNTX.may_load(deps.storage, txburn)?.unwrap_or_default();
    Ok(TxBurnResponse { is_used: res })
}

// get total native tokens
pub fn query_total_native(deps: Deps) -> StdResult<TotalNativeResponse> {
    let res = TOTAL_NATIVE_TOKENS.may_load(deps.storage)?.unwrap_or_default();
    Ok(TotalNativeResponse { result: res })
}

// get private external token for native tokens
pub fn query_native_ptoken(deps: Deps, native_token: &str) -> StdResult<PtokenResponse> {
    let res = NATIVE_TOKENS.may_load(deps.storage, native_token)?.unwrap_or_default();
    Ok(PtokenResponse { result: res })
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use super::*;

    const BEACON_1: [&str; 2] = ["beacon1", "beacon2"];
    const HEIGHT_1: u128 = 0;
    const INCOGNITO_ADDRESS: &str = "Address1";
    const USER1: &str = "user1";
    const DENOM: &str = "shield";
    const DENOM1: &str = "shield2";
    const SHIELD_AMOUNT: u128 = 1_000_000_000;
    const CW20_ADDRESS: &str = "wasm1234567890";

    fn default_instantiate(deps: DepsMut) {
        let mut beacons: Vec<String> = vec![];
        for i in 0..BEACON_1.len() {
            beacons.push(BEACON_1[i].to_string());
        }
        let msg = InstantiateMsg {
            committees: beacons,
            height: HEIGHT_1,
        };
        let info = mock_info("creator", &[]);
        instantiate(deps, mock_env(), info, msg).unwrap();
    }

    fn deposit_native(mut deps: DepsMut, amount: u128, denom: String) {
        let mut env = mock_env();
        let msg = ExecuteMsg::Deposit {
            incognito_addr: INCOGNITO_ADDRESS.to_string()
        };
        let info = mock_info(USER1, &coins(amount, denom));
        execute(deps.branch(), env.clone(), info, msg).unwrap();
    }

    fn deposit_cw20(mut deps: DepsMut, amount: u128) {
        let mut env = mock_env();

        let msg = ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: USER1.to_string(),
            amount: Uint128::new(amount),
            msg: to_binary(&ReceiveMsg::Deposit {}).unwrap(),
        });
        let info = mock_info(CW20_ADDRESS, &[]);
        execute(deps.branch(), env.clone(), info, msg).unwrap();
    }

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies(&[]);
        default_instantiate(deps.as_mut());

        // it worked, let's query the state
        let res = query_beacon(deps.as_ref(), Uint128::new(HEIGHT_1)).unwrap();
        let mut beacons: Vec<String> = vec![];
        for i in 0..BEACON_1.len() {
            beacons.push(BEACON_1[i].to_string());
        }
        assert_eq!(res.beacons, beacons);
    }

    #[test]
    fn deposit() {
        let mut deps = mock_dependencies(&[]);
        default_instantiate(deps.as_mut());
        let mut beacons: Vec<String> = vec![];
        for i in 0..BEACON_1.len() {
            beacons.push(BEACON_1[i].to_string());
        }
        let res = query_beacon(deps.as_ref(), Uint128::new(HEIGHT_1)).unwrap();
        assert_eq!(res.beacons, beacons);

        let mut total_native_token = query_total_native(deps.as_ref()).unwrap();
        assert_eq!(0, total_native_token.result.u128());

        let mut ptoken = query_native_ptoken(deps.as_ref(), DENOM).unwrap();
        assert_eq!(ptoken.result, 0);

        // test deposit native tokens
        deposit_native(deps.as_mut(), SHIELD_AMOUNT, DENOM.to_string());
        total_native_token = query_total_native(deps.as_ref()).unwrap();
        assert_eq!(1, total_native_token.result.u128());
        ptoken = query_native_ptoken(deps.as_ref(), DENOM).unwrap();
        assert_eq!(ptoken.result, 1);

        ptoken = query_native_ptoken(deps.as_ref(), DENOM1).unwrap();
        assert_eq!(ptoken.result, 0);

        deposit_native(deps.as_mut(), SHIELD_AMOUNT, DENOM1.to_string());
        total_native_token = query_total_native(deps.as_ref()).unwrap();
        assert_eq!(2, total_native_token.result.u128());
        ptoken = query_native_ptoken(deps.as_ref(), DENOM1).unwrap();
        assert_eq!(ptoken.result, 1);

        // test deposit tokens
        deposit_cw20(deps.as_mut(), SHIELD_AMOUNT);
        total_native_token = query_total_native(deps.as_ref()).unwrap();
        assert_eq!(2, total_native_token.result.u128());
    }

    #[test]
    fn withdraw() {

    }
}
