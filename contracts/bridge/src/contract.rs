#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, DepsMut, Env, MessageInfo, Response, from_slice, SubMsg, WasmMsg, coins, BankMsg, Uint256, StdResult};
use cosmwasm_std::{Addr, Uint128};
use cw2::{set_contract_version};
use std::convert::{TryFrom};
use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, ReceiveMsg, UnshieldRequest};
use cw20::{Balance, Cw20ReceiveMsg, Cw20CoinVerified, Cw20ExecuteMsg};
use crate::state::{BEACON_HEIGHTS, BEACONS, BURNTX, NATIVE_TOKENS, TOTAL_NATIVE_TOKENS};
use arrayref::{array_refs, array_ref};
use cw_storage_plus::KeyDeserialize;
use sha3::{Digest, Keccak256};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:bridge";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
const LEN: usize = 1 + 1 + 32 + 32 + 32 + 32; // ignore last 32 bytes in instruction

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    TOTAL_NATIVE_TOKENS.save(deps.storage, &Uint128::new(0));
    BEACONS.save(deps.storage, msg.height, &msg.committees);
    BEACON_HEIGHTS.save(deps.storage, &vec![msg.height]);
    Ok(Response::new()
       .add_attribute("method", "instantiate")
       .add_attribute("owner", info.sender)
       .add_attribute("heights", msg.height))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Deposit { incognitoAddr } => try_deposit(deps, Balance::from(info.funds), incognitoAddr),
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
                    let mut ptoken_id = NATIVE_TOKENS.may_load(deps.storage, &balance.clone().denom)?.unwrap_or_default();
                    // check native token existed
                    if ptoken_id == "" {
                        let total_native = TOTAL_NATIVE_TOKENS.may_load(deps.storage)?.unwrap_or_default();
                        ptoken_id = hex::encode(Uint256::from(total_native.u128()).to_be_bytes());
                        NATIVE_TOKENS.update(deps.storage, &balance.clone().denom, |_| -> StdResult<_> {
                            Ok(ptoken_id)
                        })?;
                        TOTAL_NATIVE_TOKENS.update(deps.storage, |_| -> StdResult<_> {
                            Ok(total_native.checked_add(Uint128::new(1))?)
                        })?;
                    }
                    Ok((ptoken_id.clone(), balance.amount))
                }
                _ => Err(ContractError::OneTokenAtATime {}),
            }
        },
        Balance::Cw20(have) => {
            Ok((have.address.into_string(), have.amount))
        }
        _ => Err(ContractError::WrongTokenType("The token type not supported".into())),
    }?;

    Ok(Response::new().
        add_attribute("token", token).
        add_attribute("incognitoAddress", incognito).
        add_attribute("value", amount)
    )
}
pub fn try_withdraw(deps: DepsMut, unshieldInfo: UnshieldRequest) -> Result<Response, ContractError> {
    let inst = hex::decode(unshieldInfo.inst).unwrap_or_default();
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
        tx_id, // todo: store this data
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
    if unshieldInfo.indexes.len() != unshieldInfo.signatures.len() ||
        unshieldInfo.signatures.len() != unshieldInfo.vs.len(){
        return Err(ContractError::InvalidKeysAndIndexes {});
    }

    let beacons = get_beacons(&deps, unshieldInfo.height)?;
    if beacons.len() == 0 {
        return Err(ContractError::InvalidBeaconList {});
    }

    if unshieldInfo.signatures.len() <= beacons.len() * 2 / 3 {
        return Err(ContractError::InvalidNumberOfSignature {});
    }

    let api = deps.api;
    let mut blk_data_bytes = unshieldInfo.blk_data.to_vec();
    blk_data_bytes.extend_from_slice(&unshieldInfo.inst_root);
    // Get double block hash from instRoot and other data
    let blk = hash_keccak(&hash_keccak(&blk_data_bytes[..]).0).0;

    for i in 0..unshieldInfo.indexes.len() {
        let (s_r, v) = (hex::decode(unshieldInfo.signatures[i].clone()).unwrap_or_default(), unshieldInfo.vs[i]);
        let beacon_key_from_signature_result = api.secp256k1_recover_pubkey(
            &blk,
            &s_r[..],
            v,
        ).unwrap();
        let index_beacon = unshieldInfo.indexes[i];
        let beacon_key = beacons[index_beacon as usize].clone();
        if hex::encode(beacon_key_from_signature_result) != beacon_key {
            return Err(ContractError::InvalidBeaconSignature {});
        }
    }

    // append block height to instruction
    let height_vec = append_at_top(unshieldInfo.height);
    let mut inst_vec = inst.to_vec();
    inst_vec.extend_from_slice(&height_vec);
    let inst_hash = hash_keccak(&inst_vec[..]).0;
    if !instruction_in_merkle_tree(
        &inst_hash,
        &unshieldInfo.inst_root,
        &unshieldInfo.inst_paths,
        &unshieldInfo.inst_path_is_lefts
    ) {
        return Err(ContractError::InvalidBeaconMerkleTree {});
    }

    // store tx burn
    let tx_id_str = hex::encode(tx_id);
    BURNTX.update(deps.storage, &tx_id_str, |tx| match tx {
        Some(_) => Err(ContractError::AlreadyUsed {}),
        None => Ok(1),
    })?;

    let token_addr = Addr::from_vec(token.to_vec())?.into_string();
    let recipient_str = Addr::from_vec(receiver_key.to_vec())?.into_string();
    let token_id: String = NATIVE_TOKENS.may_load(deps.storage, &token_addr)?.unwrap_or_default();

    let amount_str: String = coin_to_string(unshield_amount, &token_addr);
    let message ;
    // transfer tokens
    if token_id != "" {
        let amount = coins(unshield_amount.u128(), token_addr.clone());
        message = SubMsg::new(BankMsg::Send {
            to_address: recipient_str,
            amount,
        });
    } else {
        let transfer = Cw20ExecuteMsg::Transfer {
            recipient: recipient_str,
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
    Ok(BEACONS.may_load(deps.storage, Uint128::from(r as u128))?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{
        coin, from_slice, CosmosMsg, OverflowError, OverflowOperation, StdError, Storage,
    };
    use cw20::Denom;
    use cw4::{member_key, TOTAL_KEY};
    use cw_controllers::{AdminError, Claim, HookError};
    use cw_utils::Duration;

    use crate::error::ContractError;

    use super::*;

    const INIT_ADMIN: &str = "juan";
    const USER1: &str = "somebody";
    const USER2: &str = "else";
    const USER3: &str = "funny";
    const DENOM: &str = "stake";
    const TOKENS_PER_WEIGHT: Uint128 = Uint128::new(1_000);
    const MIN_BOND: Uint128 = Uint128::new(5_000);
    const UNBONDING_BLOCKS: u64 = 100;
    const CW20_ADDRESS: &str = "wasm1234567890";

    // fn default_instantiate(deps: DepsMut) {
    //     do_instantiate(
    //         deps,
    //         TOKENS_PER_WEIGHT,
    //         MIN_BOND,
    //         Duration::Height(UNBONDING_BLOCKS),
    //     )
    // }
    //
    // #[test]
    // fn proper_initialization() {
    //     let mut deps = mock_dependencies();
    //
    //     let msg = InstantiateMsg { count: 17 };
    //     let info = mock_info("creator", &coins(1000, "earth"));
    //
    //     // we can just call .unwrap() to assert this was a success
    //     let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
    //     assert_eq!(0, res.messages.len());
    //
    //     // it worked, let's query the state
    //     let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
    //     let value: CountResponse = from_binary(&res).unwrap();
    //     assert_eq!(17, value.count);
    // }

    #[test]
    fn increment() {
        // let mut deps = mock_dependencies(&coins(2, "token"));
        //
        // let msg = InstantiateMsg { count: 17 };
        // let info = mock_info("creator", &coins(2, "token"));
        // let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        //
        // // beneficiary can release it
        // let info = mock_info("anyone", &coins(2, "token"));
        // let msg = ExecuteMsg::Increment {};
        // let _res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        //
        // // should increase counter by 1
        // let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        // let value: CountResponse = from_binary(&res).unwrap();
        // assert_eq!(18, value.count);
    }

    #[test]
    fn reset() {
        // let mut deps = mock_dependencies(&coins(2, "token"));
        //
        // let msg = InstantiateMsg { count: 17 };
        // let info = mock_info("creator", &coins(2, "token"));
        // let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        //
        // // beneficiary can release it
        // let unauth_info = mock_info("anyone", &coins(2, "token"));
        // let msg = ExecuteMsg::Reset { count: 5 };
        // let res = execute(deps.as_mut(), mock_env(), unauth_info, msg);
        // match res {
        //     Err(ContractError::Unauthorized {}) => {}
        //     _ => panic!("Must return unauthorized error"),
        // }
        //
        // // only the original creator can reset the counter
        // let auth_info = mock_info("creator", &coins(2, "token"));
        // let msg = ExecuteMsg::Reset { count: 5 };
        // let _res = execute(deps.as_mut(), mock_env(), auth_info, msg).unwrap();
        //
        // // should now be 5
        // let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        // let value: CountResponse = from_binary(&res).unwrap();
        // assert_eq!(5, value.count);
    }
}
