use cosmwasm_std::{Addr, DepsMut, StdResult, to_binary, Uint128, WasmQuery};
use cw20::{BalanceResponse, Cw20QueryMsg, TokenInfoResponse};

pub fn get_native_balance(
    deps: DepsMut,
    from: &Addr,
    token: &str,
) -> StdResult<(Uint128, u8)> {
    let amount = deps.querier.query_balance(from, token)?.amount;
    Ok((amount, 6))
}

pub fn get_token_balance(
    deps: DepsMut,
    from: &Addr,
    token: &str,
) -> StdResult<(Uint128, u8)> {
    let mut query = WasmQuery::Smart {
        contract_addr: token.to_string(),
        msg: to_binary(&Cw20QueryMsg::Balance {
            address: from.into(),
        })?,
    };
    let res: BalanceResponse = deps.querier.query(&query.into())?;
    query = WasmQuery::Smart {
        contract_addr: token.to_string(),
        msg: to_binary(&Cw20QueryMsg::TokenInfo {})?,
    };
    let res2: TokenInfoResponse = deps.querier.query(&query.into())?;
    Ok((res.balance, res2.decimals))
}
