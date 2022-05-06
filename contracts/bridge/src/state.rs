use cosmwasm_std::{Uint128};
use cw_storage_plus::{Map, Item};

pub const BEACONS: Map<&[u8], Vec<String>> = Map::new("beacons");
// ascending list
pub const BEACON_HEIGHTS: Item<Vec<Uint128>> = Item::new("heights");
pub const BURNTX: Map<&str, u8> = Map::new("burntx");
