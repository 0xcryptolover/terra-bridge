use schemars::{JsonSchema};
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Uint128};
use cw_storage_plus::{Map, Item};

pub const BEACONS: Map<Uint128, Vec<[u8; 64]>> = Map::new("beacons");
// ascending list
pub const BEACON_HEIGHTS: Item<Vec<Uint128>> = Item::new("heights");
pub const BURNTX: Map<&[u8; 32], bool> = Map::new("burntx");
pub const NATIVE_TOKENS: Map<String, String> = Map::new("tokens");
pub const TOTAL_NATIVE_TOKENS: Item<Uint128> = Item::new("total");
