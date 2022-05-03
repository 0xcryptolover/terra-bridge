use schemars::{JsonSchema};
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Uint128};
use cw_storage_plus::{Map};

pub const BEACONS: Map<Uint128, Vec<[u8; 64]>> = Map::new("beacons");
pub const BURNTX: Map<&[u8; 32], bool> = Map::new("burntx");
