import fetch from 'isomorphic-fetch';
import { Coins, LCDClient, MsgExecuteContract, MnemonicKey } from '@terra-money/terra.js';
const gasPrices =  await fetch('https://bombay-fcd.terra.dev/v1/txs/gas_prices');
const gasPricesJson = await gasPrices.json();
const gasPricesCoins = new Coins(gasPricesJson);
const lcd = new LCDClient({
    URL: "https://bombay-lcd.terra.dev/", // Use "https://lcd.terra.dev" for prod "http://localhost:1317" for localterra.
    chainID: "bombay-12", // Use "columbus-5" for production or "localterra".
    gasPrices: gasPricesCoins,
    gasAdjustment: "1.5", // Increase gas price slightly so transactions go through smoothly.
    gas: 10000000,
});

const mk = new MnemonicKey({
    mnemonic: 'wink fringe review smart venture inflict climb usual dice vast mass dry coach announce awesome crew hair thrive virtual nephew ramp eye helmet together',
});
const wallet = lcd.wallet(mk);
const pool = "terra1hzgsea6kq3hu76h5dkld248k0z8uh3e7aw87dd"; // The LUNA/UST terraswap contract address on Bombay.
// call deposit native token
const terraShield = new MsgExecuteContract(
    wallet.key.accAddress,
    pool,
    {
        deposit: {
            incognito_addr: "12sfD6DYsmYFGvZHbkmVhQiKyapWwshxKtMDZV51UFpXwaauCZ7Zyp69ctAQo3BJdKpZeZhVkFfCd8BgT6n4sMuRAhszpJ6pbwXct3Mr5kvCzDEgBz7h9mgoGuqwt83CjLCDuX7b7hP6gf9RWuPb",
        }
    },
    new Coins({ uusd: '100000' })
);

const tx = await wallet.createAndSignTx({ msgs: [terraShield] });
const result = await lcd.tx.broadcast(tx);

console.log(result);