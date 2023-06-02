import { blob, ic, match, nat32, Opt, Record, Vec, $query, $update } from 'azle';
import { managementCanister } from 'azle/canisters/management';
import { sha256 } from 'js-sha256';

let randomness: blob = Uint8Array.from([]);

type Db = {
    users: {
        [id: string] : User;
    };
};

type User = Record <{
    id: string;
    username: string;
    age: nat32;
}>;

let db: Db = {
    users: {},
};

$query;
export function get(id: string) : Opt<User> {
    const value = db.users[id];

    return value !== undefined ? Opt.Some(value) : Opt.None;
};

$update;
export async function set(username: string, age: nat32): Promise<string> {
    const id = sha256(await getRandomness());

    const user: User = {
        id,
        username,
        age,
    };

    db.users[id] = user;

    return id;
};

$query;
export function getUsers(): Vec<User> {
    return Object.values(db.users);
};

$update;
export async function getRandomness(): Promise<blob> {
    const result = await managementCanister.raw_rand().call();

    return match(result, {
        Ok: (ok) => {
            randomness = ok;    //storing the random generator to randomness variable abobve
            return ok;
        },
        Err: (err) => ic.trap(err),
    })
};

$query;
export function randomHash() : string {
    return sha256(randomness);
};

$update;
export async function tecdsa(): Promise<blob> {
    const result = await managementCanister.ecdsa_public_key({
        canister_id: Opt.None,
        derivation_path: [],
        key_id: {
            curve: {
                secp256k1: null
            },
            name: "dfx_test_key",
        }
    }).call();

    return match(result, {
        Ok: (ok) => ok.public_key,
        Err: (err) => ic.trap(err),
    });
}