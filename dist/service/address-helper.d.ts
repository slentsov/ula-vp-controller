import { Address } from 'ula-vc-data-management';
import { CryptUtil } from 'crypt-util';
import { EventHandler } from 'universal-ledger-agent';
import { VerifiableCredential } from 'vp-toolkit-models';
export declare class AddressHelper {
    private _cryptUtil;
    constructor(_cryptUtil: CryptUtil);
    /**
     * Generates a new address from the given accountId
     * and sends a save-address message to the ULA to
     * persist the info through another plugin.
     * (we advise to use ula-vc-data-management)
     *
     * @param {number} accountId
     * @param {string} predicate
     * @param  {EventHandler} eventHandler - used to
     * @return {Promise<string>} The generated public address
     */
    generateAndSaveAddressDetails(accountId: number, predicate: string, eventHandler: EventHandler): Promise<Address>;
    /**
     * Get the address details for existing verifiable
     * credentials. The verifiable credential must be
     * in the format 'did:<anything>:<ethaddress>'
     *
     * @param {VerifiableCredential[]} credentials
     * @param {EventHandler} eventHandler
     * @return {Promise<void>}
     */
    findDidInfoForVCs(credentials: VerifiableCredential[], eventHandler: EventHandler): Promise<Address[]>;
}
