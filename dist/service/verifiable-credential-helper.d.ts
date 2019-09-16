import { ChallengeRequest, VerifiableCredential } from 'vp-toolkit-models';
import { EventHandler } from 'universal-ledger-agent';
import { AddressHelper } from './address-helper';
import { VerifiableCredentialGenerator } from 'vp-toolkit';
export declare class VerifiableCredentialHelper {
    private _vcGenerator;
    private _addressHelper;
    constructor(_vcGenerator: VerifiableCredentialGenerator, _addressHelper: AddressHelper);
    /**
     * Returns a collection of self-attested VC's to prove ownership over our DID's
     *
     * @param {ChallengeRequest} challengeRequest
     * @param {number} accountId provided by the wallet implementation
     * @param {EventHandler} eventHandler
     * @return {Promise<VerifiableCredential[]>} the self-attested VC's
     */
    generateSelfAttestedVCs(challengeRequest: ChallengeRequest, accountId: number, eventHandler: EventHandler): Promise<{
        accountId: number;
        keyId: number;
        vc: VerifiableCredential;
    }[]>;
    /**
     * The verifier asks one or more VC's
     * using the toVerify field in the
     * ChallengeRequest. This method returns
     * a collection of VC's which match the
     * verifier's needs.
     *
     * @param {ChallengeRequest} challengeRequest
     * @param  {EventHandler} eventHandler
     * @return {Promise<VerifiableCredential[]>} the self-attested VC's
     */
    findVCsForChallengeRequest(challengeRequest: ChallengeRequest, eventHandler: EventHandler): Promise<{
        matching: VerifiableCredential[];
        missing: {
            predicate: string;
            reason: string;
        }[];
    }>;
    /**
     * Removes revoked credentials, saves issued
     * credentals and saves a Transaction object.
     *
     * @todo remove revoked credentials
     * @param {string} counterpartyId              The id of the counterparty
     * @param {string[]} verifiedVcs               Collection of VerifiableCredential nonces which were sent
     * @param {VerifiableCredential[]} credentials VP sent by the counterparty, containing attested VC's
     * @param {EventHandler} eventHandler          To send messages to the ULA data plugin
     */
    processTransaction(counterpartyId: string, verifiedVcs: string[], credentials: VerifiableCredential[], eventHandler: EventHandler): Promise<void>;
    /**
     * Save the Verifiable Credentials which
     * were sent by the issuer. A VC will only
     * be saved when the DID + predicate
     * matches with the address details in
     * storage.
     * This method does NOT verify any
     * signatures!
     *
     * @param {VerifiableCredential[]} credentials The Verifiable Presentation from the issuer
     * @param {EventHandler} eventHandler
     */
    saveIssuedVCs(credentials: VerifiableCredential[], eventHandler: EventHandler): Promise<void>;
    private getUniqueCredentials;
    private containsMissingPredicate;
}
