"use strict";
/*
 *  Copyright 2019 Coöperatieve Rabobank U.A.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
class VerifiableCredentialHelper {
    constructor(_vcGenerator, _addressHelper) {
        this._vcGenerator = _vcGenerator;
        this._addressHelper = _addressHelper;
    }
    /**
     * Returns a collection of self-attested VC's to prove ownership over our DID's
     *
     * @param {ChallengeRequest} challengeRequest
     * @param {number} accountId provided by the wallet implementation
     * @param {EventHandler} eventHandler
     * @return {Promise<VerifiableCredential[]>} the self-attested VC's
     */
    generateSelfAttestedVCs(challengeRequest, accountId, eventHandler) {
        return __awaiter(this, void 0, void 0, function* () {
            const verifiableCredentials = [];
            for (const toAttest of challengeRequest.toAttest) {
                const addressDetails = yield this._addressHelper.generateAndSaveAddressDetails(accountId, toAttest.predicate, eventHandler);
                const did = 'did:eth:' + addressDetails.address;
                const selfAttestedVc = this._vcGenerator.generateVerifiableCredential({
                    type: ['VerifiableCredential', 'DidOwnership'],
                    credentialSubject: {},
                    '@context': [toAttest.predicate],
                    issuanceDate: new Date(),
                    issuer: did
                }, accountId, addressDetails.keyId);
                verifiableCredentials.push({ accountId: accountId, keyId: addressDetails.keyId, vc: selfAttestedVc });
            }
            return verifiableCredentials;
        });
    }
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
    findVCsForChallengeRequest(challengeRequest, eventHandler) {
        return __awaiter(this, void 0, void 0, function* () {
            if (challengeRequest.toVerify.length === 0) {
                return {
                    matching: [],
                    missing: []
                };
            }
            const matchingVerifiableCredentials = [];
            const failedCredentials = []; // These credentials do not pass the whitelist check
            const missingVCs = [];
            const regex = new RegExp('(' + challengeRequest.toVerify.map(value => value.predicate).join(')|(') + ')', 'g');
            yield new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
                // Get all credentials that match contain the predicate in their context arrays
                yield eventHandler.processMsg({
                    type: 'get-vcs-by-context',
                    contextRegex: regex
                }, (credentials) => __awaiter(this, void 0, void 0, function* () {
                    // The challengeRequest.toVerify array contains predicate+whitelist
                    // Step 1: Check which credentials do and don't pass the issuer whitelist check
                    for (const toVerify of challengeRequest.toVerify) {
                        let markAsMissing = true;
                        for (const credential of credentials) {
                            const credentialSubjects = Object.keys(credential.credentialSubject);
                            if (credentialSubjects.includes(toVerify.predicate)) {
                                // Step 1.1: Incase the issuer whitelist is not present or it matches the whitelist,
                                // mark the credential as 'keep this one'
                                if ((toVerify.allowedIssuers === undefined
                                    || toVerify.allowedIssuers.length === 0
                                    || toVerify.allowedIssuers.includes(credential.issuer))) {
                                    markAsMissing = false;
                                    matchingVerifiableCredentials.push({ credential: credential, predicate: toVerify.predicate });
                                }
                                else {
                                    // Step 1.2: If the credential does not pass the whitelist check, mark it as 'remove this'.
                                    // The credential can contain multiple subjects (claims), so one claim might pass the check
                                    // while other claims might not. It is imperative that the credentials from step 2.1 are
                                    // not removed. Only remove a credential if it doesn't pass for all claims completely, after
                                    // this loop.
                                    markAsMissing = false; // Do not mark it as missing, let step 2 mark it differently
                                    failedCredentials.push({ credential: credential, predicate: toVerify.predicate });
                                }
                            }
                        }
                        // Step 1.3: If there were no matching credentials found, add the predicate to the 'missing' array.
                        // The user interface will show that there is no matching credential for this predicate.
                        if (markAsMissing) {
                            missingVCs.push({ predicate: toVerify.predicate, reason: 'missing' });
                        }
                    }
                    // Step 2: Remove credentials if they don't match the whitelist check completely (for all credSubjects)
                    for (const failedCred of failedCredentials) {
                        if (!matchingVerifiableCredentials.map(x => x.predicate).includes(failedCred.predicate)
                            && !this.containsMissingPredicate(missingVCs, failedCred.predicate)) {
                            missingVCs.push({
                                predicate: failedCred.predicate,
                                reason: 'no-matching-issuer'
                            });
                        }
                    }
                    resolve();
                }));
            }));
            // Finally, return all matching credentials and missing predicates. Make sure not to send duplicated results.
            return {
                matching: this.getUniqueCredentials(matchingVerifiableCredentials),
                missing: missingVCs
            };
        });
    }
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
    processTransaction(counterpartyId, verifiedVcs, credentials, eventHandler) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.saveIssuedVCs(credentials, eventHandler);
            const transaction = {
                created: new Date(),
                counterpartyId: counterpartyId,
                state: 'success',
                issuedVcs: credentials.map(vc => vc.proof.nonce),
                verifiedVcs: verifiedVcs
            };
            yield eventHandler.processMsg({ type: 'save-vc-transaction', transaction: transaction }, undefined);
        });
    }
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
    saveIssuedVCs(credentials, eventHandler) {
        return __awaiter(this, void 0, void 0, function* () {
            const promises = [];
            const vcsToSave = [];
            for (const vc of credentials) {
                // Todo: Implement universal resolver to resolve the DID
                // Right now, we assume that the given DID is in the following format - did:xx:publicAddress
                const pubAddress = vc.credentialSubject.id.split(':').pop();
                promises.push(new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
                    yield eventHandler.processMsg({ type: 'get-address-details', publicAddress: pubAddress }, (address) => __awaiter(this, void 0, void 0, function* () {
                        if (vc.context && vc.context.includes(address.predicate)) {
                            vcsToSave.push(vc);
                        }
                        resolve();
                    }));
                })));
            }
            yield Promise.all(promises);
            yield eventHandler.processMsg({ type: 'save-vcs', verifiableCredentials: vcsToSave }, undefined);
        });
    }
    getUniqueCredentials(array) {
        return [...new Set(array.map(x => x.credential))];
    }
    containsMissingPredicate(array, predicate) {
        return array.filter(x => x.predicate === predicate).length > 0;
    }
}
exports.VerifiableCredentialHelper = VerifiableCredentialHelper;
//# sourceMappingURL=verifiable-credential-helper.js.map