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
const ula_vc_data_management_1 = require("ula-vc-data-management");
class AddressHelper {
    constructor(_cryptUtil) {
        this._cryptUtil = _cryptUtil;
    }
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
    generateAndSaveAddressDetails(accountId, predicate, eventHandler) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
                yield eventHandler.processMsg({ type: 'get-new-key-id' }, (keyId) => __awaiter(this, void 0, void 0, function* () {
                    const pubAddress = this._cryptUtil.deriveAddress(accountId, keyId);
                    const addressDetails = {
                        address: pubAddress,
                        accountId: accountId,
                        keyId: keyId,
                        predicate: predicate
                    };
                    yield eventHandler.processMsg({ type: 'save-address', address: addressDetails }, undefined);
                    resolve(new ula_vc_data_management_1.Address(addressDetails));
                }));
            }));
        });
    }
    /**
     * Get the address details for existing verifiable
     * credentials. The verifiable credential must be
     * in the format 'did:<anything>:<ethaddress>'
     *
     * @param {VerifiableCredential[]} credentials
     * @param {EventHandler} eventHandler
     * @return {Promise<void>}
     */
    findDidInfoForVCs(credentials, eventHandler) {
        return __awaiter(this, void 0, void 0, function* () {
            const promises = [];
            const didInfo = [];
            for (const credential of credentials) {
                const promise = new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
                    const address = credential.credentialSubject.id.split(':').pop();
                    yield eventHandler.processMsg({ type: 'get-address-details', publicAddress: address }, (address) => __awaiter(this, void 0, void 0, function* () {
                        didInfo.push(address);
                        resolve();
                    }));
                }));
                promises.push(promise);
            }
            yield Promise.all(promises);
            return didInfo;
        });
    }
}
exports.AddressHelper = AddressHelper;
//# sourceMappingURL=address-helper.js.map