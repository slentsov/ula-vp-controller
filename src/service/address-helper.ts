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

import { Address, IAddress } from 'ula-vc-data-management'
import { CryptUtil } from 'crypt-util'
import { EventHandler } from 'universal-ledger-agent'
import { VerifiableCredential } from 'vp-toolkit-models'

export class AddressHelper {

  constructor (private _cryptUtil: CryptUtil) {
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
  public async generateAndSaveAddressDetails (accountId: number, predicate: string, eventHandler: EventHandler): Promise<Address> {
    return new Promise(async (resolve) => {
      await eventHandler.processMsg({ type: 'get-new-key-id' },
        async (keyId: number) => {
          const pubAddress = this._cryptUtil.deriveAddress(accountId, keyId)
          const addressDetails: IAddress = {
            address: pubAddress,
            accountId: accountId,
            keyId: keyId,
            predicate: predicate
          }
          await eventHandler.processMsg({ type: 'save-address', address: addressDetails }, undefined)
          resolve(new Address(addressDetails))
        })
    })
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
  public async findDidInfoForVCs (credentials: VerifiableCredential[], eventHandler: EventHandler): Promise<Address[]> {
    const promises: Promise<void>[] = []
    const didInfo: Address[] = []
    for (const credential of credentials) {
      const promise = new Promise<void>(async (resolve) => {
        const address = (credential.credentialSubject.id as string).split(':').pop()
        await eventHandler.processMsg({ type: 'get-address-details', publicAddress: address },
          async (address: Address) => {
            didInfo.push(address)
            resolve()
          })
      })
      promises.push(promise)
    }

    await Promise.all(promises)
    return didInfo
  }
}
