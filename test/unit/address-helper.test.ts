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

import * as chai from 'chai'
import * as sinon from 'sinon'
import * as sinonChai from 'sinon-chai'
import * as chaiAsPromised from 'chai-as-promised'
import { AddressHelper } from '../../src'
import { LocalCryptUtils } from 'crypt-util'
import { EventHandler } from 'universal-ledger-agent'
import { Address, IAddress } from 'ula-vc-data-management'
import { VerifiableCredential } from 'vp-toolkit-models'

before(() => {
  chai.should()
  chai.use(chaiAsPromised)
  chai.use(sinonChai)
})

describe('address helper', function () {
  const eventHandler = new EventHandler([])
  const cryptUtil = new LocalCryptUtils()
  const publicAddress = '0x4900133bD1b8934946106CEc7DB3eD931710DC92'
  const accountId = 593
  const keyId = 856715
  const predicate = 'http://schema.org/'

  afterEach(() => {
    sinon.restore()
  })

  it('should call cryptutil, save address details and return the correct address', (done) => {
    const eventHandlerStub = sinon.stub(eventHandler, 'processMsg').onFirstCall().callsFake(
      async (jsonObj: any, callback: any) => {
        return callback(keyId)
      })
    const cryptUtilStub = sinon.stub(cryptUtil, 'deriveAddress').returns(publicAddress)
    const expectedAddressDetails: IAddress = {
      address: publicAddress,
      accountId: accountId,
      keyId: keyId,
      predicate: predicate
    }
    const sut = new AddressHelper(cryptUtil)

    sut.generateAndSaveAddressDetails(accountId, predicate, eventHandler).then((addressDetails: Address) => {
      cryptUtilStub.should.have.been.calledOnceWithExactly(accountId, keyId)
      eventHandlerStub.firstCall.should.have.been.calledWith({ type: 'get-new-key-id' })
      eventHandlerStub.secondCall.should.have.been.calledWithExactly({
        type: 'save-address',
        address: expectedAddressDetails
      }, undefined)
      addressDetails.should.deep.equal(new Address(expectedAddressDetails))
      done()
    })
  })

  it('should find address info from third-party credentials', (done) => {
    const holderAddress = 'holderAddress'
    const dummyVc1 = new VerifiableCredential({
      type: ['VerifiableCredential'],
      credentialSubject: {
        id: 'did:eth:' + holderAddress,
        'http://schema.org/givenName': 'John',
        'http://schema.org/address': 'SomeStreet'
      },
      '@context': ['http://schema.org/address'],
      issuanceDate: new Date(),
      issuer: 'did:eth:issuerTwoAddress',
      proof: {
        type: 'SomeSignature2019',
        created: new Date('01-01-2019 12:34:00'),
        verificationMethod: 'pubkey',
        nonce: '9f2f4712-a16f-44c2-8271-d6129de2b91f',
        signatureValue: 'signature'
      }
    })
    const dummyVc2 = new VerifiableCredential({
      type: ['VerifiableCredential'],
      credentialSubject: {
        id: 'did:eth:' + holderAddress,
        'http://schema.org/givenName': 'Ted',
        'http://schema.org/BankAccount': 'XX01BANK00123456789'
      },
      '@context': ['http://schema.org/givenName'],
      issuanceDate: new Date(),
      issuer: 'did:eth:issuerAddress',
      proof: {
        type: 'SomeSignature2019',
        created: new Date('01-01-2019 12:34:00'),
        verificationMethod: 'pubkey',
        nonce: '9f2f4712-a16f-44c2-8271-d6129de2b91f',
        signatureValue: 'signature'
      }
    })
    const expectedAddresses = [
      new Address({
        predicate: 'http://schema.org/givenName',
        address: holderAddress,
        keyId: 1,
        accountId: 0
      }),
      new Address({
        predicate: 'http://schema.org/address',
        address: holderAddress,
        keyId: 2,
        accountId: 0
      })
    ]
    const eventHandlerStub = sinon.stub(eventHandler, 'processMsg')
      .onFirstCall().callsFake(
        async (jsonObj: any, callback: any) => {
          return callback(expectedAddresses[0])
        })
      .onSecondCall().callsFake(
        async (jsonObj: any, callback: any) => {
          return callback(expectedAddresses[1])
        })
    const sut = new AddressHelper(cryptUtil)

    sut.findDidInfoForVCs([dummyVc1, dummyVc2], eventHandler).then((result: Address[]) => {
      eventHandlerStub.firstCall.should.have.been.calledWith({
        type: 'get-address-details',
        publicAddress: holderAddress
      })
      result.should.deep.equal(expectedAddresses)
      done()
    })
  })
})
