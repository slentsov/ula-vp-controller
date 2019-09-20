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
import { LocalCryptUtils } from 'crypt-util'
import { EventHandler } from 'universal-ledger-agent'
import { AddressHelper, VerifiableCredentialHelper } from '../../src'
import { VerifiableCredentialGenerator, VerifiableCredentialSigner } from 'vp-toolkit'
import { ChallengeRequest, IProofParams, IVerifiableCredentialParams, VerifiableCredential } from 'vp-toolkit-models'
import { Address, IAddress } from 'ula-vc-data-management'

before(() => {
  chai.should()
  chai.use(chaiAsPromised)
  chai.use(sinonChai)
})

describe('verifiable credential helper', function () {
  let clock: sinon.SinonFakeTimers
  const eventHandler = new EventHandler([])
  const cryptUtil = new LocalCryptUtils()
  const vcGenerator = new VerifiableCredentialGenerator(new VerifiableCredentialSigner(cryptUtil))
  const addressHelper = new AddressHelper(cryptUtil)
  const publicAddress = '0x4900133bD1b8934946106CEc7DB3eD931710DC92'
  const predicate = 'http://schema.org/address'
  const testProof: IProofParams = {
    type: 'Secp256k1Signature2019',
    created: new Date('01-01-2019 12:34:00'),
    verificationMethod: 'pubkey',
    signatureValue: 'signature'
  }

  beforeEach(() => {
    clock = sinon.useFakeTimers({
      now: new Date(Date.UTC(2019, 0, 1, 12, 34)),
      shouldAdvanceTime: false
    })
  })

  afterEach(() => {
    clock.restore()
    sinon.restore()
  })

  it('should find VCs which match with the given context', (done) => {
    const dummyVc = new VerifiableCredential({
      type: ['VerifiableCredential'],
      credentialSubject: {
        id: 'did:eth:holderAddress',
        'http://schema.org/givenName': 'Ted'
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
    const eventHandlerStub = sinon.stub(eventHandler, 'processMsg')
      .onFirstCall()
      .callsFake(async (message: any, callback: any) => {
        return callback([dummyVc])
      })
    const predicate2 = 'http://schema.org/givenName'
    const sut = new VerifiableCredentialHelper(vcGenerator, addressHelper)
    const challengeRequest = new ChallengeRequest({
      toVerify: [{ predicate: predicate }, { predicate: predicate2 }],
      proof: testProof
    })

    sut.findVCsForChallengeRequest(challengeRequest, eventHandler).then((credentials) => {
      eventHandlerStub.should.have.been.calledOnceWith({
        type: 'get-vcs-by-context',
        contextRegex: new RegExp('(' + predicate + ')|(' + predicate2 + ')', 'g')
      })
      credentials.should.deep.equal(
        {
          matching: [dummyVc],
          missing: [{ predicate: predicate, reason: 'missing' }]
        }
      )
      done()
    })
  })

  // If the credential exists but does not come from the right issuer, mark it as "no-matching-issuer"
  // Todo: Refactor this test
  it('should specify missing attestations with reason "no-matching-issuer"', (done) => {
    const dummyVc1 = new VerifiableCredential({
      type: ['VerifiableCredential'],
      credentialSubject: {
        id: 'did:eth:holderAddress',
        'http://schema.org/givenName': 'John',
        'http://schema.org/address': 'SomeStreet',
        'http://schema.org/birthDate': '01-01-1980'
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
        id: 'did:eth:holderAddress',
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
    const eventHandlerStub = sinon.stub(eventHandler, 'processMsg')
      .onFirstCall()
      .callsFake(async (message: any, callback: any) => {
        return callback([dummyVc1, dummyVc2])
      })
    const predicate2 = 'http://schema.org/givenName'
    const predicate3 = 'http://schema.org/test'
    const predicate4 = 'http://schema.org/BankAccount'
    const predicate5 = 'http://schema.org/birthDate'
    const sut = new VerifiableCredentialHelper(vcGenerator, addressHelper)
    // Testing many combinations
    const challengeRequest = new ChallengeRequest({
      toVerify: [
        { predicate: predicate, allowedIssuers: [] }, // address
        { predicate: predicate2, allowedIssuers: ['did:eth:otherIssuer'] },
        { predicate: predicate3 },
        { predicate: predicate4, allowedIssuers: ['did:eth:someBankIssuer'] },
        { predicate: predicate5 }
      ],
      proof: testProof
    })

    sut.findVCsForChallengeRequest(challengeRequest, eventHandler).then((credentials) => {
      eventHandlerStub.should.have.been.calledOnceWith({
        type: 'get-vcs-by-context',
        contextRegex: new RegExp('(' + predicate + ')|(' + predicate2 + ')|(' + predicate3 + ')|(' + predicate4 + ')|(' + predicate5 + ')', 'g')
      })
      credentials.should.deep.equal(
        {
          matching: [dummyVc1],
          missing: [
            { predicate: predicate3, reason: 'missing' },
            { predicate: predicate2, reason: 'no-matching-issuer' },
            { predicate: predicate4, reason: 'no-matching-issuer' }
          ]
        }
      )
      done()
    })
  })

  // Todo: Refactor this test
  it('should not specify missing attestations with reason "no-matching-issuer" if another one is present', (done) => {
    const dummyVc1 = new VerifiableCredential({
      type: ['VerifiableCredential'],
      credentialSubject: {
        id: 'did:eth:holderAddress',
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
        id: 'did:eth:holderAddress',
        'http://schema.org/givenName': 'Ted'
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
    const dummyVc3 = new VerifiableCredential({
      type: ['VerifiableCredential'],
      credentialSubject: {
        id: 'did:eth:holderAddress',
        'http://schema.org/givenName': 'John',
        'http://schema.org/address': 'SomeStreet'
      },
      '@context': ['http://schema.org/givenName'],
      issuanceDate: new Date(),
      issuer: 'did:eth:otherIssuer', // otherIssuer, allowed
      proof: {
        type: 'SomeSignature2019',
        created: new Date('01-01-2019 12:34:00'),
        verificationMethod: 'pubkey',
        nonce: '9f2f4712-a16f-44c2-8271-d6129de2b91f',
        signatureValue: 'signature'
      }
    })
    const eventHandlerStub = sinon.stub(eventHandler, 'processMsg')
      .onFirstCall()
      .callsFake(async (message: any, callback: any) => {
        return callback([dummyVc1, dummyVc2, dummyVc3])
      })
    const predicate2 = 'http://schema.org/givenName'
    const sut = new VerifiableCredentialHelper(vcGenerator, addressHelper)
    const challengeRequest = new ChallengeRequest({
      toVerify: [
        { predicate: predicate }, // address
        { predicate: predicate2, allowedIssuers: ['did:eth:otherIssuer'] }
      ],
      proof: testProof
    })

    sut.findVCsForChallengeRequest(challengeRequest, eventHandler).then((credentials) => {
      eventHandlerStub.should.have.been.calledOnceWith({
        type: 'get-vcs-by-context',
        contextRegex: new RegExp('(' + predicate + ')|(' + predicate2 + ')', 'g')
      })
      credentials.should.deep.equal(
        {
          matching: [dummyVc1, dummyVc3],
          missing: [] // It should not say predicate 'http://schema.org/givenName' is missing because it is in dummyVc3
        }
      )
      done()
    })
  })

  it('should not find VCs if toVerify in the challengeRequest is empty', (done) => {
    const eventHandlerStub = sinon.stub(eventHandler, 'processMsg')
    const predicate2 = 'http://schema.org/fullName'
    const sut = new VerifiableCredentialHelper(vcGenerator, addressHelper)
    const challengeRequest = new ChallengeRequest({
      toAttest: [{ predicate: predicate }, { predicate: predicate2 }],
      proof: testProof
    })

    sut.findVCsForChallengeRequest(challengeRequest, eventHandler).then((credentials) => {
      eventHandlerStub.callCount.should.be.equal(0)
      credentials.should.deep.equal({
        matching: [],
        missing: []
      })
      done()
    })
  })

  it('should generate a self attested VC', (done) => {
    const dummyVc = { id: 'dummy-vc' } as VerifiableCredential
    const accountId = 1001
    const keyId = 1234
    const expectedAddressDetails: IAddress = {
      address: publicAddress,
      accountId: accountId,
      keyId: keyId,
      predicate: predicate
    }
    const vcGeneratorStub = sinon.stub(vcGenerator, 'generateVerifiableCredential').returns(dummyVc)
    const addressHelperStub = sinon.stub(addressHelper, 'generateAndSaveAddressDetails')
      .resolves(new Address(expectedAddressDetails))
    const sut = new VerifiableCredentialHelper(vcGenerator, addressHelper)
    const challengeRequest = new ChallengeRequest({
      toAttest: [{ predicate: predicate }],
      proof: testProof
    })

    sut.generateSelfAttestedVCs(challengeRequest, accountId, eventHandler).then((credentials) => {
      addressHelperStub.should.have.been.calledOnceWithExactly(accountId, predicate, eventHandler)
      vcGeneratorStub.should.have.been.calledOnceWithExactly({
        type: ['VerifiableCredential', 'DidOwnership'],
        credentialSubject: {},
        '@context': [predicate],
        issuanceDate: new Date(),
        issuer: 'did:eth:' + publicAddress
      }, accountId, keyId)
      credentials.should.deep.equal([{ accountId: accountId, keyId: keyId, vc: dummyVc }])
      done()
    })
  })

  it('should process a transaction successfully', (done) => {
    const sut = new VerifiableCredentialHelper(vcGenerator, addressHelper)
    const holderAddress = '0x1aFC43cF265ac09434Cf3B16e4fAfD82b710c2c9'
    const issuerAddress = '0x0df4e8ff5c455876dae4f46d1175e0fc8fe0bad6'
    const issuerVcWithoutProof: IVerifiableCredentialParams = {
      type: ['VerifiableCredential'],
      credentialSubject: {
        id: 'did:eth:' + holderAddress
      },
      '@context': [predicate],
      issuanceDate: new Date(),
      issuer: 'did:eth:' + issuerAddress
    }
    issuerVcWithoutProof.credentialSubject['http://schema.org/givenName'] = 'Tom'
    const issuerVcWithProof = [new VerifiableCredential(
      Object.assign({ proof: testProof }, issuerVcWithoutProof)
    )]

    // Verified/revoked nonces don't have to be linked to a VC at this stage
    const verifiedVcNonces = ['d13e94e6-cbf0-4c5c-a5dd-102b054e3a52', '0364f90b-9b97-4874-996f-a1d39468f983']
    const eventHandlerStub = sinon.stub(eventHandler, 'processMsg')
      .onFirstCall()
      .callsFake(async (message: any, callback: any) => {
        return callback(new Address({
          address: holderAddress,
          accountId: 100,
          keyId: 0,
          predicate: predicate
        }))
      })

    sut.processTransaction(testProof.verificationMethod, verifiedVcNonces, issuerVcWithProof, eventHandler)
      .then(() => {
        eventHandlerStub.firstCall.should.have.been.calledWith({
          type: 'get-address-details',
          publicAddress: holderAddress
        })
        eventHandlerStub.secondCall.should.have.been.calledWith({
          type: 'save-vcs',
          verifiableCredentials: issuerVcWithProof
        })
        eventHandlerStub.thirdCall.should.have.been.calledWith({
          type: 'save-vc-transaction',
          transaction: {
            created: new Date(clock.now),
            counterpartyId: testProof.verificationMethod,
            state: 'success',
            issuedVcs: issuerVcWithProof.map(vc => vc.proof.nonce),
            verifiedVcs: verifiedVcNonces
          }
        })
        done()
      })
  })

  it('should not save VCs which are not requested in the first place', (done) => {
    const sut = new VerifiableCredentialHelper(vcGenerator, addressHelper)
    const holderAddress = '0x1aFC43cF265ac09434Cf3B16e4fAfD82b710c2c9'
    const issuerAddress = '0x0df4e8ff5c455876dae4f46d1175e0fc8fe0bad6'
    const issuerVcWithoutProof: IVerifiableCredentialParams = {
      type: ['VerifiableCredential'],
      credentialSubject: {
        id: 'did:eth:' + holderAddress
      },
      '@context': ['http://schema.org/givenName'], // Different predicate
      issuanceDate: new Date(),
      issuer: 'did:eth:' + issuerAddress
    }
    issuerVcWithoutProof.credentialSubject['http://schema.org/givenName'] = 'Tom' // Different predicate
    const issuerVcWithProof = [new VerifiableCredential(
      Object.assign({ proof: testProof }, issuerVcWithoutProof)
    )]
    const eventHandlerStub = sinon.stub(eventHandler, 'processMsg')
      .onFirstCall()
      .callsFake(async (message: any, callback: any) => {
        return callback(new Address({
          address: holderAddress,
          accountId: 100,
          keyId: 0,
          predicate: predicate // Original predicate
        }))
      })

    sut.saveIssuedVCs(issuerVcWithProof, eventHandler).then(() => {
      eventHandlerStub.firstCall.should.have.been.calledWith({
        type: 'get-address-details',
        publicAddress: holderAddress
      })
      eventHandlerStub.secondCall.should.have.been.calledWith({
        type: 'save-vcs',
        verifiableCredentials: []
      })
      done()
    })
  })
})
