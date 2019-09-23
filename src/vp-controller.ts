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

import { EventHandler, HttpService, Message, Plugin, UlaResponse } from 'universal-ledger-agent'
import {
  ChallengeRequest,
  IVerifiablePresentationParams,
  VerifiableCredential,
  VerifiablePresentation
} from 'vp-toolkit-models'
import { ChallengeRequestSigner, VerifiablePresentationGenerator, VerifiablePresentationSigner } from 'vp-toolkit'
import { VerifiableCredentialHelper } from './service/verifiable-credential-helper'
import { AddressHelper } from './service/address-helper'

/**
 * The VP Controller ULA plugin
 * ensures a correct issue/verify flow
 * by delegating various activities to
 * the correct dependencies.
 */
export class VpController implements Plugin {
  private _eventHandler?: EventHandler

  /**
   * Provide the generators you want to use
   * in order to generate VerifiableCredentials
   * and VerifiablePresentations.
   *
   * Multiple signers for one class can be provided,
   * so you can verify objects which were signed with
   * different algorithms. If the VerifiablePresentation
   * from the issuer does not contain any proofs, the
   * first given VerifiablePresentationSigner will be
   * used. Create your own signer by overriding the
   * existing signer class.
   *
   * The account ID is the 'wallet' or 'profile'
   * identifier the current user is utilizing.
   * If your wallet implementation does not provide
   * multiple wallets/profiles, then you can
   * provide 0 as accountId value.
   *
   * @param {VerifiablePresentationGenerator} _vpGenerator
   * @param {VerifiablePresentationSigner[]} _vpSigners
   * @param {ChallengeRequestSigner[]} _challengeRequestSigners
   * @param {HttpService} _httpService
   * @param {VerifiableCredentialHelper} _vcHelper
   * @param {AddressHelper} _addressHelper
   * @param {number} _accountId
   */
  public constructor (
    private _vpGenerator: VerifiablePresentationGenerator,
    private _vpSigners: VerifiablePresentationSigner[],
    private _challengeRequestSigners: ChallengeRequestSigner[],
    private _httpService: HttpService,
    private _vcHelper: VerifiableCredentialHelper,
    private _addressHelper: AddressHelper,
    private _accountId: number
  ) {
  }

  /**
   * The name of the plugin
   * @return {string}
   */
  get name () {
    return 'VpController'
  }

  /**
   * The current wallet/profile ID
   * @return {number}
   */
  get accountId () {
    return this._accountId
  }

  /**
   * When the user switches to a different
   * wallet/profile, update the accountId
   * to make sure the correct keys are
   * generated and used.
   */
  set accountId (id: number) {
    this._accountId = id
  }

  /**
   * Receive the eventHandler so we can put messages
   * back on the ULA again
   * @param {EventHandler} eventHandler
   */
  public initialize (eventHandler: EventHandler): void {
    this._eventHandler = eventHandler
  }

  /**
   * Handle incoming messages
   * @param {Message} message
   * @param callback
   * @return {Promise<string>}
   */
  public async handleEvent (message: Message, callback: any): Promise<string> {
    if (message.properties.type.match('accept-consent')) {
      return this.handleConsent(message, callback)
    }

    if (message.properties.type !== 'process-challengerequest') {
      return 'ignored' // This message is not intended for us
    }

    if (!message.properties.endpoint || !message.properties.msg) {
      return 'ignored' // The message type is correct, but endpoint or msg is missing
    }

    if (!this._eventHandler) {
      this.triggerFailure(callback)
      throw new Error('Plugin not initialized. Did you forget to call initialize() ?')
    }

    try {
      const challengeRequest = new ChallengeRequest(message.properties.msg)
      // Check if we expect a response containing a VP with issued VC's from the issuer (otherwise it is a verifier)
      const matchingCrSigner = this._challengeRequestSigners.find((crSigner) => crSigner.signatureType === challengeRequest.proof.type)
      const isValidChallengeRequest = matchingCrSigner ? matchingCrSigner.verifyChallengeRequest(challengeRequest) : false

      if (!isValidChallengeRequest) {
        this.triggerFailure(callback)
        return 'error-cr'
      }

      // toAttest process
      // Receive the DidInfo to create a new proof using the same DID keys
      const selfAttestedVCsAndDidInfo = await this._vcHelper.generateSelfAttestedVCs(challengeRequest, this._accountId, this._eventHandler)
      const selfAttestedVCs = selfAttestedVCsAndDidInfo.map((vcd: any) => vcd.vc)

      // toVerify process
      const vcSearchResult = await this._vcHelper.findVCsForChallengeRequest(challengeRequest, this._eventHandler)
      const existingVcAddresses = await this._addressHelper.findDidInfoForVCs(vcSearchResult.matching, this._eventHandler)

      // Transform all DID info so generateVerifiablePresentation can digest it
      const selfAttestedDidInfo = selfAttestedVCsAndDidInfo.map(info => {
        return { accountId: info.accountId, keyId: info.keyId }
      })
      const existingVcDidInfo = existingVcAddresses.map(addr => {
        return { accountId: addr.accountId, keyId: addr.keyId }
      })

      // Prepare the response, but make the VP undefined if there are no credentials found
      const allFoundCredentials = selfAttestedVCs.concat(vcSearchResult.matching)
      const selfAttestedVP = allFoundCredentials.length > 0 ?
        this._vpGenerator.generateVerifiablePresentation(
          {
            type: ['VerifiablePresentation', 'ChallengeResponse'],
            verifiableCredential: allFoundCredentials
          },
          selfAttestedDidInfo.concat(existingVcDidInfo),
          challengeRequest.correspondenceId
        )
        : undefined

      // Ask for consent
      const nextMessage = new UlaResponse(
        {
          statusCode: 200,
          body: {
            confirmAttestations: vcSearchResult.matching.map((vc) => {
              for (const cs of Object.keys(vc.credentialSubject)) {
                if (cs !== 'id') {
                  return {
                    key: cs.split('/').pop(),
                    value: vc.credentialSubject[cs],
                    attestor: vc.additionalFields['issuerName']
                  }
                }
              }
            }),
            missingAttestations: vcSearchResult.missing,
            filledTemplate: {
              challengeRequest: challengeRequest,
              verifiablePresentation: selfAttestedVP
            },
            url: message.properties.endpoint,
            type: 'accept-consent'
          }
        }
      ) // Todo: Redesign this message structure

      // If the counterparty requests data (toVerify), show the consent screen
      if (challengeRequest.toVerify.length > 0) {
        callback(new UlaResponse({ statusCode: 1, body: { loading: false, success: false, failure: false } }))
        callback(nextMessage)
      } else {
        nextMessage.body.payload = nextMessage.body.filledTemplate
        return this.handleConsent(new Message(nextMessage.body), callback)
      }

    } catch (error) {
      this.triggerFailure(callback)
      return 'error'
    }

    return 'success'
  }

  private async handleConsent (message: Message, callback: any): Promise<string> {
    // Send challengeresponse (VP) and process the response from the endpoint
    const challengeRequest = message.properties.payload.challengeRequest as ChallengeRequest
    const selfAttestedVP = message.properties.payload.verifiablePresentation as VerifiablePresentation
    const response = await this._httpService.postRequest(message.properties.url, selfAttestedVP)
    let issuedCredentials: VerifiableCredential[] = []

    // The endpoint can either be an issuer sending back a VP - or a verifier sending back an empty response
    if (challengeRequest.toAttest.length > 0) {
      const vp = new VerifiablePresentation(response as IVerifiablePresentationParams)
      issuedCredentials = vp.verifiableCredential
      const matchingVpSigner = this._vpSigners.find((vpSigner) => vp.proof.length > 0 && vpSigner.signatureType === vp.proof[0].type)
      const vpIsValidVp = matchingVpSigner
        ? matchingVpSigner.verifyVerifiablePresentation(vp, true)
        : this._vpSigners[0].verifyVerifiablePresentation(vp, true)

      if (!vpIsValidVp) {
        this.triggerFailure(callback)
        return 'error-vp'
      }
    }

    // Save the VC's coming from the issuer
    await this._vcHelper.processTransaction(
      challengeRequest.proof.verificationMethod,
      selfAttestedVP.verifiableCredential.filter(vc => (!vc.type.includes('DidOwnership'))).map(vc => vc.proof.nonce),
      issuedCredentials,
      // @ts-ignore
      this._eventHandler
    )

    callback(new UlaResponse({ statusCode: 1, body: { loading: false, success: true, failure: false } }))
    callback(new UlaResponse({ statusCode: 201, body: {} }))

    return 'success'
  }

  private triggerFailure (callback: any) {
    if (callback) {
      callback(new UlaResponse({ statusCode: 1, body: { loading: false, success: false, failure: true } }))
      callback(new UlaResponse({ statusCode: 204, body: {} }))
    }
  }
}
