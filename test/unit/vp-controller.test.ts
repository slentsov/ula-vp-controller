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

import { assert } from 'chai'
import { AddressHelper, VerifiableCredentialHelper, VpController } from '../../src'
import { BrowserHttpService, EventHandler } from 'universal-ledger-agent'
import { LocalCryptUtils } from 'crypt-util'
import {
  ChallengeRequestSigner,
  VerifiableCredentialGenerator,
  VerifiableCredentialSigner,
  VerifiablePresentationGenerator,
  VerifiablePresentationSigner
} from 'vp-toolkit'

describe('vp controller requestData, name and initialize', function () {
  const accountId = 1010
  const cryptUtil = new LocalCryptUtils()
  const crSigner = new ChallengeRequestSigner(cryptUtil)
  const vcSigner = new VerifiableCredentialSigner(cryptUtil)
  const vcGenerator = new VerifiableCredentialGenerator(vcSigner)
  const vpSigner = new VerifiablePresentationSigner(cryptUtil, vcSigner)
  const vpGenerator = new VerifiablePresentationGenerator(vpSigner)
  const httpService = new BrowserHttpService()
  const addressHelper = new AddressHelper(cryptUtil)
  const vcHelper = new VerifiableCredentialHelper(vcGenerator, addressHelper)
  let sut = new VpController(vpGenerator, [vpSigner], [crSigner], httpService, vcHelper, addressHelper, accountId)

  afterEach(() => {
    sut = new VpController(vpGenerator, [vpSigner], [crSigner], httpService, vcHelper, addressHelper, accountId)
  })

  it('should return a hardcoded name', () => {
    const pluginName = 'VpController'
    const result = sut.name
    assert.strictEqual(result, pluginName)
  })

  it('should set the accountId to a different value', () => {
    const result = sut.accountId = 1234
    assert.strictEqual(result, sut.accountId)
  })

  it('should initialize with a valid eventhandler object', () => {
    const eventHandler = new EventHandler([])
    const initAction = () => {
      sut.initialize(eventHandler)
    }
    assert.doesNotThrow(initAction)
  })
})
