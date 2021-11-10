/* global artifacts */
require('dotenv').config({ path: '../.env' })
const MOVRSmashnado = artifacts.require('MOVRSmashnado')
const Verifier = artifacts.require('Verifier')
const hasherContract = artifacts.require('Hasher')


module.exports = function(deployer, network, accounts) {
  return deployer.then(async () => {
    const { MERKLE_TREE_HEIGHT, MOVR_AMOUNT_O } = process.env
    const verifier = await Verifier.deployed()
    const hasherInstance = await hasherContract.deployed()
    await MOVRSmashnado.link(hasherContract, hasherInstance.address)
    const smashnado = await deployer.deploy(MOVRSmashnado, verifier.address, MOVR_AMOUNT_O, MERKLE_TREE_HEIGHT, accounts[0])
    console.log('MOVR Smashnado\'s address ', smashnado.address)
  })
}
